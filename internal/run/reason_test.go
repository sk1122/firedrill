package run

import (
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

func inlineDrill(t *testing.T, src string) *drill.Drill {
	t.Helper()
	d, issues := drill.Parse("test.drill.yaml", []byte(src))
	if drill.HasErrors(issues) {
		t.Fatal(issues)
	}
	if issues := drill.Validate(d); drill.HasErrors(issues) {
		t.Fatal(issues)
	}
	return d
}

// A fact the failing conditions never read is never blamed: the secrets drill
// also fetches agents, and an agent file there is not the leak.
func TestFailReasonNeverNamesAFactTheConditionDoesNotRead(t *testing.T) {
	g := graph.New()
	targetRepo(g)
	scan(g, "secrets", "acme/api", 3)
	scan(g, "agent_configs", "acme/api", 1)
	agentFile(g, ".cursorignore", false, false)
	secret(g, "scripts/deploy.sh", "prod", "real", true)
	got := Decide(loadDrill(t, "agent/no-prod-secrets-in-agent-reach"), g, Options{Now: testNow})
	if got[0].Verdict != tag.Fail {
		t.Fatalf("%s %q", got[0].Verdict, got[0].Reason)
	}
	if strings.Contains(got[0].Reason, ".cursorignore") || !strings.Contains(got[0].Reason, "scripts/deploy.sh") {
		t.Fatalf("the reason must name the secret, not the agent file: %q", got[0].Reason)
	}
}

const twoListsDrill = `firedrill: v0
id: test/two-lists
safeguard: "Neither list holds a bad row."
severity: low
for_each: repos
fetch:
  secrets: { fact: files.secrets }
  agents:  { fact: files.agent_configs }
pass_when:
  - secrets.found.filter(s, s.env_class == "prod").size() == 0
  - agents.found.filter(a, a.local_override && !a.gitignored).size() == 0
fix: "Nothing."
`

// With two lists both read by failing conditions, the first failing
// condition's list is the one named.
func TestFailReasonPrefersTheFirstFailingConditionsList(t *testing.T) {
	d := inlineDrill(t, twoListsDrill)
	g := graph.New()
	targetRepo(g)
	scan(g, "secrets", "acme/api", 3)
	scan(g, "agent_configs", "acme/api", 2)
	agentFile(g, ".claude/settings.local.json", true, false)
	agentFile(g, ".claude/settings.json", false, false)
	secret(g, ".env.production", "prod", "p1", true)
	secret(g, "a-harmless.env", "example", "e1", true)
	got := Decide(d, g, Options{Now: testNow})
	if got[0].Verdict != tag.Fail || got[0].Reason != "1 failing, first: prod credential in .env.production" {
		t.Fatalf("%s %q", got[0].Verdict, got[0].Reason)
	}
	// Only the second condition fails: its list is named, with one row.
	g = graph.New()
	targetRepo(g)
	scan(g, "secrets", "acme/api", 3)
	scan(g, "agent_configs", "acme/api", 2)
	agentFile(g, ".claude/settings.local.json", true, false)
	agentFile(g, ".claude/settings.json", false, false)
	secret(g, "a-harmless.env", "example", "e1", true)
	got = Decide(d, g, Options{Now: testNow})
	if got[0].Verdict != tag.Fail || got[0].Reason != "1 failing, first in .claude/settings.local.json" {
		t.Fatalf("%s %q", got[0].Verdict, got[0].Reason)
	}
}

const objectDrill = `firedrill: v0
id: test/object
safeguard: "Force pushes are off."
severity: low
for_each: github.repos
fetch:
  rules: { fact: github.branch_rules, args: { branch: default } }
  envs:  { fact: files.secrets }
pass_when:
  - rules.force_push_allowed == false
fix: "Nothing."
`

// A failing condition on an object, not a list, names the condition, even
// when another fetched fact has rows.
func TestFailReasonOnAnObjectNamesTheCondition(t *testing.T) {
	d := inlineDrill(t, objectDrill)
	g := graph.New()
	ghRepo(g, "team", true)
	branchRule(g, 1, "none", true)
	scan(g, "secrets", "acme/api", 3)
	node(g, "secret:x", graph.KindSecretSeen, map[string]any{"repo": "acme/api", "kind": "generic", "file": "a.sh", "line": int64(1),
		"env_class": "prod", "hash": "x", "agent_readable": true, "key_id": "", "in_agent_config": false, "gitignored": false})
	got := Decide(d, g, Options{Now: testNow, Available: map[string]bool{"github": true}})
	if got[0].Verdict != tag.Fail || got[0].Reason != "failed: rules.force_push_allowed == false" {
		t.Fatalf("%s %q", got[0].Verdict, got[0].Reason)
	}
}

// A secrets drill's evidence says which file, which kind and which
// fingerprint failed, not only the flags its condition reads, and the record
// scanner leaves those fields as they are.
func TestEvidenceKeepsIdentityFields(t *testing.T) {
	g := graph.New()
	targetRepo(g)
	scan(g, "secrets", "acme/api", 3)
	scan(g, "agent_configs", "acme/api", 1)
	agentFile(g, ".claude/settings.json", false, false)
	secret(g, "scripts/deploy.sh", "prod", "0f3a9c1d2e4b5a6c7d8e9f0a1b2c3d4e", true)
	got := Decide(loadDrill(t, "agent/no-prod-secrets-in-agent-reach"), g, Options{Now: testNow})
	tg := &tag.Tag{Evidence: tag.Evidence{Facts: got[0].Facts}}
	tag.ScanTag(tg, salt)
	if len(tg.Header.ScannerNotes) != 0 {
		t.Fatalf("the scanner changed identity fields: %v", tg.Header.ScannerNotes)
	}
	rows := tg.Evidence.Facts["secrets"].(map[string]any)["found"].([]any)
	row := rows[0].(map[string]any)
	want := map[string]any{"file": "scripts/deploy.sh", "kind": "generic", "hash": "0f3a9c1d2e4b5a6c7d8e9f0a1b2c3d4e", "line": int64(1),
		"agent_readable": true, "env_class": "prod"}
	for k, v := range want {
		if row[k] != v {
			t.Errorf("%s: got %v, want %v", k, row[k], v)
		}
	}
	if _, leaked := row["in_agent_config"]; leaked {
		t.Fatal("a field neither read nor identity must stay out")
	}
	// agents is fetched but never read: it stays a count of its fields.
	if a := tg.Evidence.Facts["agents"].(map[string]any); a["fields"] == nil {
		t.Fatalf("an unread fact gains no identity: %+v", a)
	}
}

// Identity fields locate a thing; none is an address, a login or a value.
func TestIdentityFieldsAreNeverPersonal(t *testing.T) {
	for _, def := range facts.All() {
		for _, p := range def.Identity {
			leaf := p[strings.LastIndex(p, ".")+1:]
			if leaf == "email" || leaf == "login" || leaf == "member" || leaf == "value" || leaf == "owner" {
				t.Errorf("%s: %s is not an identity field", def.Name, p)
			}
			if !shapeHas(def.Shape, p) {
				t.Errorf("%s: %s is not a field of the fact", def.Name, p)
			}
		}
	}
}

func shapeHas(s *facts.Shape, path string) bool {
	for _, part := range strings.Split(path, ".") {
		for s != nil && s.Kind == "list" {
			s = s.Elem
		}
		if s == nil || s.Kind != "object" {
			return false
		}
		if s = s.Fields[part]; s == nil {
			return false
		}
	}
	return true
}

// A list past the cap keeps identity on its first rows only.
func TestIdentityRowsAreCapped(t *testing.T) {
	rows := []any{}
	for i := 0; i < maxIdentityRows+5; i++ {
		rows = append(rows, map[string]any{"file": "f", "env_class": "prod", "agent_readable": true})
	}
	got := trimValue(map[string]any{"found": rows}, []string{"found", "found.env_class"}, []string{"found.file"}).(map[string]any)["found"].([]any)
	if got[0].(map[string]any)["file"] != "f" || got[maxIdentityRows].(map[string]any)["file"] != nil {
		t.Fatalf("first %v, past the cap %v", got[0], got[maxIdentityRows])
	}
}

// A chain whose older tags hold evidence trimmed the old way still verifies
// once tags with identity fields follow.
func TestOldEvidenceChainsStillVerify(t *testing.T) {
	s := tag.Store{Root: t.TempDir()}
	old := &tag.Tag{Header: tag.Header{DrillID: "agent/no-prod-secrets-in-agent-reach", Target: "acme/api", Verdict: tag.Fail, State: tag.Open,
		Time: testNow.AddDate(0, 0, -7)}, Evidence: tag.Evidence{Facts: map[string]any{"secrets": map[string]any{"found": []any{
		map[string]any{"agent_readable": true, "env_class": "prod"}}}}}}
	if _, err := s.Write(old); err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	targetRepo(g)
	scan(g, "secrets", "acme/api", 3)
	secret(g, "scripts/deploy.sh", "prod", "h", true)
	got := Decide(loadDrill(t, "agent/no-prod-secrets-in-agent-reach"), g, Options{Now: testNow})
	next := &tag.Tag{Header: tag.Header{DrillID: old.Header.DrillID, Target: "acme/api", Verdict: got[0].Verdict, State: tag.Open, Time: testNow},
		Evidence: tag.Evidence{Facts: got[0].Facts}}
	if _, err := s.Write(next); err != nil {
		t.Fatal(err)
	}
	hist, err := s.History(old.Header.DrillID, "acme/api")
	if err != nil || len(hist) != 2 {
		t.Fatalf("%v %d", err, len(hist))
	}
	if st := tag.VerifyChain(hist); !st.OK {
		t.Fatalf("%+v", st)
	}
}

// The admins drill counts its problems by kind and system, never "N failing,
// first: ...".
func TestAdminReasonsCountByKind(t *testing.T) {
	want := map[string]string{
		"GitHub owners not mapped to a person": "2 GitHub admins are not mapped to a person (map GitHub logins in .firedrill/people.yaml, or connect Google Workspace)",
		"a bot owns the org with no owner":     "1 GitHub app has no owner; 1 GitHub admin is not mapped to a person",
		"an org owner who has left":            "1 admin belongs to someone who has left or is suspended",
	}
	for _, c := range drillCases() {
		w, ok := want[c.name]
		if !ok || c.id != "access/every-admin-is-someone" {
			continue
		}
		g := graph.New()
		c.setup(g)
		got := Decide(loadDrill(t, c.id), g, Options{Now: testNow, Available: allConnectors})
		if got[0].Verdict != c.verdictWant || !strings.HasPrefix(got[0].Reason, w) {
			t.Errorf("%s: %s %q, want %q", c.name, got[0].Verdict, got[0].Reason, w)
		}
	}
}
