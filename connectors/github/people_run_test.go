package github

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

// fieldsDrill reads every new field, so drill.Validate checks each against the
// facts' shapes.
const fieldsDrill = `firedrill: v0
id: test/github-people-fields
safeguard: "Every new GitHub people field can be read."
severity: low
for_each: github.repos
fetch:
  people: { fact: github.people }
  bypass: { fact: github.bypass_actors, args: { branch: default } }
  rules:  { fact: github.branch_rules, args: { branch: default } }
pass_when:
  - >-
    people.all(p, p.id != "" && p.login != "" && p.org_role != "" && size(p.teams) >= 0
    && size(p.repos_admin) >= 0 && size(p.repos_write) >= 0 && size(p.repos_bypass) >= 0
    && (p.is_outside || !p.is_outside))
  - bypass.known == true
  - bypass.people.all(x, x.id != "" && x.login != "" && size(x.via) > 0 && size(x.through) >= 0)
  - size(bypass.teams) >= 0
  - bypass.apps.all(a, a.id != "" && a.kind != "" && a.name == a.name)
  - bypass.count >= 0
  - rules.bypass_actors_known == true
fix: "Nothing to fix: this drill only reads fields."
`

func parseDrill(t *testing.T, src string) *drill.Drill {
	t.Helper()
	d, issues := drill.Parse("test.drill.yaml", []byte(src))
	if drill.HasErrors(issues) {
		t.Fatal(issues)
	}
	if issues := drill.Validate(d); drill.HasErrors(issues) {
		t.Fatalf("the new fields validate: %v", issues)
	}
	return d
}

func TestNewFieldsValidate(t *testing.T) {
	d := parseDrill(t, fieldsDrill)
	bad, _ := drill.Parse("bad.drill.yaml", []byte(strings.Replace(fieldsDrill, "bypass.count >= 0", "bypass.nobody >= 0", 1)))
	if issues := drill.Validate(bad); !drill.HasErrors(issues) {
		t.Fatal("an unknown field must fail, so the check above means something")
	}

	s := scope(t)
	g := collectAll(t, fakeGitHub(t, people(rulesetWith([]any{obj{"actor_id": 11, "actor_type": "Team", "bypass_mode": "always"}}))), s)
	opts := run.Options{Now: now, Available: map[string]bool{"github": true}, Failures: map[string]string{}}
	verdict := func(g graph.Reader) (string, string) {
		for _, o := range run.Decide(d, g, opts) {
			if o.Target == "acme/api" {
				return o.Verdict, o.Reason
			}
		}
		t.Fatal("no outcome for acme/api")
		return "", ""
	}
	if v, why := verdict(g); v != tag.Pass {
		t.Fatalf("%s %s", v, why)
	}

	// One repo's collaborators unreadable: partial, so WARN.
	g = collectAll(t, fakeGitHub(t, people(routes{"/repos/acme/api/collaborators": 403})), scope(t))
	if v, why := verdict(g); v != tag.Warn {
		t.Fatalf("a partial read gives WARN: %s %s", v, why)
	}

	// Members unreadable: ERROR.
	g = collectAll(t, fakeGitHub(t, people(routes{"/orgs/acme/members?role=admin": 403})), scope(t))
	if v, why := verdict(g); v != tag.Error {
		t.Fatalf("unread members give ERROR: %s %s", v, why)
	}
}

const bypassDrill = `firedrill: v0
id: test/who-can-bypass
safeguard: "Nobody can skip review on main."
severity: low
for_each: github.repos
fetch:
  bypass: { fact: github.bypass_actors, args: { branch: default } }
  people: { fact: github.people }
pass_when:
  - bypass.known && bypass.count == 0
fix: "Remove bypass actors."
`

// The step's done condition: the graph shows who can bypass review on each
// repo. bo is in team release, which a ruleset lets bypass.
func TestRunShowsWhoCanBypass(t *testing.T) {
	r := base(routes{
		"/orgs/acme/members?role=admin":                []any{user("ana-acme", 1)},
		"/orgs/acme/members?role=member":               []any{user("bo-acme", 2), user("cy-acme", 3)},
		"/orgs/acme/outside_collaborators":             []any{},
		"/orgs/acme/teams":                             []any{obj{"id": 13, "slug": "release", "privacy": "closed"}},
		"/orgs/acme/teams/release/members":             []any{},
		"/orgs/acme/teams/release/members?role=member": []any{user("bo-acme", 2)},
		"/repos/acme/api/collaborators":                []any{collab("ana-acme", 1, "admin"), collab("bo-acme", 2, "push"), collab("cy-acme", 3, "push")},
		"/repos/acme/api/teams":                        []any{obj{"slug": "release", "permission": "push"}},
	})
	for k, v := range rulesetWith([]any{obj{"actor_id": 13, "actor_type": "Team", "bypass_mode": "always"}}) {
		r[k] = v
	}
	c := fakeGitHub(t, r)
	s := scope(t)
	s.Project.Config.Connected = []string{"github"}
	records := t.TempDir()
	res, err := run.Run(context.Background(), run.Config{
		Project: s.Project, Drills: []*drill.Drill{parseDrill(t, bypassDrill)}, Connectors: []connector.Connector{c},
		Scope: s, Stream: "local", RanBy: "test", Records: records, WriteRecords: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Fatal != "" || len(res.Failures) > 0 {
		t.Fatalf("%s %v", res.Fatal, res.Failures)
	}
	data := mustFact(t, res.Graph, "github.bypass_actors").Data.(map[string]any)
	if data["known"] != true || !slices.Equal(peopleIDs(t, data), []string{"bo-acme"}) {
		t.Fatalf("%+v", data)
	}
	for _, row := range mustFact(t, res.Graph, "github.people").Data.([]any) {
		m := row.(map[string]any)
		want := []any{}
		if m["login"] == "bo-acme" {
			want = []any{"acme/api"}
		}
		if !slices.Equal(m["repos_bypass"].([]any), want) {
			t.Fatalf("%+v", m)
		}
	}
	if len(res.Outcomes) != 1 || res.Outcomes[0].Verdict != tag.Fail {
		t.Fatalf("%+v", res.Outcomes)
	}
	// The records hold the hashed IDs, never a login, except the tag's
	// evidence, which keeps the login a condition read.
	files, err := graph.SnapshotFiles(filepath.Join(records, "snapshots"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no snapshot was written: %v", err)
	}
	for _, p := range files {
		snap, err := graph.ReadSnapshot(p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(snap)
		if len(snap.Nodes) == 0 || !strings.Contains(string(b), "github:user/") {
			t.Fatalf("%s holds no people", p)
		}
		for _, login := range []string{"ana-acme", "bo-acme", "cy-acme"} {
			if strings.Contains(string(b), login) {
				t.Errorf("%s holds the login %s", p, login)
			}
		}
	}
}
