package graph

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	hashA  = "aaaa1111bbbb2222cccc3333dddd4444"
	hashB  = "bbbb2222cccc3333dddd4444eeee5555"
	secret = "0123456789abcdef0123456789abcdef"
)

// estate holds the nodes and edges of one realistic run, before and after.
type estate struct {
	at time.Time
	g  *Graph
}

func (e *estate) node(id ID, kind, source string, attrs map[string]any) {
	e.g.Node(Node{ID: id, Kind: kind, Source: source, Attrs: attrs, SeenAt: e.at})
}

func (e *estate) edge(from, to ID, kind, source string) {
	e.g.Edge(Edge{From: from, To: to, Kind: kind, Source: source})
}

func (e *estate) scan(source, scanner, scope string, inspected int) {
	WriteScan(e.g, source, scanner, scope, inspected, "", e.at)
}

// weekRun builds one run of a small company: a GitHub repo with a branch rule
// and an environment, AWS users with keys, Google users, a repo with secrets,
// an agent config and a workflow, a GCP bucket and DNS hosts. The second run
// adds an admin, a key, a secret in a new file, turns bypass on, adds an MCP
// server and a public grant, and changes timestamps, counters and line numbers.
func weekRun(t *testing.T, second bool) Snapshot {
	t.Helper()
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	if second {
		at = at.Add(7 * 24 * time.Hour)
	}
	e := &estate{at: at, g: New()}
	pick := func(a, b any) any {
		if second {
			return b
		}
		return a
	}

	// config
	e.node("repo:acme/api", KindTargetRepo, "config", map[string]any{"name": "acme/api", "local": true})
	e.node("config-host:app.example.com", KindConfigHost, "config", map[string]any{"host": "app.example.com", "owner": "@acme/web"})
	e.edge("config-host:app.example.com", "host:app.example.com", EdgeOwns, "config")

	// github
	e.node("github:repo/acme/api", KindGitHubRepo, "github", map[string]any{"name": "acme/api", "private": true, "plan": "team", "protection_available": true})
	e.node("github:branch-rule/acme/api/default", KindBranchRule, "github", map[string]any{
		"required_approvals": int64(1), "dismiss_stale": true, "code_owner_review": false,
		"bypass": pick("none", "allowed"), "bypass_source": "api", "bypass_detail": "api",
		"force_push_allowed": false, "deletion_allowed": false,
	})
	e.node("github:env/acme/api/production", KindEnvironment, "github", map[string]any{
		"required_reviewers": []any{"acme/release"}, "prevent_self_review": true, "admin_bypass": false, "protected_branches_only": true,
	})
	e.edge("github:repo/acme/api", "github:env/acme/api/production", EdgeDeploysTo, "github")
	e.node("github:actions/acme/api", KindActionsPerms, "github", map[string]any{"can_approve_pull_requests": false, "default_token_permission": "read"})

	// aws
	keys := []any{"AKIAAAAAAAAAAAAAAAA1"}
	if second {
		keys = append(keys, "AKIAAAAAAAAAAAAAAAA2")
	}
	e.node("aws:iam-user/111122223333/deploy-bot", KindAWSPrincipal, "aws", map[string]any{
		"account": "111122223333", "principal_kind": "user", "name": "deploy-bot",
		"last_used": pick("2026-11-04T10:00:00Z", "2026-11-11T10:00:00Z"), "created": "2025-01-01T00:00:00Z",
		"keys": keys, "is_admin": false, "destructive_actions": []any{}, "excluded": false,
	})
	for _, k := range keys {
		id := ID("aws:key/" + k.(string))
		e.node(id, KindAWSKey, "aws", map[string]any{"key_id": k, "account": "111122223333", "user": "deploy-bot"})
		e.edge("aws:iam-user/111122223333/deploy-bot", id, EdgeHolds, "aws")
	}

	// google, and the link step
	e.node("google:user/"+hashA, KindIdentityUser, "google", map[string]any{
		"suspended": false, "is_admin": pick(false, true), "is_delegated_admin": false, "mfa_enrolled": true, "mfa_enforced": true,
		"last_login": pick("2026-11-04T08:00:00Z", "2026-11-11T08:00:00Z"), "created": "2024-03-01T00:00:00Z",
	})
	e.node("google:user/"+hashB, KindIdentityUser, "google", map[string]any{
		"suspended": false, "is_admin": true, "is_delegated_admin": false, "mfa_enrolled": true, "mfa_enforced": true,
		"last_login": pick("2026-11-03T08:00:00Z", "2026-11-10T08:00:00Z"), "created": "2023-03-01T00:00:00Z",
	})
	e.node("person:"+hashA, KindPerson, "link", nil)
	e.edge("person:"+hashA, ID("google:user/"+hashA), EdgeSamePerson, "link")

	// files
	e.scan("files", "agent_configs", "acme/api", 1)
	e.scan("files", "secrets", "acme/api", pick(40, 43).(int))
	e.scan("files", "workflows", "acme/api", 1)
	e.scan("files", "terraform", "acme/api", 0)
	occurrence := func(file string, line int) {
		id := ID("secret:" + secret + "@acme/api/" + file + ":" + strconv.Itoa(line))
		e.node(id, KindSecretSeen, "files", map[string]any{
			"kind": "stripe", "file": file, "line": int64(line), "env_class": "prod", "hash": secret,
			"agent_readable": true, "key_id": "", "in_agent_config": false, "gitignored": false, "repo": "acme/api",
		})
		e.node("secret:"+secret, KindSecret, "files", nil)
		e.edge("secret:"+secret, ID("file:acme/api/"+file), EdgeFoundIn, "files")
	}
	occurrence("config/prod.env", pick(3, 5).(int)) // an edit above it moved the line
	if second {
		occurrence("scripts/deploy.sh", 12)
	}
	servers := []any{map[string]any{"name": "github", "credentials": []any{"var:GITHUB_TOKEN"}}}
	if second {
		servers = append(servers, map[string]any{"name": "postgres", "credentials": []any{"var:DATABASE_URL"}})
	}
	e.node("agent:acme/api/.mcp.json", KindAgentConfig, "files", map[string]any{
		"tool": "claude-code", "scope": "repo", "file": ".mcp.json", "allowed_commands": []any{}, "denied_commands": []any{},
		"deny_read_paths": []any{}, "unguarded_destructive": []any{}, "mcp_servers": servers, "gitignored": false,
		"local_override": false, "repo": "acme/api",
	})
	e.node("github:workflow/acme/api/.github/workflows/ci.yml", KindWorkflow, "files", map[string]any{
		"file": ".github/workflows/ci.yml", "permissions": "read", "unpinned_actions": []any{},
		"pull_request_target_checkout": false, "triggers": []any{"pull_request", "push"}, "secrets": []any{}, "repo": "acme/api",
	})

	// gcp
	e.node("gcp:project/acme-prod", KindGCPProject, "gcp", map[string]any{"name": "acme-prod", "number": "1234", "member_domains": []any{"example.com"}, "partial": []any{}})
	grants := []any{}
	if second {
		grants = []any{"allUsers roles/storage.objectViewer"}
	}
	e.node("gcp:bucket/acme-assets", KindGCPBucket, "gcp", map[string]any{
		"project": "acme-prod", "name": "acme-assets", "public_grants": grants, "public_access_prevention": "inherited",
		"uniform_access": true, "policy_readable": true,
	})

	// ctlog and dns
	e.scan("ctlog", "ctlog", "example.com", pick(2, 2).(int))
	e.scan("dns", "dns", "example.com", 2)
	e.node("host:app.example.com", KindHost, "ctlog", map[string]any{"domain": "example.com", "host": "app.example.com"})
	e.node("host:www.example.com", KindHost, "ctlog", map[string]any{"domain": "example.com", "host": "www.example.com"})
	e.node("dns-cname:app.example.com", KindCNAME, "dns", map[string]any{"domain": "example.com", "host": "app.example.com", "target": "acme.herokudns.com", "target_resolves": true})
	e.edge("host:app.example.com", "host:acme.herokudns.com", EdgePointsTo, "dns")

	s := TakeSnapshot(e.g, at)
	if !second {
		s = stored(t, s) // the earlier run comes back from disk
	}
	return s
}

// stored round-trips a snapshot through JSON, as reading it from disk does.
func stored(t *testing.T, s Snapshot) Snapshot {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var out Snapshot
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func types(d DiffResult) []string {
	out := []string{}
	for _, c := range d.Changes {
		out = append(out, c.Type)
	}
	return out
}

func TestDiffWeekApartFindsEachWeakeningAndNoNoise(t *testing.T) {
	d := Diff(weekRun(t, false), weekRun(t, true))
	for _, c := range d.Changes {
		t.Log(c.Type, "|", c.Summary)
	}
	want := []string{ChangeNewAdmin, ChangeNewKey, ChangeSecretSeen, ChangeBypassOn, ChangeMCPServer, ChangePublic}
	if got := types(d); !reflect.DeepEqual(got, want) {
		for _, c := range d.Changes {
			t.Log(c.Type, c.Subject, c.Summary)
		}
		t.Fatalf("types = %v, want %v", got, want)
	}
	for _, c := range d.Changes {
		if !c.Weakening {
			t.Errorf("%s should weaken: %s", c.Type, c.Summary)
		}
		if emailRe.MatchString(c.Summary) || strings.Contains(c.Summary, "@") {
			t.Errorf("summary holds an address: %s", c.Summary)
		}
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped %v", d.Skipped)
	}
	byType := map[string]Change{}
	for _, c := range d.Changes {
		byType[c.Type] = c
	}
	if c := byType[ChangeNewAdmin]; c.Subject != ID("google:user/"+hashA) || c.Attr != "is_admin" || c.Before != false || c.After != true {
		t.Errorf("new admin: %+v", c)
	}
	if c := byType[ChangeNewKey]; c.Subject != "aws:key/AKIAAAAAAAAAAAAAAAA2" || !strings.Contains(c.Summary, "deploy-bot") {
		t.Errorf("new key: %+v", c)
	}
	if c := byType[ChangeSecretSeen]; !strings.Contains(c.Summary, "scripts/deploy.sh") || strings.Contains(c.Summary, secret) {
		t.Errorf("secret: %+v", c)
	}
	if c := byType[ChangeBypassOn]; c.Summary != "default branch rule of acme/api: bypass is now allowed (was none)" {
		t.Errorf("bypass: %q", c.Summary)
	}
	if c := byType[ChangeMCPServer]; !strings.Contains(c.Summary, "postgres") {
		t.Errorf("mcp: %+v", c)
	}
}

func TestDiffIgnoresTimesCountersAndLines(t *testing.T) {
	old := weekRun(t, false)
	new := stored(t, old)
	new.Time = old.Time.Add(7 * 24 * time.Hour)
	for i, n := range new.Nodes {
		n.SeenAt = new.Time
		switch n.Kind {
		case KindAWSPrincipal:
			n.Attrs["last_used"] = "2026-11-12T00:00:00Z"
			n.Attrs["created"] = "2026-01-01T00:00:00Z"
		case KindIdentityUser:
			n.Attrs["last_login"] = "2026-11-12T00:00:00Z"
		case KindScan:
			n.Attrs["inspected"] = float64(999)
		case KindSecretSeen:
			n.ID = ID(strings.Replace(string(n.ID), ":3", ":30", 1))
			n.Attrs["line"] = float64(30)
		}
		new.Nodes[i] = n
	}
	if d := Diff(old, new); len(d.Changes) != 0 {
		t.Fatalf("noise read as changes: %+v", d.Changes)
	}
}

func TestDiffIdenticalSnapshotsHaveNoChanges(t *testing.T) {
	s := weekRun(t, true)
	d := Diff(s, s)
	if len(d.Changes) != 0 || len(d.Skipped) != 0 {
		t.Fatalf("%+v", d)
	}
}

func TestDiffSecretOccurrenceIsKeyedByFileNotLine(t *testing.T) {
	occ := func(line int, file string) Node {
		return Node{ID: ID("secret:" + secret + "@acme/api/" + file + ":" + strconv.Itoa(line)), Kind: KindSecretSeen, Source: "files",
			Attrs: map[string]any{"hash": secret, "repo": "acme/api", "file": file, "line": int64(line), "agent_readable": false}}
	}
	scan := Node{ID: ScanID("secrets", "acme/api"), Kind: KindScan, Source: "files", Attrs: map[string]any{"scanner": "secrets", "scope": "acme/api", "inspected": int64(3)}}
	old := Snapshot{Nodes: []Node{scan, occ(3, "a.env")}}
	moved := Snapshot{Nodes: []Node{scan, occ(9, "a.env"), occ(20, "a.env")}}
	if d := Diff(old, moved); len(d.Changes) != 0 {
		t.Fatalf("a moved line is not a change: %+v", d.Changes)
	}
	elsewhere := Snapshot{Nodes: []Node{scan, occ(3, "b.env")}}
	d := Diff(old, elsewhere)
	if got := types(d); !reflect.DeepEqual(got, []string{ChangeSecretSeen, ChangeRemoved}) {
		t.Fatalf("types = %v", got)
	}
}

func TestDiffSkipsAConnectorNotReadInEitherRun(t *testing.T) {
	full := weekRun(t, false)
	withoutAWS := func(s Snapshot) Snapshot {
		out := s
		out.Nodes, out.Edges = nil, nil
		for _, n := range s.Nodes {
			if n.Source != "aws" {
				out.Nodes = append(out.Nodes, n)
			}
		}
		for _, e := range s.Edges {
			if e.Source != "aws" {
				out.Edges = append(out.Edges, e)
			}
		}
		return out
	}
	// Absent in the earlier run, inferred from the nodes.
	d := Diff(withoutAWS(full), full)
	assertNoSource(t, d, "aws")
	if !reflect.DeepEqual(d.Skipped, []string{"aws: not read in the earlier run"}) {
		t.Fatalf("skipped = %v", d.Skipped)
	}
	// Failed in the later run, recorded explicitly.
	later := withoutAWS(weekRun(t, true))
	later.Coverage = &Coverage{Read: []string{"config", "github", "google", "files", "gcp", "ctlog", "dns"}, Failed: []string{"aws"}}
	d = Diff(full, later)
	assertNoSource(t, d, "aws")
	if !reflect.DeepEqual(d.Skipped, []string{"aws: failed in the later run"}) {
		t.Fatalf("skipped = %v", d.Skipped)
	}
}

func assertNoSource(t *testing.T, d DiffResult, source string) {
	t.Helper()
	for _, c := range d.Changes {
		if c.System == source {
			t.Fatalf("%s changes reported although it was not read in both runs: %+v", source, c)
		}
	}
}

func TestDiffPrefersRecordedCoverage(t *testing.T) {
	old, new := weekRun(t, false), weekRun(t, true)
	// The nodes are there, but the run says GitHub did not collect cleanly.
	new.Coverage = &Coverage{Read: []string{"config", "aws", "google", "files", "gcp", "ctlog", "dns"}, Failed: []string{"github"}}
	d := Diff(old, new)
	assertNoSource(t, d, "github")
	if !contains(d.Skipped, "github: failed in the later run") {
		t.Fatalf("skipped = %v", d.Skipped)
	}
}

func TestDiffRepoScannedInOneRunGivesNoFileChanges(t *testing.T) {
	old, new := weekRun(t, false), weekRun(t, true)
	e := &estate{at: new.Time, g: FromSnapshot(new)}
	e.scan("files", "secrets", "acme/web", 10)
	e.scan("files", "terraform", "acme/web", 1)
	e.node("github:workflow/acme/web/.github/workflows/release.yml", KindWorkflow, "files", map[string]any{
		"file": ".github/workflows/release.yml", "permissions": "write", "triggers": []any{"pull_request_target"}, "repo": "acme/web",
	})
	e.node("tf:bucket/acme/web/logs", KindTFBucket, "files", map[string]any{"name": "logs", "file": "main.tf", "public_acl": true, "repo": "acme/web"})
	e.edge("secret:"+secret, "file:acme/web/.env", EdgeFoundIn, "files")
	d := Diff(old, TakeSnapshot(e.g, new.Time))
	for _, c := range d.Changes {
		if strings.Contains(string(c.Subject), "acme/web") || strings.Contains(c.Summary, "acme/web") {
			t.Fatalf("acme/web was scanned only once, yet: %+v", c)
		}
	}
	if !contains(d.Skipped, "files acme/web: not scanned in the earlier run") {
		t.Fatalf("skipped = %v", d.Skipped)
	}
}

func TestDiffGCPProjectThatFailedIsSkipped(t *testing.T) {
	old, new := weekRun(t, false), weekRun(t, true)
	for i, n := range new.Nodes {
		if n.Kind == KindGCPProject {
			new.Nodes[i].Attrs["error"] = "read the IAM policy: 403"
		}
	}
	d := Diff(old, new)
	assertNoSource(t, d, "gcp")
	if !contains(d.Skipped, "gcp acme-prod: could not be read in the later run") {
		t.Fatalf("skipped = %v", d.Skipped)
	}
}

func TestDiffPartialDomainScanIsSkipped(t *testing.T) {
	old, new := weekRun(t, false), weekRun(t, true)
	var nodes []Node
	for _, n := range new.Nodes {
		if n.ID == "host:www.example.com" {
			continue // missing because certificate logs timed out
		}
		if n.ID == ScanID("ctlog", "example.com") {
			n.Attrs["partial"] = "certificate log timed out"
		}
		nodes = append(nodes, n)
	}
	new.Nodes = nodes
	d := Diff(old, new)
	assertNoSource(t, d, "ctlog")
	if !contains(d.Skipped, "ctlog example.com: read only in part in the later run") {
		t.Fatalf("skipped = %v", d.Skipped)
	}
}

func TestDiffEdgesAddedAndRemoved(t *testing.T) {
	old, new := weekRun(t, false), weekRun(t, true)
	g := FromSnapshot(new)
	g.Node(Node{ID: "github:env/acme/api/staging", Kind: KindEnvironment, Source: "github", Attrs: map[string]any{"required_reviewers": []any{}}})
	g.Edge(Edge{From: "github:repo/acme/api", To: "github:env/acme/api/staging", Kind: EdgeDeploysTo, Source: "github"})
	s := TakeSnapshot(g, new.Time)
	var edges []Edge
	for _, e := range s.Edges {
		if e.Kind != EdgePointsTo {
			edges = append(edges, e)
		}
	}
	s.Edges = edges
	d := Diff(old, s)
	var deploy, gone, envAdded int
	for _, c := range d.Changes {
		switch {
		case c.Type == ChangeDeployPath:
			deploy++
			if !c.Weakening || c.Summary != "new deploy path: repo acme/api deploys to environment acme/api/staging" {
				t.Errorf("deploy: %+v", c)
			}
		case c.Type == ChangeRemoved && c.Edge != nil && c.Edge.Kind == EdgePointsTo:
			gone++
			if c.Weakening {
				t.Errorf("a removal is not a weakening: %+v", c)
			}
		case c.Subject == "github:env/acme/api/staging":
			envAdded++
		}
	}
	if deploy != 1 || gone != 1 || envAdded != 0 {
		t.Fatalf("deploy %d, gone %d, env added %d: %+v", deploy, gone, envAdded, d.Changes)
	}
}

func TestDiffStrengtheningIsNotAWeakening(t *testing.T) {
	old, new := weekRun(t, true), weekRun(t, false)
	d := Diff(stored(t, old), new)
	if len(d.Changes) == 0 {
		t.Fatal("no changes")
	}
	for _, c := range d.Changes {
		if c.Weakening {
			t.Errorf("going back is not a weakening: %+v", c)
		}
	}
}

func TestDiffWeakeningRules(t *testing.T) {
	cases := []struct {
		kind, attr    string
		before, after any
		typ           string
		weak          bool
	}{
		{KindBranchRule, "required_approvals", int64(2), int64(1), ChangeWeakened, true},
		{KindBranchRule, "required_approvals", int64(1), int64(2), ChangeChanged, false},
		{KindBranchRule, "force_push_allowed", false, true, ChangeWeakened, true},
		{KindBranchRule, "deletion_allowed", false, true, ChangeWeakened, true},
		{KindIdentityUser, "mfa_enforced", true, false, ChangeWeakened, true},
		{KindEnvironment, "required_reviewers", []any{"acme/release", "acme/sre"}, []any{"acme/release"}, ChangeWeakened, true},
		{KindEnvironment, "required_reviewers", []any{"acme/release"}, []any{"acme/sre", "acme/release"}, ChangeChanged, false},
		{KindWorkflow, "permissions", "read", "write", ChangeWeakened, true},
		{KindWorkflow, "triggers", []any{"push"}, []any{"push", "pull_request_target"}, ChangeWeakened, true},
		{KindWorkflow, "unpinned_actions", []any{}, []any{"acme/deploy@main"}, ChangeWeakened, true},
		{KindWorkflow, "triggers", []any{"push", "pull_request"}, []any{"pull_request", "push"}, "", false},
		{KindTFBucket, "public_access_block", true, false, ChangePublic, true},
		{KindCNAME, "target_resolves", false, true, ChangePublic, true},
		{KindGCPBucket, "public_access_prevention", "enforced", "inherited", ChangePublic, true},
		{KindAgentConfig, "denied_commands", []any{"rm -rf"}, []any{}, ChangeWeakened, true},
		{KindAWSPrincipal, "is_admin", false, true, ChangeNewAdmin, true},
		{KindAWSPrincipal, "is_admin", true, false, ChangeChanged, false},
		{KindAWSPrincipal, "github_oidc_unscoped", false, true, ChangeWeakened, true},
		{KindAWSPrincipal, "github_oidc_unscoped", true, false, ChangeChanged, false},
		{KindAWSPrincipal, "github_oidc", false, true, ChangeChanged, false},
		{KindWorkflow, "unfrozen_installs", []any{}, []any{"npm install"}, ChangeWeakened, true},
		{KindWorkflow, "unfrozen_installs", []any{"npm install"}, []any{}, ChangeChanged, false},
		{KindWorkflow, "cloud_key_secrets", []any{}, []any{"AWS_SECRET_ACCESS_KEY"}, ChangeWeakened, true},
		{KindWorkflow, "cloud_key_secrets", []any{"AWS_SECRET_ACCESS_KEY"}, []any{}, ChangeChanged, false},
		{KindWorkflow, "uses_oidc", true, false, ChangeChanged, false},
		{KindManifest, "lockfile_committed", true, false, ChangeWeakened, true},
		{KindManifest, "lockfile_committed", false, true, ChangeChanged, false},
		{KindManifest, "install_scripts", []any{"esbuild"}, []any{"acme-colors", "esbuild"}, ChangeWeakened, true},
		{KindManifest, "install_scripts", []any{"acme-colors", "esbuild"}, []any{"esbuild"}, ChangeChanged, false},
		{KindManifest, "lockfile", "", "package-lock.json", ChangeChanged, false},
		{KindManifest, "manager", "npm", "pnpm", ChangeChanged, false},
		{KindManifest, "install_scripts_known", true, false, ChangeChanged, false},
		{KindOAuthApp, "sensitive_scopes", []any{}, []any{"https://mail.google.com/"}, ChangeOAuthGrant, true},
		{KindOAuthApp, "sensitive_scopes", []any{"https://mail.google.com/"}, []any{}, ChangeChanged, false},
		{KindDatabase, "automated_backups", true, false, ChangeWeakened, true},
		{KindDatabase, "automated_backups", false, true, ChangeChanged, false},
		{KindDatabase, "retention_days", int64(14), int64(1), ChangeWeakened, true},
		{KindDatabase, "retention_days", int64(1), int64(14), ChangeChanged, false},
		{KindDatabase, "deletion_protection", true, false, ChangeWeakened, true},
		{KindDatabase, "deletion_protection", false, true, ChangeChanged, false},
		{KindDatabase, "separate_copy", "yes", "no", ChangeWeakened, true},
		{KindDatabase, "separate_copy", "declared", "no", ChangeWeakened, true},
		{KindDatabase, "separate_copy", "yes", "unknown", ChangeChanged, false},
		{KindDatabase, "separate_copy", "no", "yes", ChangeChanged, false},
		{KindDatabase, "production", false, true, ChangeChanged, false},
		{KindAIKey, "status", "inactive", "active", ChangeNewKey, true},
		{KindAIKey, "status", "active", "archived", ChangeChanged, false},
		{KindAIKey, "has_owner", true, false, ChangeWeakened, true},
		{KindAIKey, "has_owner", false, true, ChangeChanged, false},
		{KindAIKey, "capped", true, false, ChangeWeakened, true},
		{KindAIKey, "capped", false, true, ChangeChanged, false},
		{KindConfigAIKey, "monthly_limit_usd", 500.0, -1.0, ChangeWeakened, true},
		{KindConfigAIKey, "monthly_limit_usd", 500.0, 800.0, ChangeChanged, false},
		{KindConfigAIKey, "owner", "@ml", "@platform", ChangeChanged, false},
		{KindConfigApp, "owner", "@it", "", ChangeChanged, false},
		{KindConfigApp, "reviewed", "2026-01-01", "2026-11-01", ChangeChanged, false},
		{KindConfigBackup, "copy_location", "vault in 444455556666", "vault in 555566667777", ChangeChanged, false},
		{KindConfigBackup, "owner", "@platform", "@sre", ChangeChanged, false},
		// A new org admin is told by its admin_of edge, so the role alone is not.
		{KindGitHubUser, "org_role", "member", "admin", ChangeChanged, false},
		{KindGitHubUser, "org_role", "member", "outside", ChangeChanged, false},
		{KindGitHubUser, "site_admin", false, true, ChangeNewAdmin, true},
		{KindGitHubUser, "site_admin", true, false, ChangeChanged, false},
		{KindGitHubUser, "type", "user", "bot", ChangeChanged, false},
		{KindGitHubTeam, "privacy", "secret", "closed", ChangeChanged, false},
		{KindGitHubTeam, "parent", "", "platform", ChangeChanged, false},
		{KindAgentConfig, "mcp_servers",
			[]any{map[string]any{"name": "docs", "credentials": []any{}, "transport": "http", "host": "mcp.acme.com", "host_known": true, "pinned": true}},
			[]any{map[string]any{"name": "docs", "credentials": []any{}, "transport": "http", "host": "mcp.unknown.example", "host_known": false, "pinned": true}},
			ChangeWeakened, true},
		{KindAgentConfig, "mcp_servers",
			[]any{map[string]any{"name": "fs", "credentials": []any{}, "transport": "stdio", "package": "acme-mcp", "version": "1.0.0", "pinned": true, "package_known": true}},
			[]any{map[string]any{"name": "fs", "credentials": []any{}, "transport": "stdio", "package": "acme-mcp", "version": "", "pinned": false, "package_known": true}},
			ChangeWeakened, true},
		{KindAgentConfig, "mcp_servers",
			[]any{map[string]any{"name": "fs", "credentials": []any{}, "transport": "stdio", "package": "acme-mcp", "version": "1.0.0", "pinned": true, "package_known": true}},
			[]any{map[string]any{"name": "fs", "credentials": []any{}, "transport": "stdio", "package": "acme-mcp", "version": "1.1.0", "pinned": true, "package_known": true}},
			ChangeChanged, false},
		{KindAgentConfig, "mcp_servers",
			[]any{map[string]any{"name": "fs", "credentials": []any{}}},
			[]any{map[string]any{"name": "fs", "credentials": []any{}, "transport": "stdio", "package": "acme-mcp", "version": "", "pinned": false, "package_known": false}},
			ChangeChanged, false},
	}
	for _, c := range cases {
		a := Node{ID: "x", Kind: c.kind, Source: "s", Attrs: map[string]any{c.attr: c.before}}
		b := Node{ID: "x", Kind: c.kind, Source: "s", Attrs: map[string]any{c.attr: c.after}}
		got := compareNode(a, b)
		if c.typ == "" {
			if len(got) != 0 {
				t.Errorf("%s %s: order alone is not a change: %+v", c.kind, c.attr, got)
			}
			continue
		}
		if len(got) != 1 || got[0].Type != c.typ || got[0].Weakening != c.weak {
			t.Errorf("%s %s %v -> %v: got %+v", c.kind, c.attr, c.before, c.after, got)
		}
	}
}

func TestDiffIgnoresKindsNotInTheTable(t *testing.T) {
	old := Snapshot{Nodes: []Node{{ID: "semgrep:a", Kind: KindSemgrep, Source: "semgrep", Attrs: map[string]any{"line": int64(1)}}}}
	new := Snapshot{Nodes: []Node{{ID: "semgrep:b", Kind: KindSemgrep, Source: "semgrep"}, {ID: "file:acme/api/x.json", Kind: KindFileDoc, Source: "files"}}}
	if d := Diff(old, new); len(d.Changes) != 0 {
		t.Fatalf("%+v", d.Changes)
	}
}

func TestDiffIsDeterministic(t *testing.T) {
	a := Diff(weekRun(t, false), weekRun(t, true))
	for range 5 {
		b := Diff(weekRun(t, false), weekRun(t, true))
		if !reflect.DeepEqual(a, b) {
			t.Fatal("two diffs of the same snapshots differ")
		}
	}
}

func TestFromSnapshotRestoresWholeNumbers(t *testing.T) {
	g := FromSnapshot(stored(t, weekRun(t, false)))
	n, ok := g.Get(ScanID("secrets", "acme/api"))
	if !ok {
		t.Fatal("scan missing")
	}
	if v, ok := n.Attrs["inspected"].(int64); !ok || v != 40 {
		t.Fatalf("inspected = %#v", n.Attrs["inspected"])
	}
	if len(g.Edges(EdgeHolds)) != 1 {
		t.Fatalf("edges: %v", g.Edges(""))
	}
}

func TestDiffTier1AddedAndRemoved(t *testing.T) {
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	run := func(second bool) Snapshot {
		e := &estate{at: at, g: New()}
		e.scan("google", "oauth_tokens", "", 3)
		e.scan("aws", "aws_backups", "acme-prod", 1)
		e.scan("anthropic", "ai_keys", "anthropic", 1)
		e.node("config:settings", KindConfigSettings, "config", map[string]any{"min_retention_days": int64(7)})
		app := ID("google:oauth-app/1234-notes.apps.googleusercontent.com")
		if second {
			e.node(app, KindOAuthApp, "google", map[string]any{"client_id": "1234-notes.apps.googleusercontent.com", "name": "Acme Notes AI",
				"sensitive_scopes": []any{"https://mail.google.com/"}, "high_risk": true, "user_count": int64(1)})
			e.edge(app, "person:"+hashA, EdgeGrantedTo, "google")
			e.node("anthropic:key/apikey_01AcmeLoop", KindAIKey, "anthropic", map[string]any{"provider": "anthropic",
				"key_id": "apikey_01AcmeLoop", "name": "overnight-agent", "status": "active", "has_owner": false, "capped": false})
		} else {
			e.node("aws:db/111122223333/us-east-1/orders", KindDatabase, "aws", map[string]any{"system": "aws", "account": "111122223333",
				"profile": "acme-prod", "region": "us-east-1", "name": "orders", "automated_backups": true, "retention_days": int64(7)})
			e.node("config-backup:orders", KindConfigBackup, "config", map[string]any{"database": "orders", "copy_location": "vault"})
		}
		snap := TakeSnapshot(e.g, at)
		snap.Coverage = &Coverage{Read: []string{"config", "google", "aws", "anthropic"}}
		return snap
	}
	d := Diff(run(false), run(true))
	byType := map[string][]Change{}
	for _, c := range d.Changes {
		byType[c.Type] = append(byType[c.Type], c)
		if strings.Contains(c.Summary, "@") {
			t.Fatalf("a summary holds an address: %s", c.Summary)
		}
	}
	if len(byType[ChangeOAuthGrant]) != 1 || !byType[ChangeOAuthGrant][0].Weakening || !strings.Contains(byType[ChangeOAuthGrant][0].Summary, "mail.google.com") {
		t.Fatalf("a new app is a new OAuth grant, its edge told by the node: %+v", d.Changes)
	}
	if len(byType[ChangeNewKey]) != 1 || !strings.Contains(byType[ChangeNewKey][0].Summary, "apikey_01AcmeLoop") {
		t.Fatalf("a new active key: %+v", d.Changes)
	}
	if len(byType[ChangeWeakened]) != 2 {
		t.Fatalf("a database and a declared copy gone are both worth a glance: %+v", d.Changes)
	}
	for _, c := range byType[ChangeWeakened] {
		if !c.Weakening || !strings.HasPrefix(c.Summary, "gone: ") {
			t.Fatalf("%+v", c)
		}
	}
}

func TestDiffSkipsATier1CollectionThatFailed(t *testing.T) {
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	run := func(read bool) Snapshot {
		e := &estate{at: at, g: New()}
		e.node("google:user/"+hashA, KindIdentityUser, "google", map[string]any{"is_admin": false})
		if read {
			e.scan("google", "oauth_tokens", "", 3)
			e.node("google:oauth-app/x", KindOAuthApp, "google", map[string]any{"client_id": "x", "sensitive_scopes": []any{}})
			e.edge("google:oauth-app/x", ID("person:"+hashA), EdgeGrantedTo, "google")
			e.scan("aws", "aws_backups", "acme-prod", 1)
			e.node("aws:db/1/us-east-1/orders", KindDatabase, "aws", map[string]any{"system": "aws", "profile": "acme-prod", "name": "orders"})
		} else {
			// The scope was missing, and RDS was denied: both scans carry an error.
			for _, sc := range [][3]string{{"google", "oauth_tokens", ""}, {"aws", "aws_backups", "acme-prod"}} {
				e.g.Node(Node{ID: ScanID(sc[1], sc[2]), Kind: KindScan, Source: sc[0], SeenAt: at,
					Attrs: map[string]any{"scanner": sc[1], "scope": sc[2], "inspected": int64(0), "partial": "denied", "error": "denied"}})
			}
		}
		snap := TakeSnapshot(e.g, at)
		snap.Coverage = &Coverage{Read: []string{"google", "aws"}}
		return snap
	}
	d := Diff(run(true), run(false))
	if len(d.Changes) != 0 {
		t.Fatalf("a collection that failed while its connector worked is not everything gone: %+v", d.Changes)
	}
	if len(d.Skipped) != 2 {
		t.Fatalf("%v", d.Skipped)
	}
}

func TestDiffGitHubPeople(t *testing.T) {
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	ana, bo, dee, eve := ID("github:user/"+hashA), ID("github:user/"+hashB), ID("github:user/"+secret), ID("github:user/eeee5555ffff6666aaaa7777bbbb8888")
	repo, org := ID("github:repo/acme/api"), ID("github:org/acme")
	run := func(second bool) Snapshot {
		e := &estate{at: at, g: New()}
		e.scan("github", "github_people", "acme", 3)
		e.scan("github", "github_repo_people", "acme/api", 3)
		user := func(id ID, role string) {
			e.node(id, KindGitHubUser, "github", map[string]any{"org": "acme", "org_role": role, "type": "user"})
		}
		user(ana, "admin")
		e.edge(ana, org, EdgeAdminOf, "github")
		e.edge(ana, repo, EdgeAdminOf, "github")
		e.edge(bo, repo, EdgeWritesTo, "github")
		e.node("github:team/acme/core", KindGitHubTeam, "github", map[string]any{"org": "acme", "slug": "core", "privacy": "closed", "parent": ""})
		if !second {
			user(bo, "member")
			user(dee, "member")
			return TakeSnapshot(e.g, at)
		}
		user(bo, "admin") // promoted to owner
		e.edge(bo, org, EdgeAdminOf, "github")
		e.edge(bo, repo, EdgeCanBypass, "github") // a new bypass actor
		user(dee, "outside")                      // left the org, kept write
		e.edge(dee, repo, EdgeWritesTo, "github")
		user(eve, "member") // a new account that is a repo admin
		e.edge(eve, repo, EdgeAdminOf, "github")
		e.node("github:app/77", KindGitHubApp, "github", map[string]any{"org": "acme", "name": "acme-deployer"})
		e.edge("github:app/77", repo, EdgeCanBypass, "github")
		return TakeSnapshot(e.g, at.Add(time.Hour))
	}
	d := Diff(run(false), run(true))
	byType := map[string][]Change{}
	for _, c := range d.Changes {
		byType[c.Type] = append(byType[c.Type], c)
		for _, login := range []string{"ana-acme", "bo-acme"} {
			if strings.Contains(c.Summary, login) {
				t.Fatalf("a summary holds a login: %s", c.Summary)
			}
		}
	}
	admins := map[string]bool{}
	for _, c := range byType[ChangeNewAdmin] {
		admins[c.Summary] = c.Weakening
	}
	for _, want := range []string{"GitHub user bbbb2222 is now an admin of org acme", "GitHub user eeee5555 is now an admin of repo acme/api"} {
		if !admins[want] {
			t.Errorf("missing new admin %q in %+v", want, byType[ChangeNewAdmin])
		}
	}
	bypass := map[string]bool{}
	for _, c := range byType[ChangeBypassActor] {
		bypass[c.Summary] = c.Weakening
	}
	for _, want := range []string{"GitHub user bbbb2222 can now bypass review on repo acme/api", "GitHub app acme-deployer can now bypass review on repo acme/api"} {
		if !bypass[want] {
			t.Errorf("missing new bypass actor %q in %+v", want, byType[ChangeBypassActor])
		}
	}
	outside := false
	for _, c := range byType[ChangeWeakened] {
		if c.Subject == dee && c.Weakening && strings.Contains(c.Summary, "outside collaborator who can push to acme/api") {
			outside = true
		}
	}
	if !outside {
		t.Errorf("a member who became an outside collaborator with write is a weakening: %+v", d.Changes)
	}
	if ChangeLabel(ChangeBypassActor) != "New bypass actor" {
		t.Fatal(ChangeLabel(ChangeBypassActor))
	}

	// A new writes_to edge from an outside collaborator is a weakening; from a
	// member it is not.
	snap := run(true)
	c := edgeDiff(Edge{From: dee, To: repo, Kind: EdgeWritesTo, Source: "github"}, true, snap, run(false), nil)
	if c.Type != ChangeWeakened || !c.Weakening {
		t.Fatalf("%+v", c)
	}
	c = edgeDiff(Edge{From: ana, To: repo, Kind: EdgeWritesTo, Source: "github"}, true, snap, run(false), nil)
	if c.Type != ChangeAdded || c.Weakening {
		t.Fatalf("%+v", c)
	}
	c = edgeDiff(Edge{From: ana, To: "github:team/acme/core", Kind: EdgeMemberOf, Source: "github"}, true, snap, run(false), nil)
	if c.Weakening || !strings.Contains(c.Summary, "is a member of team acme/core") {
		t.Fatalf("%+v", c)
	}
}

func TestDiffSkipsGitHubPeopleNotRead(t *testing.T) {
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	bo, repo := ID("github:user/"+hashB), ID("github:repo/acme/api")
	run := func(read bool) Snapshot {
		e := &estate{at: at, g: New()}
		if read {
			e.scan("github", "github_people", "acme", 1)
			e.scan("github", "github_repo_people", "acme/api", 1)
			e.node(bo, KindGitHubUser, "github", map[string]any{"org": "acme", "org_role": "member", "type": "user"})
			e.edge(bo, repo, EdgeCanBypass, "github")
		} else {
			// Members could not be read, and acme/api's bypass list could not be.
			e.g.Node(Node{ID: ScanID("github_people", "acme"), Kind: KindScan, Source: "github", SeenAt: at,
				Attrs: map[string]any{"scanner": "github_people", "scope": "acme", "inspected": int64(0), "partial": "denied", "error": "denied"}})
		}
		snap := TakeSnapshot(e.g, at)
		snap.Coverage = &Coverage{Read: []string{"github"}}
		return snap
	}
	d := Diff(run(true), run(false))
	if len(d.Changes) != 0 {
		t.Fatalf("people not read are not people gone: %+v", d.Changes)
	}
	if len(d.Skipped) != 2 {
		t.Fatalf("%v", d.Skipped)
	}
}
