package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/connectors/files"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

var now = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)

type rewrite struct{ server *httptest.Server }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.server.URL)
	c := req.Clone(req.Context())
	c.Header.Set("X-Original-Host", req.URL.Host)
	c.URL.Scheme, c.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(c)
}

type routes map[string]any

func fakeGitHub(t *testing.T, r routes) *Connector {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			t.Errorf("the connector sent %s %s", req.Method, req.URL.Path)
		}
		if got := req.Header.Get("Authorization"); got != "Bearer tok" {
			t.Errorf("auth header: %q", got)
		}
		v, ok := r[req.URL.Path]
		if !ok {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		if code, isInt := v.(int); isInt {
			w.WriteHeader(code)
			_, _ = io.WriteString(w, `{"message":"no"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(v)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.Next, c.Limit, c.Burst = rewrite{srv}, 10000, 10000
	return c
}

func scope(t *testing.T) connector.Scope {
	t.Helper()
	dir := t.TempDir()
	p := &config.Project{Dir: filepath.Join(dir, ".firedrill")}
	p.Config.GitHub.Org = "acme"
	p.Config.GitHub.Repos = []string{"api"}
	return connector.Scope{Project: p, Now: now, Log: &connector.CallLog{}, Token: "tok", Hasher: graph.NewHasher("s")}
}

type obj = map[string]any

func base(extra routes) routes {
	r := routes{
		"/orgs/acme":      obj{"login": "acme", "plan": obj{"name": "team"}},
		"/repos/acme/api": obj{"name": "api", "private": true, "default_branch": "main"},
		"/repos/acme/api/actions/permissions/workflow": obj{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false},
	}
	maps.Copy(r, extra)
	return r
}

func collect(t *testing.T, c *Connector, s connector.Scope) *graph.Graph {
	t.Helper()
	g := graph.New()
	if err := c.Collect(context.Background(), c.Collections()[0], s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) > 0 {
		t.Fatalf("guard violations: %v", v)
	}
	return g
}

func rule(t *testing.T, g *graph.Graph) map[string]any {
	t.Helper()
	n, ok := g.Get("github:branch-rule/acme/api/default")
	if !ok {
		t.Fatal("no branch rule")
	}
	return n.Attrs
}

const protPath = "/repos/acme/api/branches/main/protection"
const rulesPath = "/repos/acme/api/rules/branches/main"

func TestNoProtectionAtAll(t *testing.T) {
	g := collect(t, fakeGitHub(t, base(nil)), scope(t))
	r := rule(t, g)
	if r["required_approvals"] != int64(0) || r["force_push_allowed"] != true || r["deletion_allowed"] != true || r["bypass"] != "none" {
		t.Fatalf("%+v", r)
	}
	repo, _ := g.Get("github:repo/acme/api")
	if repo.Attrs["plan"] != "team" || repo.Attrs["private"] != true || repo.Attrs["protection_available"] != true {
		t.Fatalf("%+v", repo.Attrs)
	}
}

func TestClassicProtection(t *testing.T) {
	g := collect(t, fakeGitHub(t, base(routes{protPath: obj{
		"required_pull_request_reviews": obj{"required_approving_review_count": 2, "dismiss_stale_reviews": true, "require_code_owner_reviews": true},
		"enforce_admins":                obj{"enabled": true},
		"allow_force_pushes":            obj{"enabled": false},
		"allow_deletions":               obj{"enabled": false},
	}})), scope(t))
	r := rule(t, g)
	if r["required_approvals"] != int64(2) || r["dismiss_stale"] != true || r["code_owner_review"] != true || r["bypass"] != "none" || r["force_push_allowed"] != false {
		t.Fatalf("%+v", r)
	}
}

func TestAdminsNotEnforcedMeansBypassAllowed(t *testing.T) {
	g := collect(t, fakeGitHub(t, base(routes{protPath: obj{
		"required_pull_request_reviews": obj{"required_approving_review_count": 1},
		"enforce_admins":                obj{"enabled": false},
	}})), scope(t))
	if r := rule(t, g); r["bypass"] != "allowed" {
		t.Fatalf("%+v", r)
	}
}

func rulesetRoutes(bypass any) routes {
	ruleset := obj{"id": 7, "name": "main"}
	if bypass != nil {
		ruleset["bypass_actors"] = bypass
	}
	return base(routes{
		rulesPath: []any{
			obj{"type": "pull_request", "ruleset_id": 7, "parameters": obj{"required_approving_review_count": 3, "dismiss_stale_reviews_on_push": true}},
			obj{"type": "non_fast_forward", "ruleset_id": 7},
			obj{"type": "deletion", "ruleset_id": 7},
		},
		"/repos/acme/api/rulesets/7": ruleset,
	})
}

func TestRulesetsMergeWithProtection(t *testing.T) {
	r := rulesetRoutes([]any{})
	r[protPath] = obj{"required_pull_request_reviews": obj{"required_approving_review_count": 1}, "enforce_admins": obj{"enabled": true}, "allow_force_pushes": obj{"enabled": true}}
	got := rule(t, collect(t, fakeGitHub(t, r), scope(t)))
	if got["required_approvals"] != int64(3) {
		t.Fatalf("the stricter rule wins: %+v", got)
	}
	if got["force_push_allowed"] != false || got["deletion_allowed"] != false || got["dismiss_stale"] != true {
		t.Fatalf("%+v", got)
	}
	if got["bypass"] != "none" || got["bypass_source"] != "api" {
		t.Fatalf("%+v", got)
	}
}

func TestBypassThreeValues(t *testing.T) {
	allowed := rule(t, collect(t, fakeGitHub(t, rulesetRoutes([]any{obj{"actor_id": 1, "actor_type": "Team", "bypass_mode": "always"}})), scope(t)))
	if allowed["bypass"] != "allowed" {
		t.Fatalf("%+v", allowed)
	}
	unseen := rule(t, collect(t, fakeGitHub(t, rulesetRoutes(nil)), scope(t)))
	if unseen["bypass"] != "unknown" {
		t.Fatalf("a read-only token sees no list, so bypass is unknown: %+v", unseen)
	}
}

func writeExport(t *testing.T, s connector.Scope, at time.Time, actors []json.RawMessage) {
	t.Helper()
	exp := Export{GeneratedAt: at, GeneratedBy: "admin", Repos: map[string]map[string]RulesetExport{"acme/api": {"7": {Name: "main", BypassActors: actors}}}}
	b, _ := json.Marshal(exp)
	p := filepath.Join(s.Project.Dir, ExportFile)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAdminExportFillsUnseenBypass(t *testing.T) {
	s := scope(t)
	writeExport(t, s, now.AddDate(0, 0, -5), []json.RawMessage{})
	got := rule(t, collect(t, fakeGitHub(t, rulesetRoutes(nil)), s))
	if got["bypass"] != "none" || got["bypass_source"] != "admin_export" || !strings.Contains(got["bypass_detail"].(string), "admin") {
		t.Fatalf("%+v", got)
	}

	s = scope(t)
	writeExport(t, s, now.AddDate(0, 0, -5), []json.RawMessage{json.RawMessage(`{"actor_id":1}`)})
	if got := rule(t, collect(t, fakeGitHub(t, rulesetRoutes(nil)), s)); got["bypass"] != "allowed" {
		t.Fatalf("%+v", got)
	}

	s = scope(t)
	writeExport(t, s, now.AddDate(0, 0, -31), []json.RawMessage{})
	if got := rule(t, collect(t, fakeGitHub(t, rulesetRoutes(nil)), s)); got["bypass"] != "unknown" {
		t.Fatalf("an export over 30 days old is not used: %+v", got)
	}
}

func TestEnvironments(t *testing.T) {
	g := collect(t, fakeGitHub(t, base(routes{"/repos/acme/api/environments": obj{"total_count": 1, "environments": []any{obj{
		"name": "production", "can_admins_bypass": false,
		"deployment_branch_policy": obj{"protected_branches": true, "custom_branch_policies": false},
		"protection_rules": []any{
			obj{"type": "required_reviewers", "prevent_self_review": true, "reviewers": []any{obj{"type": "User", "reviewer": obj{"login": "ravi"}}}},
		},
	}}}})), scope(t))
	n, ok := g.Get("github:env/acme/api/production")
	if !ok {
		t.Fatal("no environment")
	}
	if n.Attrs["prevent_self_review"] != true || n.Attrs["admin_bypass"] != false || n.Attrs["protected_branches_only"] != true {
		t.Fatalf("%+v", n.Attrs)
	}
	rev := n.Attrs["required_reviewers"].([]any)
	if len(rev) != 1 || rev[0] != "ravi" {
		t.Fatalf("%+v", rev)
	}
}

func TestPlans(t *testing.T) {
	free := base(nil)
	free["/orgs/acme"] = obj{"plan": obj{"name": "free"}}
	repo, _ := collect(t, fakeGitHub(t, free), scope(t)).Get("github:repo/acme/api")
	if repo.Attrs["protection_available"] != false {
		t.Fatalf("free private repos have no protection: %+v", repo.Attrs)
	}
	hidden := base(nil)
	hidden["/orgs/acme"] = obj{"login": "acme"}
	repo, _ = collect(t, fakeGitHub(t, hidden), scope(t)).Get("github:repo/acme/api")
	if repo.Attrs["plan"] != "unknown" || repo.Attrs["protection_available"] != true {
		t.Fatalf("%+v", repo.Attrs)
	}
	user := base(nil)
	delete(user, "/orgs/acme")
	user["/users/acme"] = obj{"login": "acme", "plan": obj{"name": "pro"}}
	repo, _ = collect(t, fakeGitHub(t, user), scope(t)).Get("github:repo/acme/api")
	if repo.Attrs["plan"] != "pro" {
		t.Fatalf("%+v", repo.Attrs)
	}
}

func TestForbiddenProtectionIsNotFatal(t *testing.T) {
	collect(t, fakeGitHub(t, base(routes{protPath: 403, rulesPath: 403})), scope(t))
}

func TestRepoErrorIsReported(t *testing.T) {
	r := base(nil)
	delete(r, "/repos/acme/api")
	c := fakeGitHub(t, r)
	s := scope(t)
	if err := c.Collect(context.Background(), c.Collections()[0], s, graph.New()); err == nil {
		t.Fatal("a repo that can't be read must be an error")
	}
}

func TestExportRulesets(t *testing.T) {
	r := rulesetRoutes([]any{obj{"actor_id": 1}})
	r["/user"] = obj{"login": "admin"}
	r["/repos/acme/api/rulesets"] = []any{obj{"id": 7, "name": "main"}}
	c := fakeGitHub(t, r)
	s := scope(t)
	path, n, err := c.ExportRulesets(context.Background(), s)
	if err != nil || n != 1 {
		t.Fatalf("%v %d", err, n)
	}
	b, _ := os.ReadFile(path)
	var exp Export
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Fatal(err)
	}
	if exp.GeneratedBy != "admin" || len(exp.Repos["acme/api"]["7"].BypassActors) != 1 {
		t.Fatalf("%+v", exp)
	}
	// A non-admin gets no list, and must be told rather than write an empty one.
	r2 := rulesetRoutes(nil)
	r2["/user"] = obj{"login": "dev"}
	r2["/repos/acme/api/rulesets"] = []any{obj{"id": 7, "name": "main"}}
	if _, _, err := fakeGitHub(t, r2).ExportRulesets(context.Background(), scope(t)); err == nil {
		t.Fatal("a non-admin export must fail")
	}
}

func TestTarballThroughGuardedRedirect(t *testing.T) {
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	tw := tar.NewWriter(z)
	content := []byte("RAILWAY_TOKEN=6f1b9d2e-7c44-4a10-9e3b-2d5ac81f0e77\n")
	_ = tw.WriteHeader(&tar.Header{Name: "acme-api-abc/scripts/x.sh", Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(content)
	_ = tw.Close()
	_ = z.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Original-Host") {
		case "api.github.com":
			http.Redirect(w, r, "https://codeload.github.com/acme/api/tar.gz/main", http.StatusFound)
		case "codeload.github.com":
			_, _ = w.Write(buf.Bytes())
		default:
			t.Errorf("unexpected host %s", r.Header.Get("X-Original-Host"))
		}
	}))
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	s := scope(t)
	rc, err := c.Tarball(s)(context.Background(), "acme/api")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	got, err := files.ReadTarball(rc)
	if err != nil || len(got) != 1 || got[0].Path != "scripts/x.sh" {
		t.Fatalf("%v %+v", err, got)
	}
	if len(s.Log.Violations()) != 0 {
		t.Fatal(s.Log.Violations())
	}
}

func TestAvailable(t *testing.T) {
	s := scope(t)
	if ok, _ := New().Available(s); !ok {
		t.Fatal("token and repos present")
	}
	s.Token = ""
	if ok, why := New().Available(s); ok || !strings.Contains(why, "connect github") {
		t.Fatal(why)
	}
}
