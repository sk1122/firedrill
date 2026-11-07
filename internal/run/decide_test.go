package run

import (
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
	"github.com/sk1122/firedrill/packs"
)

var testNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

func loadDrill(t *testing.T, id string) *drill.Drill {
	t.Helper()
	data, err := packs.FS.ReadFile(id + ".drill.yaml")
	if err != nil {
		t.Fatal(err)
	}
	d, issues := drill.Load(id, data)
	if drill.HasErrors(issues) {
		t.Fatal(issues)
	}
	return d
}

func node(g *graph.Graph, id, kind string, attrs map[string]any) {
	g.Node(graph.Node{ID: graph.ID(id), Kind: kind, Attrs: attrs, Source: "fixture", SeenAt: testNow})
}

func ghRepo(g *graph.Graph, plan string, private bool) {
	node(g, "github:repo/acme/api", graph.KindGitHubRepo, map[string]any{
		"name": "acme/api", "private": private, "plan": plan, "protection_available": !private || plan != "free"})
	node(g, "github:actions/acme/api", graph.KindActionsPerms, map[string]any{
		"can_approve_pull_requests": false, "default_token_permission": "read"})
}

func branchRule(g *graph.Graph, approvals int64, bypass string, force bool) {
	node(g, "github:branch-rule/acme/api/default", graph.KindBranchRule, map[string]any{
		"required_approvals": approvals, "dismiss_stale": approvals > 0, "code_owner_review": false,
		"bypass": bypass, "bypass_source": "api", "force_push_allowed": force, "deletion_allowed": force})
}

func prodEnv(g *graph.Graph, reviewers []any, protected bool) {
	node(g, "github:env/acme/api/production", graph.KindEnvironment, map[string]any{
		"required_reviewers": reviewers, "prevent_self_review": len(reviewers) > 0, "admin_bypass": false,
		"protected_branches_only": protected})
}

func targetRepo(g *graph.Graph) {
	node(g, "repo:acme/api", graph.KindTargetRepo, map[string]any{"name": "acme/api", "local": true})
}

func scan(g *graph.Graph, scanner, scope string, n int) {
	graph.WriteScan(g, "fixture", scanner, scope, n, "", testNow)
}

func secret(g *graph.Graph, file, class, hash string, readable bool) {
	node(g, "secret:"+hash+"@"+file, graph.KindSecretSeen, map[string]any{
		"repo": "acme/api", "kind": "generic", "file": file, "line": int64(1), "env_class": class,
		"hash": hash, "agent_readable": readable, "key_id": ""})
}

func awsKey(g *graph.Graph, admin bool) {
	node(g, "s", graph.KindSecretSeen, map[string]any{"repo": "acme/api", "kind": "aws", "file": "a.sh", "line": int64(1),
		"env_class": "unknown", "hash": "h", "agent_readable": true, "key_id": "AKIAEXAMPLE"})
	node(g, "aws:key/AKIAEXAMPLE", graph.KindAWSKey, map[string]any{"key_id": "AKIAEXAMPLE", "account": "1", "user": "ci"})
	node(g, "aws:iam-user/1/ci", graph.KindAWSPrincipal, map[string]any{"account": "1", "principal_kind": "user", "name": "ci",
		"is_admin": admin, "destructive_actions": []any{}, "keys": []any{}, "excluded": false, "last_used": "", "created": ""})
}

func agentConfig(g *graph.Graph, unguarded []any, creds ...string) {
	servers := []any{}
	for i, c := range creds {
		servers = append(servers, map[string]any{"name": string(rune('a' + i)), "credentials": []any{c}})
	}
	node(g, "agent:claude/acme/api", graph.KindAgentConfig, map[string]any{"repo": "acme/api", "tool": "claude-code", "scope": "repo",
		"file": ".mcp.json", "allowed_commands": []any{}, "denied_commands": []any{}, "deny_read_paths": []any{},
		"unguarded_destructive": unguarded, "mcp_servers": servers})
}

func user(g *graph.Graph, email string, admin, suspended, enforced bool, login string) {
	g.Node(graph.Node{ID: graph.ID("google:user/" + email), Kind: graph.KindIdentityUser, SeenAt: testNow,
		Attrs: map[string]any{"suspended": suspended, "is_admin": admin, "is_delegated_admin": false, "mfa_enrolled": enforced,
			"mfa_enforced": enforced, "last_login": login, "created": "2020-01-01T00:00:00Z"},
		Private: map[string]any{"email": email}})
}

func leaver(g *graph.Graph, email, date string) {
	g.Node(graph.Node{ID: graph.ID("person:" + email), Kind: graph.KindLeaver, SeenAt: testNow,
		Attrs: map[string]any{"leave_date": date}, Private: map[string]any{"email": email}})
}

func domain(g *graph.Graph) {
	node(g, "domain:acme.com", graph.KindConfigDomain, map[string]any{"domain": "acme.com", "verified": true})
}

func gcpProject(g *graph.Graph, domains ...string) {
	ds := []any{}
	for _, d := range domains {
		ds = append(ds, d)
	}
	node(g, "gcp:project/acme-prod", graph.KindGCPProject, map[string]any{"name": "acme-prod", "number": "123", "member_domains": ds})
}

func gcpBinding(g *graph.Graph, role, kind, domain string, googleManaged bool) {
	node(g, "gcp:binding/acme-prod/"+role+"/"+kind+domain, graph.KindGCPBinding, map[string]any{
		"project": "acme-prod", "role": role, "member_type": kind, "member_domain": domain, "member": "",
		"google_managed": googleManaged, "default_account": false, "conditional": false})
}

func gcpBucket(g *graph.Graph, name string, public []any, pap string) {
	node(g, "gcp:bucket/"+name, graph.KindGCPBucket, map[string]any{
		"project": "acme-prod", "name": name, "public_grants": public, "public_access_prevention": pap, "uniform_access": true})
}

func gcpKey(g *graph.Graph, id, created, lastUsed string, known bool) {
	node(g, "gcp:key/acme-prod/"+id, graph.KindGCPKey, map[string]any{
		"project": "acme-prod", "service_account": "ci@acme-prod.iam.gserviceaccount.com", "key_id": id,
		"created": created, "last_used": lastUsed, "last_use_known": known, "disabled": false})
}

func TestEveryDrillGoesGreenRedAndNA(t *testing.T) {
	recent := "2026-11-01T00:00:00Z"
	cases := []struct {
		id, verdictWant string
		name            string
		setup           func(g *graph.Graph)
	}{
		{"change/no-solo-ship", tag.Pass, "pass on enterprise", func(g *graph.Graph) {
			ghRepo(g, "enterprise", true)
			branchRule(g, 1, "none", false)
			prodEnv(g, []any{"@a"}, true)
		}},
		{"change/no-solo-ship", tag.Pass, "pass on team uses protected branches", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			branchRule(g, 1, "none", false)
			prodEnv(g, []any{}, true)
		}},
		{"change/no-solo-ship", tag.Fail, "bypass allowed", func(g *graph.Graph) {
			ghRepo(g, "enterprise", true)
			branchRule(g, 1, "allowed", false)
			prodEnv(g, []any{"@a"}, true)
		}},
		{"change/no-solo-ship", tag.Warn, "bypass unseen", func(g *graph.Graph) {
			ghRepo(g, "enterprise", true)
			branchRule(g, 1, "unknown", false)
			prodEnv(g, []any{"@a"}, true)
		}},
		{"change/no-solo-ship", tag.NA, "no environment", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			branchRule(g, 1, "none", false)
		}},
		{"change/no-solo-ship", tag.NA, "free private repo", func(g *graph.Graph) {
			ghRepo(g, "free", true)
			branchRule(g, 0, "none", false)
			prodEnv(g, []any{}, false)
		}},
		{"change/human-review-required", tag.Pass, "pass", func(g *graph.Graph) { ghRepo(g, "team", true); branchRule(g, 1, "none", false) }},
		{"change/human-review-required", tag.Fail, "no approvals", func(g *graph.Graph) { ghRepo(g, "team", true); branchRule(g, 0, "none", false) }},
		{"change/human-review-required", tag.NA, "free", func(g *graph.Graph) { ghRepo(g, "free", true); branchRule(g, 0, "none", false) }},
		{"change/no-force-push-main", tag.Pass, "pass", func(g *graph.Graph) { ghRepo(g, "team", true); branchRule(g, 1, "none", false) }},
		{"change/no-force-push-main", tag.Fail, "force allowed", func(g *graph.Graph) { ghRepo(g, "team", true); branchRule(g, 1, "none", true) }},
		{"change/no-force-push-main", tag.NA, "free", func(g *graph.Graph) { ghRepo(g, "free", true); branchRule(g, 0, "none", true) }},
		{"change/prod-deploy-gated", tag.Pass, "pass", func(g *graph.Graph) { ghRepo(g, "team", true); prodEnv(g, []any{}, true) }},
		{"change/prod-deploy-gated", tag.Fail, "any branch", func(g *graph.Graph) { ghRepo(g, "team", true); prodEnv(g, []any{}, false) }},
		{"change/prod-deploy-gated", tag.Fail, "enterprise without reviewer", func(g *graph.Graph) { ghRepo(g, "enterprise", true); prodEnv(g, []any{}, true) }},
		{"change/prod-deploy-gated", tag.NA, "no env", func(g *graph.Graph) { ghRepo(g, "team", true) }},

		{"change/actions-pinned", tag.Pass, "pass", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			node(g, "w", graph.KindWorkflow, map[string]any{"repo": "acme/api", "file": "a", "permissions": "read", "unpinned_actions": []any{}, "pull_request_target_checkout": false})
		}},
		{"change/actions-pinned", tag.Fail, "unpinned", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			node(g, "w", graph.KindWorkflow, map[string]any{"repo": "acme/api", "file": "a", "permissions": "read", "unpinned_actions": []any{"x/y@v1"}, "pull_request_target_checkout": false})
		}},
		{"change/actions-pinned", tag.NA, "no workflows", func(g *graph.Graph) { targetRepo(g); scan(g, "workflows", "acme/api", 0) }},
		{"change/workflow-tokens-read-only", tag.Pass, "pass", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			node(g, "w", graph.KindWorkflow, map[string]any{"repo": "acme/api", "file": "a", "permissions": "read", "unpinned_actions": []any{}, "pull_request_target_checkout": false})
		}},
		{"change/workflow-tokens-read-only", tag.Fail, "pull request code", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			node(g, "w", graph.KindWorkflow, map[string]any{"repo": "acme/api", "file": "a", "permissions": "read", "unpinned_actions": []any{}, "pull_request_target_checkout": true})
		}},
		{"change/workflow-tokens-read-only", tag.NA, "none", func(g *graph.Graph) { targetRepo(g) }},

		{"access/leavers-locked-out", tag.Pass, "suspended", func(g *graph.Graph) {
			leaver(g, "a@x.com", "2026-10-01")
			user(g, "a@x.com", false, true, true, recent)
		}},
		{"access/leavers-locked-out", tag.Fail, "active", func(g *graph.Graph) {
			leaver(g, "a@x.com", "2026-10-01")
			user(g, "a@x.com", false, false, true, recent)
		}},
		{"access/leavers-locked-out", tag.NA, "future date ignored", func(g *graph.Graph) {
			leaver(g, "a@x.com", "2027-01-01")
			user(g, "a@x.com", false, false, true, recent)
		}},
		{"access/admins-use-mfa", tag.Pass, "enforced", func(g *graph.Graph) { user(g, "a@x.com", true, false, true, recent) }},
		{"access/admins-use-mfa", tag.Fail, "not enforced", func(g *graph.Graph) { user(g, "a@x.com", true, false, false, recent) }},
		{"access/admins-use-mfa", tag.NA, "no users", func(g *graph.Graph) {}},
		{"access/no-dormant-admins", tag.Pass, "recent", func(g *graph.Graph) { user(g, "a@x.com", true, false, true, recent) }},
		{"access/no-dormant-admins", tag.Fail, "old login", func(g *graph.Graph) { user(g, "a@x.com", true, false, true, "2026-01-01T00:00:00Z") }},
		{"access/no-dormant-admins", tag.Fail, "never logged in, old account", func(g *graph.Graph) { user(g, "a@x.com", true, false, true, "") }},
		{"access/no-dormant-admins", tag.NA, "empty", func(g *graph.Graph) {}},
		{"gcp/no-public-buckets", tag.Pass, "private and enforced", func(g *graph.Graph) {
			gcpProject(g)
			gcpBucket(g, "logs", []any{}, "enforced")
		}},
		{"gcp/no-public-buckets", tag.Fail, "allUsers can read", func(g *graph.Graph) {
			gcpProject(g)
			gcpBucket(g, "site", []any{"allUsers roles/storage.objectViewer"}, "inherited")
		}},
		{"gcp/no-public-buckets", tag.Warn, "private but prevention not enforced", func(g *graph.Graph) {
			gcpProject(g)
			gcpBucket(g, "logs", []any{}, "inherited")
		}},
		{"gcp/no-public-buckets", tag.NA, "no buckets", func(g *graph.Graph) { gcpProject(g) }},
		{"gcp/no-outside-owners", tag.Pass, "owner in own domain", func(g *graph.Graph) {
			gcpProject(g, "acme.com")
			gcpBinding(g, "roles/owner", "user", "acme.com", false)
			gcpBinding(g, "roles/viewer", "user", "gmail.com", false)
		}},
		{"gcp/no-outside-owners", tag.Fail, "gmail editor", func(g *graph.Graph) {
			gcpProject(g, "acme.com")
			gcpBinding(g, "roles/editor", "user", "gmail.com", false)
		}},
		{"gcp/no-outside-owners", tag.Fail, "owner granted to everyone", func(g *graph.Graph) {
			gcpProject(g, "acme.com")
			gcpBinding(g, "roles/owner", "allAuthenticatedUsers", "", false)
		}},
		{"gcp/no-outside-owners", tag.Fail, "deleted outside owner", func(g *graph.Graph) {
			gcpProject(g, "acme.com")
			gcpBinding(g, "roles/owner", "deleted_user", "contractor.io", false)
		}},
		{"gcp/no-outside-owners", tag.NA, "no domains configured", func(g *graph.Graph) {
			gcpProject(g)
			gcpBinding(g, "roles/editor", "user", "gmail.com", false)
		}},
		{"gcp/no-editor-service-accounts", tag.Pass, "only Google's agent has Editor", func(g *graph.Graph) {
			gcpProject(g)
			gcpBinding(g, "roles/editor", "service_account", "cloudservices.gserviceaccount.com", true)
			gcpBinding(g, "roles/storage.admin", "service_account", "acme-prod.iam.gserviceaccount.com", false)
		}},
		{"gcp/no-editor-service-accounts", tag.Fail, "default compute account has Editor", func(g *graph.Graph) {
			gcpProject(g)
			gcpBinding(g, "roles/editor", "service_account", "developer.gserviceaccount.com", false)
		}},
		{"gcp/no-editor-service-accounts", tag.NA, "no bindings", func(g *graph.Graph) { gcpProject(g) }},
		{"gcp/sa-keys-short-lived", tag.Pass, "new and used", func(g *graph.Graph) {
			gcpProject(g)
			gcpKey(g, "k1", "2026-10-01T00:00:00Z", "2026-11-06T00:00:00Z", true)
		}},
		{"gcp/sa-keys-short-lived", tag.Pass, "new, last use unknown", func(g *graph.Graph) {
			gcpProject(g)
			gcpKey(g, "k1", "2026-10-01T00:00:00Z", "", false)
		}},
		{"gcp/sa-keys-short-lived", tag.Fail, "old key", func(g *graph.Graph) {
			gcpProject(g)
			gcpKey(g, "k1", "2025-01-01T00:00:00Z", "2026-11-06T00:00:00Z", true)
		}},
		{"gcp/sa-keys-short-lived", tag.NA, "no keys", func(g *graph.Graph) { gcpProject(g) }},

		{"access/no-shared-prod-keys", tag.Pass, "clean scan", func(g *graph.Graph) { targetRepo(g); scan(g, "secrets", "acme/api", 5) }},
		{"access/no-shared-prod-keys", tag.Fail, "shared", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			secret(g, ".env.production", "prod", "h1", true)
			secret(g, ".env.staging", "staging", "h1", true)
		}},
		{"access/no-shared-prod-keys", tag.NA, "empty scan", func(g *graph.Graph) { targetRepo(g); scan(g, "secrets", "acme/api", 0) }},

		{"agent/no-prod-secrets-in-agent-reach", tag.Pass, "clean scan", func(g *graph.Graph) { targetRepo(g); scan(g, "secrets", "acme/api", 5) }},
		{"agent/no-prod-secrets-in-agent-reach", tag.Pass, "example only", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			secret(g, "fixtures/k", "example", "h", true)
		}},
		{"agent/no-prod-secrets-in-agent-reach", tag.Fail, "unknown env", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			secret(g, "scripts/x.sh", "unknown", "h", true)
		}},
		{"agent/no-prod-secrets-in-agent-reach", tag.Pass, "denied to agents", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			secret(g, "scripts/x.sh", "prod", "h", false)
		}},
		{"agent/no-prod-secrets-in-agent-reach", tag.NA, "empty", func(g *graph.Graph) { targetRepo(g) }},
		{"agent/no-destructive-tokens", tag.Pass, "limited", func(g *graph.Graph) { awsKey(g, false) }},
		{"agent/no-destructive-tokens", tag.Fail, "admin", func(g *graph.Graph) { awsKey(g, true) }},
		{"agent/no-destructive-tokens", tag.NA, "no keys", func(g *graph.Graph) {}},
		{"agent/destructive-commands-gated", tag.Pass, "guarded", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			agentConfig(g, []any{})
		}},
		{"agent/destructive-commands-gated", tag.Fail, "allowed", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			agentConfig(g, []any{"Bash(rm -rf *)"})
		}},
		{"agent/destructive-commands-gated", tag.NA, "no configs", func(g *graph.Graph) { targetRepo(g); scan(g, "agent_configs", "acme/api", 0) }},
		{"agent/no-shared-agent-keys", tag.Pass, "own keys", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			agentConfig(g, []any{}, "secret:a", "secret:b")
		}},
		{"agent/no-shared-agent-keys", tag.Fail, "shared", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			agentConfig(g, []any{}, "secret:a", "secret:a")
		}},
		{"agent/no-shared-agent-keys", tag.NA, "no configs", func(g *graph.Graph) { targetRepo(g) }},

		{"doors/no-public-source-maps", tag.Pass, "clean", func(g *graph.Graph) { domain(g); scan(g, "web_source_maps", "acme.com", 3) }},
		{"doors/no-public-source-maps", tag.Fail, "public", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_source_maps", "acme.com", 3)
			node(g, "m", graph.KindSourceMap, map[string]any{"domain": "acme.com", "host": "a", "bundle": "b", "map_url": "c"})
		}},
		{"doors/no-public-source-maps", tag.NA, "nothing checked", func(g *graph.Graph) { domain(g) }},
		{"doors/no-public-api-docs", tag.Pass, "clean", func(g *graph.Graph) { domain(g); scan(g, "web_api_docs", "acme.com", 3) }},
		{"doors/no-public-api-docs", tag.Fail, "public", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_api_docs", "acme.com", 3)
			node(g, "d", graph.KindAPIDoc, map[string]any{"domain": "acme.com", "host": "a", "path": "/swagger.json", "status": int64(200)})
		}},
		{"doors/no-public-api-docs", tag.NA, "nothing", func(g *graph.Graph) { domain(g) }},
		{"doors/no-dangling-dns", tag.Pass, "resolves", func(g *graph.Graph) {
			domain(g)
			scan(g, "dns", "acme.com", 1)
			node(g, "c", graph.KindCNAME, map[string]any{"domain": "acme.com", "host": "a", "target": "t", "target_resolves": true})
		}},
		{"doors/no-dangling-dns", tag.Fail, "dangling", func(g *graph.Graph) {
			domain(g)
			scan(g, "dns", "acme.com", 1)
			node(g, "c", graph.KindCNAME, map[string]any{"domain": "acme.com", "host": "a", "target": "t", "target_resolves": false})
		}},
		{"doors/no-dangling-dns", tag.NA, "nothing", func(g *graph.Graph) { domain(g) }},
		{"doors/every-host-owned", tag.Pass, "owned", func(g *graph.Graph) {
			domain(g)
			scan(g, "ctlog", "acme.com", 1)
			node(g, "host:a", graph.KindHost, map[string]any{"domain": "acme.com", "host": "a.acme.com"})
			node(g, "ch", graph.KindConfigHost, map[string]any{"host": "a.acme.com", "owner": "@r"})
		}},
		{"doors/every-host-owned", tag.Fail, "unowned", func(g *graph.Graph) {
			domain(g)
			scan(g, "ctlog", "acme.com", 1)
			node(g, "host:a", graph.KindHost, map[string]any{"domain": "acme.com", "host": "a.acme.com"})
		}},
		{"doors/every-host-owned", tag.NA, "no certs", func(g *graph.Graph) { domain(g) }},
		{"doors/no-public-buckets-in-terraform", tag.Pass, "private", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "terraform", "acme/api", 1)
			node(g, "b", graph.KindTFBucket, map[string]any{"repo": "acme/api", "name": "x", "file": "m.tf", "public_acl": false, "public_policy": false, "public_access_block": true})
		}},
		{"doors/no-public-buckets-in-terraform", tag.Fail, "public", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "terraform", "acme/api", 1)
			node(g, "b", graph.KindTFBucket, map[string]any{"repo": "acme/api", "name": "x", "file": "m.tf", "public_acl": true, "public_policy": false, "public_access_block": false})
		}},
		{"doors/no-public-buckets-in-terraform", tag.NA, "no terraform", func(g *graph.Graph) { targetRepo(g) }},
		{"code/rules-clean", tag.Pass, "clean", func(g *graph.Graph) { scan(g, "semgrep", "", 1) }},
		{"code/rules-clean", tag.Fail, "error", func(g *graph.Graph) {
			scan(g, "semgrep", "", 1)
			node(g, "f", graph.KindSemgrep, map[string]any{"rule": "r", "severity": "ERROR", "file": "a.go", "line": int64(1)})
		}},
		{"code/rules-clean", tag.NA, "not read", func(g *graph.Graph) {}},
	}
	covered := map[string]map[string]bool{}
	all := map[string]bool{"github": true, "google": true, "aws": true, "hr": true, "semgrep": true, "dns": true, "ctlog": true, "web": true, "gcp": true}
	for _, c := range cases {
		t.Run(c.id+"/"+c.name, func(t *testing.T) {
			g := graph.New()
			c.setup(g)
			got := Decide(loadDrill(t, c.id), g, Options{Now: testNow, Available: all})
			if len(got) != 1 || got[0].Verdict != c.verdictWant {
				t.Fatalf("got %s (%s), want %s", got[0].Verdict, got[0].Reason, c.verdictWant)
			}
		})
		if covered[c.id] == nil {
			covered[c.id] = map[string]bool{}
		}
		covered[c.id][c.verdictWant] = true
	}
	if len(covered) != 24 {
		t.Errorf("covered %d drills, want 24", len(covered))
	}
	for id, v := range covered {
		if !v[tag.Pass] || !v[tag.Fail] || !v[tag.NA] {
			t.Errorf("%s lacks a passing, failing or N/A case: %v", id, v)
		}
	}
}

func TestSkipWhenConnectorMissing(t *testing.T) {
	got := Decide(loadDrill(t, "access/admins-use-mfa"), graph.New(), Options{Now: testNow, Available: map[string]bool{}})
	if got[0].Verdict != tag.Skip {
		t.Fatalf("got %s", got[0].Verdict)
	}
}

func TestMissingFieldIsError(t *testing.T) {
	g := graph.New()
	ghRepo(g, "team", true)
	node(g, "github:branch-rule/acme/api/default", graph.KindBranchRule, map[string]any{"bypass": "none"})
	got := Decide(loadDrill(t, "change/human-review-required"), g, Options{Now: testNow, Available: map[string]bool{"github": true}})
	if got[0].Verdict != tag.Error {
		t.Fatalf("got %s", got[0].Verdict)
	}
}

func TestFindingWaiver(t *testing.T) {
	d := loadDrill(t, "agent/no-prod-secrets-in-agent-reach")
	waive := func(file, hash string) config.Waiver {
		w := config.Waiver{Drill: d.ID, Target: "acme/api", Reason: "r", ApprovedBy: "@a", Expires: "2027-01-31"}
		w.Finding = &struct {
			File string `yaml:"file"`
			Hash string `yaml:"hash"`
		}{file, hash}
		return w
	}
	one := func() *graph.Graph {
		g := graph.New()
		targetRepo(g)
		scan(g, "secrets", "acme/api", 3)
		secret(g, "demo.sh", "unknown", "fake", true)
		return g
	}
	got := Decide(d, one(), Options{Now: testNow, Waivers: []config.Waiver{waive("demo.sh", "secret:fake")}})
	if got[0].Verdict != tag.Fail || !got[0].Waived {
		t.Fatalf("a covered FAIL prints as FAIL and is waived, got %s waived=%v", got[0].Verdict, got[0].Waived)
	}
	g := one()
	secret(g, "real.sh", "prod", "real", true)
	got = Decide(d, g, Options{Now: testNow, Waivers: []config.Waiver{waive("demo.sh", "secret:fake")}})
	if got[0].Waived {
		t.Fatal("a real leak beside a waived finding must stay unwaived")
	}
	got = Decide(d, one(), Options{Now: testNow.AddDate(1, 0, 0), Waivers: []config.Waiver{waive("demo.sh", "secret:fake")}})
	if got[0].Waived {
		t.Fatal("an expired waiver must not apply")
	}
}

func TestStateRule(t *testing.T) {
	d := &drill.Drill{ID: "x/y", Severity: "high"}
	step := func(prev *tag.Tag, verdict string) *Outcome {
		o := &Outcome{Drill: d, Verdict: verdict}
		ApplyState(o, prev, nil)
		return o
	}
	first := step(nil, tag.Fail)
	if first.State != tag.Open || !first.NewlyOpen {
		t.Fatalf("first FAIL: %+v", first)
	}
	if ExitCode([]*Outcome{first}, "") != 1 {
		t.Fatal("newly open high safeguard exits 1")
	}
	open := &tag.Tag{Header: tag.Header{State: tag.Open, Time: testNow}}
	for _, v := range []string{tag.Warn, tag.NA, tag.Skip, tag.Error} {
		o := step(open, v)
		if o.State != tag.Open || o.NewlyOpen || o.Unverified != "open, unverified this run" {
			t.Errorf("FAIL then %s must stay OPEN and flagged: %+v", v, o)
		}
	}
	again := step(open, tag.Fail)
	if again.NewlyOpen {
		t.Fatal("a FAIL after an ERROR on an OPEN safeguard is not new")
	}
	if ExitCode([]*Outcome{again}, "") != 0 || ExitCode([]*Outcome{again}, "open") != 1 {
		t.Fatal("exit rules for a known open safeguard")
	}
	closed := step(open, tag.Pass)
	if closed.State != tag.Closed || !closed.NewlyClosed {
		t.Fatalf("PASS closes: %+v", closed)
	}
	c := &tag.Tag{Header: tag.Header{State: tag.Closed, Time: testNow}}
	if u := step(c, tag.NA); u.State != tag.Closed || !strings.HasPrefix(u.Unverified, "closed, unverified since") {
		t.Fatalf("closed unverified: %+v", u)
	}
	if u := step(nil, tag.NA); u.State != tag.Unknown {
		t.Fatalf("no decisive verdict is UNKNOWN: %+v", u)
	}
	expired := &tag.Tag{Header: tag.Header{State: tag.Open, Waived: true, Time: testNow}}
	if o := step(expired, tag.Fail); !o.NewlyOpen {
		t.Fatal("waiver expiry on an open safeguard counts as newly open")
	}
	o := &Outcome{Drill: d, Verdict: tag.Fail}
	ApplyState(o, open, &config.Retired{Target: "x", Reason: "gone"})
	if o.State != tag.Retired {
		t.Fatal("retired target")
	}
	if ExitCode([]*Outcome{{Drill: d, Verdict: tag.Error}, first}, "") != 2 {
		t.Fatal("2 wins over 1")
	}
	low := &Outcome{Drill: &drill.Drill{ID: "l/l", Severity: "low"}, Verdict: tag.Fail}
	ApplyState(low, nil, nil)
	if ExitCode([]*Outcome{low}, "") != 0 || ExitCode([]*Outcome{low}, "any") != 1 {
		t.Fatal("low severity exit rules")
	}
}

func TestEvidenceIsTrimmed(t *testing.T) {
	g := graph.New()
	ghRepo(g, "team", true)
	branchRule(g, 0, "none", false)
	got := Decide(loadDrill(t, "change/no-force-push-main"), g, Options{Now: testNow, Available: map[string]bool{"github": true}})
	rules := got[0].Facts["rules"].(map[string]any)
	if _, leaked := rules["required_approvals"]; leaked {
		t.Fatal("evidence must keep only the fields conditions used")
	}
	if _, ok := rules["force_push_allowed"]; !ok {
		t.Fatal("evidence lost a used field")
	}
}

func TestFailReasonNamesTheRealFinding(t *testing.T) {
	g := graph.New()
	targetRepo(g)
	scan(g, "secrets", "acme/api", 3)
	secret(g, "a-fixture.env", "example", "fake", true)
	secret(g, "z-real.sh", "prod", "real", true)
	got := Decide(loadDrill(t, "agent/no-prod-secrets-in-agent-reach"), g, Options{Now: testNow})
	if !strings.Contains(got[0].Reason, "z-real.sh") || !strings.Contains(got[0].Reason, "1 failing") {
		t.Fatalf("reason must name the real leak, got %q", got[0].Reason)
	}
}

func TestTargetIsCountedAsRead(t *testing.T) {
	g := graph.New()
	targetRepo(g)
	scan(g, "secrets", "acme/api", 1)
	got := Decide(loadDrill(t, "access/no-shared-prod-keys"), g, Options{Now: testNow})
	found := false
	for _, id := range got[0].Read {
		if id == "repo:acme/api" {
			found = true
		}
	}
	if !found {
		t.Fatalf("read: %v", got[0].Read)
	}
}
