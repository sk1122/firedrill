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
		srv := stdioServer(string(rune('a'+i)), "acme-mcp", "", "", true, true)
		srv["credentials"] = []any{c}
		servers = append(servers, srv)
	}
	node(g, "agent:claude/acme/api", graph.KindAgentConfig, map[string]any{"repo": "acme/api", "tool": "claude-code", "scope": "repo",
		"file": ".mcp.json", "allowed_commands": []any{}, "denied_commands": []any{}, "deny_read_paths": []any{},
		"unguarded_destructive": unguarded, "mcp_servers": servers, "egress": "open", "egress_hosts": []any{}, "egress_unbounded": false})
}

// stdioServer is an MCP server row for a local command, with every field.
func stdioServer(name, command, pkg, version string, pinned, known bool) map[string]any {
	return map[string]any{"name": name, "credentials": []any{}, "transport": "stdio", "host": "", "host_known": false,
		"command": command, "package": pkg, "version": version, "pinned": pinned, "package_known": known}
}

// httpServer is an MCP server row for a remote URL, with every field.
func httpServer(name, host string, known bool) map[string]any {
	return map[string]any{"name": name, "credentials": []any{}, "transport": "http", "host": host, "host_known": known,
		"command": "", "package": "", "version": "", "pinned": true, "package_known": true}
}

// mcpConfig is a .mcp.json holding the given servers.
func mcpConfig(g *graph.Graph, servers ...map[string]any) {
	list := []any{}
	for _, s := range servers {
		list = append(list, s)
	}
	node(g, "agent:acme/api/.mcp.json", graph.KindAgentConfig, map[string]any{"repo": "acme/api", "tool": "claude-code", "scope": "repo",
		"file": ".mcp.json", "allowed_commands": []any{}, "denied_commands": []any{}, "deny_read_paths": []any{},
		"unguarded_destructive": []any{}, "mcp_servers": list, "gitignored": false, "local_override": false,
		"egress": "open", "egress_hosts": []any{}, "egress_unbounded": false})
}

func workflow(g *graph.Graph, perms string, triggers, secrets []any) {
	node(g, "github:workflow/acme/api/.github/workflows/a.yml", graph.KindWorkflow, map[string]any{"repo": "acme/api",
		"file": ".github/workflows/a.yml", "permissions": perms, "unpinned_actions": []any{}, "pull_request_target_checkout": false,
		"triggers": triggers, "secrets": secrets, "unfrozen_installs": []any{}, "cloud_key_secrets": []any{}, "uses_oidc": false})
}

// ciWorkflow is a push workflow with the install and cloud fields set.
func ciWorkflow(g *graph.Graph, file string, secrets, unfrozen, cloudKeys []any, oidc bool) {
	node(g, "github:workflow/acme/api/"+file, graph.KindWorkflow, map[string]any{"repo": "acme/api",
		"file": file, "permissions": "read", "unpinned_actions": []any{}, "pull_request_target_checkout": false,
		"triggers": []any{"push"}, "secrets": secrets, "unfrozen_installs": unfrozen, "cloud_key_secrets": cloudKeys, "uses_oidc": oidc})
}

// manifest is one package.json and its lockfile.
func manifest(g *graph.Graph, file, lockfile string, committed bool, scripts, newScripts []any) {
	manager := "unknown"
	if lockfile != "" {
		manager = "npm"
	}
	node(g, "manifest:acme/api/"+file, graph.KindManifest, map[string]any{"repo": "acme/api", "file": file, "manager": manager,
		"lockfile": lockfile, "lockfile_committed": committed, "install_scripts": scripts, "install_scripts_known": true,
		"new_install_scripts": newScripts})
}

// agentSecret is a secret seen in a file, with the agent config fields.
func agentSecret(g *graph.Graph, file string, inAgentConfig, gitignored bool) {
	node(g, "secret:h@"+file, graph.KindSecretSeen, map[string]any{
		"repo": "acme/api", "kind": "generic", "file": file, "line": int64(1), "env_class": "unknown",
		"hash": "h", "agent_readable": true, "key_id": "", "in_agent_config": inAgentConfig, "gitignored": gitignored})
}

// agentFile is one parsed agent config file.
func agentFile(g *graph.Graph, file string, local, gitignored bool) {
	tool := "claude-code"
	if strings.HasPrefix(file, ".gemini/") {
		tool = "gemini"
	}
	node(g, "agent:acme/api/"+file, graph.KindAgentConfig, map[string]any{"repo": "acme/api", "tool": tool, "scope": "repo",
		"file": file, "allowed_commands": []any{}, "denied_commands": []any{}, "deny_read_paths": []any{},
		"unguarded_destructive": []any{}, "mcp_servers": []any{}, "gitignored": gitignored, "local_override": local,
		"egress": "open", "egress_hosts": []any{}, "egress_unbounded": false})
}

func user(g *graph.Graph, email string, admin, suspended, enforced bool, login string) {
	g.Node(graph.Node{ID: graph.ID("google:user/" + email), Kind: graph.KindIdentityUser, SeenAt: testNow,
		Attrs: map[string]any{"suspended": suspended, "is_admin": admin, "is_delegated_admin": false, "mfa_enrolled": enforced,
			"mfa_enforced": enforced, "last_login": login, "created": "2020-01-01T00:00:00Z"},
		Private: map[string]any{"email": email}})
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

// settings is the config node holding thresholds, with how many names are
// listed under production.
func settings(g *graph.Graph, production int64) {
	node(g, "config:settings", graph.KindConfigSettings, map[string]any{
		"review_days": int64(180), "min_retention_days": int64(7), "restore_days": int64(90), "production_markers": production})
}

// oauthApp is a third-party app users granted access, high risk when it holds
// full Drive and Gmail scopes.
func oauthApp(g *graph.Graph, id, name string, highRisk bool) {
	scopes, sensitive := []any{"https://www.googleapis.com/auth/drive.file", "openid"}, []any{}
	if highRisk {
		scopes = []any{"https://mail.google.com/", "https://www.googleapis.com/auth/drive", "openid"}
		sensitive = []any{"https://mail.google.com/", "https://www.googleapis.com/auth/drive"}
	}
	node(g, "google:oauth-app/"+id, graph.KindOAuthApp, map[string]any{"client_id": id, "name": name, "scopes": scopes,
		"sensitive_scopes": sensitive, "high_risk": highRisk, "user_count": int64(3), "native": false, "anonymous": false})
}

func appRegister(g *graph.Graph, id, owner, reviewed string) {
	node(g, "config-app:"+id, graph.KindConfigApp, map[string]any{"client_id": id, "name": "", "owner": owner, "reviewed": reviewed, "note": ""})
}

// database is one database as the aws or gcp connector writes it.
func database(g *graph.Graph, system, name string, production bool, retention int64, copy, detail string) {
	account, project, region := "111122223333", "", "us-east-1"
	if system == "gcp" {
		account, project, region = "", "acme-prod", "europe-west1"
	}
	node(g, system+":db/"+account+project+"/"+name, graph.KindDatabase, map[string]any{"system": system, "account": account,
		"project": project, "profile": "acme-prod", "region": region, "name": name, "engine": "postgres", "db_kind": "instance",
		"production": production, "production_marked": production, "automated_backups": retention > 0, "retention_days": retention,
		"deletion_protection": true, "separate_copy": copy, "copy_detail": detail})
}

// aiKey is one provider API key as the anthropic or openai connector writes it.
func aiKey(g *graph.Graph, provider, id, status string, owned, readable, capped bool) {
	owner, kind, scope := "", "unknown", "unknown"
	if owned {
		owner, kind = "person:"+strings.Repeat("a", 32), "user"
	}
	switch {
	case capped:
		scope = "project"
	case readable:
		scope = "none"
	}
	ws, wsName, proj, projName := "", "", "", ""
	if provider == "anthropic" {
		ws, wsName = "wrkspc_01AcmeProd", "acme-prod"
	} else {
		proj, projName = "proj_acmeprod", "acme-prod"
	}
	node(g, provider+":key/"+id, graph.KindAIKey, map[string]any{"provider": provider, "key_id": id, "hint": "sk-...abcd",
		"name": "agent", "status": status, "workspace": ws, "workspace_name": wsName, "project": proj, "project_name": projName,
		"owner_kind": kind, "has_owner": owned, "owner": owner, "limit_readable": readable, "capped": capped, "limit_scope": scope,
		"created": "2026-10-01T00:00:00Z"})
}

type drillCase struct {
	id, verdictWant string
	name            string
	setup           func(g *graph.Graph)
}

var allConnectors = map[string]bool{"github": true, "google": true, "aws": true, "hr": true, "semgrep": true, "dns": true, "ctlog": true,
	"web": true, "gcp": true, "anthropic": true, "openai": true}

// drillCases are a passing, a failing and a not-applicable setup for every
// starter drill. They also generate the drills' fixture files.
func drillCases() []drillCase {
	return append(append(baseCases(), tier2Cases()...), tier3Cases()...)
}

func baseCases() []drillCase {
	recent := "2026-11-01T00:00:00Z"
	return []drillCase{
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
		{"change/no-pr-target-with-secrets", tag.Pass, "pull_request with secrets", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			workflow(g, "write", []any{"pull_request", "push"}, []any{"NPM_TOKEN"})
		}},
		{"change/no-pr-target-with-secrets", tag.Pass, "read-only pull_request_target", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			workflow(g, "read", []any{"pull_request_target"}, []any{})
		}},
		{"change/no-pr-target-with-secrets", tag.Fail, "agent on pull_request_target", func(g *graph.Graph) {
			// The PR-title attack: an agent run on pull_request_target with an API
			// key and the default token.
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			workflow(g, "undeclared", []any{"issue_comment", "pull_request_target"}, []any{"ANTHROPIC_API_KEY"})
		}},
		{"change/no-pr-target-with-secrets", tag.Fail, "write token", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			workflow(g, "write", []any{"pull_request_target"}, []any{})
		}},
		{"change/no-pr-target-with-secrets", tag.Fail, "read-only with a secret", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			workflow(g, "read", []any{"pull_request_target"}, []any{"ANTHROPIC_API_KEY"})
		}},
		{"change/no-pr-target-with-secrets", tag.Fail, "inherits secrets", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			workflow(g, "read", []any{"pull_request_target"}, []any{"inherit"})
		}},
		{"change/no-pr-target-with-secrets", tag.NA, "no workflows", func(g *graph.Graph) { targetRepo(g); scan(g, "workflows", "acme/api", 0) }},

		{"change/ci-uses-oidc-not-keys", tag.Pass, "OIDC role", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			ciWorkflow(g, ".github/workflows/deploy.yml", []any{}, []any{}, []any{}, true)
		}},
		{"change/ci-uses-oidc-not-keys", tag.Pass, "no cloud access", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			ciWorkflow(g, ".github/workflows/ci.yml", []any{"NPM_TOKEN"}, []any{}, []any{}, false)
		}},
		{"change/ci-uses-oidc-not-keys", tag.Fail, "static AWS keys", func(g *graph.Graph) {
			// The supply-chain harvest: a long-lived AWS key stored as a secret,
			// read by any workflow step a poisoned dependency runs in.
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			keys := []any{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
			ciWorkflow(g, ".github/workflows/deploy.yml", keys, []any{}, keys, false)
		}},
		{"change/ci-uses-oidc-not-keys", tag.Fail, "GCP credentials_json", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "workflows", "acme/api", 1)
			ciWorkflow(g, ".github/workflows/deploy.yml", []any{"GCP_DEPLOY"}, []any{}, []any{"GCP_DEPLOY"}, false)
		}},
		{"change/ci-uses-oidc-not-keys", tag.NA, "no workflows", func(g *graph.Graph) { targetRepo(g); scan(g, "workflows", "acme/api", 0) }},
		{"supply/installs-from-lockfile", tag.Pass, "committed lockfile, frozen install", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "manifests", "acme/api", 1)
			scan(g, "workflows", "acme/api", 1)
			manifest(g, "package.json", "package-lock.json", true, []any{"esbuild"}, []any{})
			ciWorkflow(g, ".github/workflows/ci.yml", []any{}, []any{}, []any{}, false)
		}},
		{"supply/installs-from-lockfile", tag.Fail, "no lockfile", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "manifests", "acme/api", 1)
			manifest(g, "package.json", "", false, []any{}, []any{})
		}},
		{"supply/installs-from-lockfile", tag.Fail, "lockfile gitignored", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "manifests", "acme/api", 1)
			manifest(g, "package.json", "package-lock.json", false, []any{}, []any{})
		}},
		{"supply/installs-from-lockfile", tag.Fail, "npm install in CI", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "manifests", "acme/api", 1)
			scan(g, "workflows", "acme/api", 1)
			manifest(g, "package.json", "package-lock.json", true, []any{}, []any{})
			ciWorkflow(g, ".github/workflows/ci.yml", []any{}, []any{"npm install"}, []any{}, false)
		}},
		{"supply/installs-from-lockfile", tag.Fail, "dependency gained an install script", func(g *graph.Graph) {
			// Shai-Hulud: a trusted dependency's new release adds a postinstall
			// script that runs on every install.
			targetRepo(g)
			scan(g, "manifests", "acme/api", 1)
			manifest(g, "package.json", "package-lock.json", true, []any{"acme-colors", "esbuild"}, []any{"acme-colors"})
		}},
		{"supply/installs-from-lockfile", tag.NA, "no package.json", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "manifests", "acme/api", 0)
			scan(g, "workflows", "acme/api", 1)
			ciWorkflow(g, ".github/workflows/ci.yml", []any{}, []any{}, []any{}, false)
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
		{"agent/no-secrets-in-agent-config", tag.Pass, "no agent secrets", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			scan(g, "agent_configs", "acme/api", 1)
			agentSecret(g, "scripts/x.sh", false, false)
			agentFile(g, ".claude/settings.json", false, false)
		}},
		{"agent/no-secrets-in-agent-config", tag.Pass, "gitignored local settings", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			scan(g, "agent_configs", "acme/api", 1)
			agentFile(g, ".claude/settings.local.json", true, true)
		}},
		{"agent/no-secrets-in-agent-config", tag.Pass, "no agent config", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			scan(g, "agent_configs", "acme/api", 0)
		}},
		{"agent/no-secrets-in-agent-config", tag.Fail, "committed local settings with a secret", func(g *graph.Graph) {
			// The Claude Code leak: an allow-list holding a token, committed.
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			scan(g, "agent_configs", "acme/api", 1)
			agentSecret(g, ".claude/settings.local.json", true, false)
			agentFile(g, ".claude/settings.local.json", true, false)
		}},
		{"agent/no-secrets-in-agent-config", tag.Fail, "committed local settings", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			scan(g, "agent_configs", "acme/api", 1)
			agentFile(g, ".claude/settings.local.json", true, false)
		}},
		{"agent/no-secrets-in-agent-config", tag.Fail, "secret in gemini settings", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			scan(g, "agent_configs", "acme/api", 1)
			agentSecret(g, ".gemini/settings.json", true, false)
			agentFile(g, ".gemini/settings.json", false, false)
		}},
		{"agent/no-secrets-in-agent-config", tag.Fail, "secret in gitignored local settings", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "secrets", "acme/api", 5)
			scan(g, "agent_configs", "acme/api", 1)
			agentSecret(g, ".claude/settings.local.json", true, true)
			agentFile(g, ".claude/settings.local.json", true, true)
		}},
		{"agent/no-secrets-in-agent-config", tag.NA, "nothing inspected", func(g *graph.Graph) { targetRepo(g) }},
		{"agent/mcp-servers-known", tag.Pass, "owned host, pinned allowlisted package, local script", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			mcpConfig(g, httpServer("docs", "mcp.acme.com", true),
				stdioServer("fs", "npx", "@acme/mcp-fs", "1.4.2", true, true),
				stdioServer("tools", "scripts/mcp.sh", "", "", true, true))
		}},
		{"agent/mcp-servers-known", tag.Fail, "unknown remote host", func(g *graph.Graph) {
			// The MCP incident: a config pointing an agent at a server on a host
			// nobody owns or reviewed.
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			mcpConfig(g, httpServer("helper", "mcp.unknown-tools.example", false))
		}},
		{"agent/mcp-servers-known", tag.Fail, "unpinned npx package", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			mcpConfig(g, stdioServer("helper", "npx", "some-mcp", "", false, false))
		}},
		{"agent/mcp-servers-known", tag.Fail, "latest tag", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			mcpConfig(g, stdioServer("helper", "npx", "@acme/mcp-fs", "", false, true))
		}},
		{"agent/mcp-servers-known", tag.Warn, "pinned but unknown package", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			mcpConfig(g, stdioServer("helper", "uvx", "acme-mcp-search", "0.3.1", true, false))
		}},
		{"agent/mcp-servers-known", tag.NA, "no agent config", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 0)
		}},

		{"access/third-party-apps-reviewed", tag.Pass, "reviewed, with an owner", func(g *graph.Graph) {
			settings(g, 0)
			scan(g, "oauth_tokens", "", 40)
			oauthApp(g, "1234-notes.apps.googleusercontent.com", "Acme Notes AI", true)
			appRegister(g, "1234-notes.apps.googleusercontent.com", "@it", "2026-09-01")
		}},
		{"access/third-party-apps-reviewed", tag.Pass, "only low-risk scopes", func(g *graph.Graph) {
			settings(g, 0)
			scan(g, "oauth_tokens", "", 40)
			oauthApp(g, "5678-sched.apps.googleusercontent.com", "Acme Scheduler", false)
		}},
		{"access/third-party-apps-reviewed", tag.Fail, "full Drive and Gmail access, no owner", func(g *graph.Graph) {
			// The incident: an employee granted an outside app full access to
			// their mail and Drive, and nobody ever reviewed the grant.
			settings(g, 0)
			scan(g, "oauth_tokens", "", 40)
			oauthApp(g, "1234-notes.apps.googleusercontent.com", "Acme Notes AI", true)
		}},
		{"access/third-party-apps-reviewed", tag.Fail, "review lapsed", func(g *graph.Graph) {
			settings(g, 0)
			scan(g, "oauth_tokens", "", 40)
			oauthApp(g, "1234-notes.apps.googleusercontent.com", "Acme Notes AI", true)
			appRegister(g, "1234-notes.apps.googleusercontent.com", "@it", "2025-01-15")
		}},
		{"access/third-party-apps-reviewed", tag.Warn, "some users' grants unreadable", func(g *graph.Graph) {
			settings(g, 0)
			graph.WriteScan(g, "fixture", "oauth_tokens", "", 39, "the OAuth grants of 1 of 40 users could not be read", testNow)
			oauthApp(g, "5678-sched.apps.googleusercontent.com", "Acme Scheduler", false)
		}},
		{"access/third-party-apps-reviewed", tag.NA, "no app granted", func(g *graph.Graph) {
			settings(g, 0)
			scan(g, "oauth_tokens", "", 40)
		}},

		{"recovery/backups-separate-and-retained", tag.Pass, "retained and copied to another account", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "aws_backups", "acme-prod", 1)
			database(g, "aws", "orders", true, 14, "yes", "cross-account vault 444455556666")
		}},
		{"recovery/backups-separate-and-retained", tag.Fail, "no automated backups", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "aws_backups", "acme-prod", 1)
			database(g, "aws", "orders", true, 0, "yes", "cross-account vault 444455556666")
		}},
		{"recovery/backups-separate-and-retained", tag.Fail, "retention too short", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "aws_backups", "acme-prod", 1)
			database(g, "aws", "orders", true, 3, "yes", "cross-account vault 444455556666")
		}},
		{"recovery/backups-separate-and-retained", tag.Fail, "backups only in the same account", func(g *graph.Graph) {
			// The incident: a destructive token deleted the production database
			// and its backups together, since both lived in the same place.
			settings(g, 1)
			scan(g, "aws_backups", "acme-prod", 1)
			database(g, "aws", "orders", true, 14, "no", "")
		}},
		{"recovery/backups-separate-and-retained", tag.Warn, "separate copy unknown", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			database(g, "gcp", "ledger", true, 14, "unknown", "backups kept after the instance is deleted, in the same project")
		}},
		{"recovery/backups-separate-and-retained", tag.Pass, "declared copy", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			database(g, "gcp", "ledger", true, 14, "unknown", "")
			node(g, "config-backup:ledger", graph.KindConfigBackup, map[string]any{"database": "ledger",
				"copy_location": "nightly export to gs://acme-backup-vault in acme-backup", "owner": "@platform", "verified": "2026-11-01"})
		}},
		{"recovery/backups-separate-and-retained", tag.NA, "no production database", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "aws_backups", "acme-prod", 1)
			database(g, "aws", "scratch", false, 0, "no", "")
		}},

		{"keys/ai-keys-capped", tag.Pass, "owned and capped", func(g *graph.Graph) {
			scan(g, "ai_keys", "openai", 1)
			aiKey(g, "openai", "key_acmeci", "active", true, true, true)
		}},
		{"keys/ai-keys-capped", tag.Fail, "active key with no owner and no cap", func(g *graph.Graph) {
			// The incident: an unattended agent loop ran overnight on a key with
			// no spend cap and nobody answering for it.
			scan(g, "ai_keys", "openai", 1)
			aiKey(g, "openai", "key_acmeloop", "active", false, true, false)
		}},
		{"keys/ai-keys-capped", tag.Fail, "owner but no cap", func(g *graph.Graph) {
			scan(g, "ai_keys", "openai", 1)
			aiKey(g, "openai", "key_acmeci", "active", true, true, false)
		}},
		{"keys/ai-keys-capped", tag.Warn, "limit not readable and not declared", func(g *graph.Graph) {
			scan(g, "ai_keys", "anthropic", 1)
			aiKey(g, "anthropic", "apikey_01AcmeCI", "active", true, false, false)
		}},
		{"keys/ai-keys-capped", tag.Pass, "cap declared for the workspace", func(g *graph.Graph) {
			scan(g, "ai_keys", "anthropic", 1)
			aiKey(g, "anthropic", "apikey_01AcmeCI", "active", true, false, false)
			node(g, "config-ai-key:anthropic/workspace/acme-prod", graph.KindConfigAIKey, map[string]any{"provider": "anthropic",
				"key_id": "", "workspace": "acme-prod", "project": "", "owner": "@ml", "monthly_limit_usd": 500.0, "verified": "2026-11-01"})
		}},
		{"keys/ai-keys-capped", tag.NA, "no active key", func(g *graph.Graph) {
			scan(g, "ai_keys", "anthropic", 1)
			aiKey(g, "anthropic", "apikey_01AcmeOld", "archived", false, false, false)
		}},

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
}

func TestEveryDrillGoesGreenRedAndNA(t *testing.T) {
	covered := map[string]map[string]bool{}
	all := allConnectors
	for _, c := range drillCases() {
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
	if len(covered) != 38 {
		t.Errorf("covered %d drills, want 38", len(covered))
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

func TestFailReasonNamesPlainListItems(t *testing.T) {
	all := map[string]bool{"gcp": true}
	cases := []struct {
		id, want string
		setup    func(g *graph.Graph)
	}{
		{"gcp/sa-keys-short-lived", "1 failing, first: key 0f3a9c1d2e4b of ci@acme-prod.iam.gserviceaccount.com, 455 days old", func(g *graph.Graph) {
			gcpProject(g)
			gcpKey(g, "fresh", "2026-10-01T00:00:00Z", "", false)
			gcpKey(g, "0f3a9c1d2e4b5a6c7d8e", "2025-08-09T00:00:00Z", "", false)
		}},
		{"gcp/no-outside-owners", "1 failing, first: a user in gmail.com has roles/editor", func(g *graph.Graph) {
			gcpProject(g, "acme.com")
			gcpBinding(g, "roles/owner", "user", "acme.com", false)
			gcpBinding(g, "roles/editor", "user", "gmail.com", false)
		}},
		{"gcp/no-public-buckets", "1 failing, first: bucket site", func(g *graph.Graph) {
			gcpProject(g)
			gcpBucket(g, "logs", []any{}, "enforced")
			gcpBucket(g, "site", []any{"allUsers roles/storage.objectViewer"}, "enforced")
		}},
	}
	for _, c := range cases {
		g := graph.New()
		c.setup(g)
		got := Decide(loadDrill(t, c.id), g, Options{Now: testNow, Available: all})
		if len(got) != 1 || got[0].Verdict != tag.Fail || got[0].Reason != c.want {
			t.Errorf("%s: got %s %q, want %q", c.id, got[0].Verdict, got[0].Reason, c.want)
		}
	}
}

func TestGCPPartialAndUnreadableProjects(t *testing.T) {
	all := map[string]bool{"gcp": true}
	g := graph.New()
	gcpProject(g)
	gcpBucket(g, "logs", []any{}, "enforced")
	node(g, "gcp:bucket/hidden", graph.KindGCPBucket, map[string]any{"project": "acme-prod", "name": "hidden",
		"public_grants": []any{}, "public_access_prevention": "enforced", "uniform_access": true, "policy_readable": false})
	if got := Decide(loadDrill(t, "gcp/no-public-buckets"), g, Options{Now: testNow, Available: all}); got[0].Verdict != tag.Warn {
		t.Fatalf("an unreadable bucket gives WARN, got %s %s", got[0].Verdict, got[0].Reason)
	}
	g = graph.New()
	node(g, "gcp:project/acme-prod", graph.KindGCPProject, map[string]any{"name": "acme-prod", "number": "", "member_domains": []any{}, "error": "HTTP 403"})
	if got := Decide(loadDrill(t, "gcp/no-outside-owners"), g, Options{Now: testNow, Available: all}); len(got) != 1 || got[0].Verdict != tag.Error {
		t.Fatalf("an unreadable project gives ERROR on that project, got %+v", got)
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

func TestCarryWaiverOnUnjudgedRun(t *testing.T) {
	d := &drill.Drill{ID: "x/y", Severity: "high"}
	finding := func(expires string) config.Waiver {
		w := config.Waiver{Drill: d.ID, Target: "acme/api", Reason: "r", ApprovedBy: "@a", Expires: expires}
		w.Finding = &struct {
			File string `yaml:"file"`
			Hash string `yaml:"hash"`
		}{"demo.sh", "secret:fake"}
		return w
	}
	wide := config.Waiver{Drill: d.ID, Reason: "r", ApprovedBy: "@a", Expires: "2026-11-20"}
	openWaived := &tag.Tag{Header: tag.Header{State: tag.Open, Waived: true, WaivedParts: 1, Time: testNow}}
	openPlain := &tag.Tag{Header: tag.Header{State: tag.Open, Time: testNow}}
	closed := &tag.Tag{Header: tag.Header{State: tag.Closed, Time: testNow}}
	cases := []struct {
		name    string
		verdict string
		prev    *tag.Tag
		ws      []config.Waiver
		want    bool
	}{
		{"finding waiver active, was waived", tag.Skip, openWaived, []config.Waiver{finding("2026-11-20")}, true},
		{"finding waiver active, was not waived", tag.Skip, openPlain, []config.Waiver{finding("2026-11-20")}, false},
		{"finding waiver expired", tag.Skip, openWaived, []config.Waiver{finding("2026-11-06")}, false},
		{"finding waiver for another target", tag.Skip, openWaived, []config.Waiver{func() config.Waiver { w := finding("2026-11-20"); w.Target = "acme/web"; return w }()}, false},
		{"finding waiver removed", tag.NA, openWaived, nil, false},
		{"drill-wide waiver, any target", tag.Warn, openPlain, []config.Waiver{wide}, true},
		{"closed safeguard is not waived", tag.Skip, closed, []config.Waiver{wide}, false},
		{"no history", tag.Skip, nil, []config.Waiver{wide}, false},
		{"a PASS is never waived", tag.Pass, openWaived, []config.Waiver{wide}, false},
	}
	for _, c := range cases {
		o := &Outcome{Drill: d, Target: "acme/api", Verdict: c.verdict}
		CarryWaiver(o, c.prev, c.ws, testNow)
		if o.Waived != c.want {
			t.Errorf("%s: waived=%v, want %v", c.name, o.Waived, c.want)
		}
		ApplyState(o, c.prev, nil)
		if c.want && (o.NewlyOpen || ExitCode([]*Outcome{o}, "open") != 0) {
			t.Errorf("%s: a waived open safeguard must not be newly open or fail CI: %+v", c.name, o)
		}
	}
	// The finding waiver's count carries with it.
	o := &Outcome{Drill: d, Target: "acme/api", Verdict: tag.Skip}
	CarryWaiver(o, openWaived, []config.Waiver{finding("2026-11-20")}, testNow)
	if o.WaivedParts != 1 || len(o.Waivers) != 1 {
		t.Fatalf("carried waiver detail: %+v", o)
	}
	// Expiry after a carried waiver counts as newly open once.
	o = &Outcome{Drill: d, Target: "acme/api", Verdict: tag.Skip}
	CarryWaiver(o, openWaived, []config.Waiver{finding("2026-11-06")}, testNow)
	ApplyState(o, openWaived, nil)
	if o.Waived || !o.NewlyOpen {
		t.Fatalf("expiry on an unjudged run must be newly open: %+v", o)
	}
}

func TestOneFactForEitherCloudOrEitherProvider(t *testing.T) {
	for _, c := range []struct {
		drill, a, b string
	}{{"recovery/backups-separate-and-retained", "aws", "gcp"}, {"keys/ai-keys-capped", "anthropic", "openai"}} {
		d := loadDrill(t, c.drill)
		// Neither connected: the drill waits and names both.
		got := Decide(d, graph.New(), Options{Now: testNow, Available: map[string]bool{"github": true}})
		if got[0].Verdict != tag.Skip || got[0].Reason != "needs "+c.a+" or "+c.b {
			t.Fatalf("%s: %s %q", c.drill, got[0].Verdict, got[0].Reason)
		}
		// One failed while the other was read: never a clean result.
		got = Decide(d, graph.New(), Options{Now: testNow, Available: map[string]bool{c.a: true, c.b: true},
			Failures: map[string]string{c.a: "HTTP 403"}})
		if got[0].Verdict != tag.Error || !strings.Contains(got[0].Reason, c.a) {
			t.Fatalf("%s: %s %q", c.drill, got[0].Verdict, got[0].Reason)
		}
	}
	// Only Google Cloud connected: the drill runs on what it read.
	g := graph.New()
	settings(g, 1)
	scan(g, "gcp_backups", "acme-prod", 1)
	database(g, "gcp", "ledger", true, 14, "unknown", "")
	got := Decide(loadDrill(t, "recovery/backups-separate-and-retained"), g, Options{Now: testNow, Available: map[string]bool{"gcp": true}})
	if got[0].Verdict != tag.Warn {
		t.Fatalf("%s %s", got[0].Verdict, got[0].Reason)
	}
	// Only OpenAI connected.
	g = graph.New()
	scan(g, "ai_keys", "openai", 1)
	aiKey(g, "openai", "key_acmeci", "active", true, true, true)
	got = Decide(loadDrill(t, "keys/ai-keys-capped"), g, Options{Now: testNow, Available: map[string]bool{"openai": true}})
	if got[0].Verdict != tag.Pass {
		t.Fatalf("%s %s", got[0].Verdict, got[0].Reason)
	}
}

func TestTier1FailReasonsNameTheThing(t *testing.T) {
	want := map[string]string{
		"full Drive and Gmail access, no owner": "app Acme Notes AI (1234-notes.apps.googleusercontent.com), 3 users",
		"backups only in the same account":      "database orders (aws 111122223333 us-east-1)",
		"active key with no owner and no cap":   "openai key key_acmeloop (agent) in acme-prod",
	}
	for _, c := range drillCases() {
		w, ok := want[c.name]
		if !ok {
			continue
		}
		g := graph.New()
		c.setup(g)
		got := Decide(loadDrill(t, c.id), g, Options{Now: testNow, Available: allConnectors})
		if !strings.Contains(got[0].Reason, w) {
			t.Errorf("%s: %q lacks %q", c.name, got[0].Reason, w)
		}
	}
}

func TestUnmarkedDatabasesAreAllJudged(t *testing.T) {
	g := graph.New()
	settings(g, 0)
	scan(g, "aws_backups", "acme-prod", 1)
	database(g, "aws", "orders", false, 14, "no", "")
	got := Decide(loadDrill(t, "recovery/backups-separate-and-retained"), g, Options{Now: testNow, Available: allConnectors})
	if got[0].Verdict != tag.Fail || !strings.Contains(got[0].Reason, "every database is judged") {
		t.Fatalf("with nothing named production every database is judged, and the reason says so: %s %q", got[0].Verdict, got[0].Reason)
	}
	// One named elsewhere: unmarked databases are not production.
	g = graph.New()
	settings(g, 1)
	scan(g, "aws_backups", "acme-prod", 1)
	database(g, "aws", "orders", false, 14, "no", "")
	if got := Decide(loadDrill(t, "recovery/backups-separate-and-retained"), g, Options{Now: testNow, Available: allConnectors}); got[0].Verdict != tag.NA {
		t.Fatalf("%s %q", got[0].Verdict, got[0].Reason)
	}
}

func TestUnreadableEvidenceIsNeverAPass(t *testing.T) {
	// OAuth grants unreadable: the scope is missing from the delegation.
	g := graph.New()
	node(g, string(graph.ScanID("oauth_tokens", "")), graph.KindScan, map[string]any{"scanner": "oauth_tokens", "scope": "",
		"inspected": int64(0), "partial": "x", "error": "could not read users' OAuth grants: add the scope"})
	if got := Decide(loadDrill(t, "access/third-party-apps-reviewed"), g, Options{Now: testNow, Available: allConnectors}); got[0].Verdict != tag.Error {
		t.Fatalf("%s", got[0].Verdict)
	}
	// RDS unreadable in an account.
	g = graph.New()
	node(g, string(graph.ScanID("aws_backups", "acme-prod")), graph.KindScan, map[string]any{"scanner": "aws_backups", "scope": "acme-prod",
		"inspected": int64(0), "partial": "x", "error": "could not read RDS in profile acme-prod: AccessDenied"})
	scan(g, "gcp_backups", "acme-prod", 1)
	database(g, "gcp", "ledger", true, 14, "yes", "")
	if got := Decide(loadDrill(t, "recovery/backups-separate-and-retained"), g, Options{Now: testNow, Available: allConnectors}); got[0].Verdict != tag.Error {
		t.Fatalf("%s", got[0].Verdict)
	}
	// Never read at all.
	if got := Decide(loadDrill(t, "keys/ai-keys-capped"), graph.New(), Options{Now: testNow, Available: allConnectors}); got[0].Verdict != tag.Error {
		t.Fatalf("%s", got[0].Verdict)
	}
}
