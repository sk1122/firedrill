package run

import (
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// The Tier 2 drills read the graph after the link step, so these helpers
// write it in that shape: a person node joined by same_person to each
// account, as link writes it. Names stand in for hashes.

// readGoogle and readGitHub write the scan records the people facts read.
func readGoogle(g *graph.Graph) { scan(g, "google_users", "", 1) }

func readGitHub(g *graph.Graph) {
	node(g, string(graph.ScanID("github_people", "acme")), graph.KindScan, map[string]any{
		"scanner": "github_people", "scope": "acme", "inspected": int64(1), "org": true})
}

// human is a person the link step made, holding the given systems.
func human(g *graph.Graph, name string, systems ...any) graph.ID {
	id := graph.ID("person:" + name)
	g.Node(graph.Node{ID: id, Kind: graph.KindPerson, SeenAt: testNow,
		Attrs:   map[string]any{"systems": systems, "external": false},
		Private: map[string]any{"email": name + "@acme.example"}})
	return id
}

// gone is a leaver from the HR file, after linking.
func gone(g *graph.Graph, name, date string, systems ...any) graph.ID {
	id := graph.ID("person:" + name)
	g.Node(graph.Node{ID: id, Kind: graph.KindLeaver, SeenAt: testNow,
		Attrs:   map[string]any{"leave_date": date, "systems": systems, "external": false},
		Private: map[string]any{"email": name + "@acme.example"}})
	return id
}

func holds(g *graph.Graph, person, account graph.ID) {
	g.Edge(graph.Edge{From: person, To: account, Kind: graph.EdgeSamePerson, Source: "link"})
}

// workspaceUser is a Google user held by a person.
func workspaceUser(g *graph.Graph, person graph.ID, name string, admin, suspended bool) {
	id := graph.ID("google:user/" + name)
	node(g, string(id), graph.KindIdentityUser, map[string]any{"is_admin": admin, "is_delegated_admin": false, "suspended": suspended})
	if person != "" {
		holds(g, person, id)
	}
}

// githubUser is a GitHub user, held by a person when one is given.
func githubUser(g *graph.Graph, person graph.ID, name, role string) graph.ID {
	id := graph.ID("github:user/" + name)
	node(g, string(id), graph.KindGitHubUser, map[string]any{"org": "acme", "org_role": role, "type": "user"})
	if person != "" {
		holds(g, person, id)
	}
	return id
}

func repoEdge(g *graph.Graph, from graph.ID, kind string) {
	g.Edge(graph.Edge{From: from, To: "github:repo/acme/api", Kind: kind, Source: "github"})
}

// project is a GCP project, marked production or not.
func project(g *graph.Graph, name string, production bool) {
	node(g, "gcp:project/"+name, graph.KindGCPProject, map[string]any{"name": name, "number": "1", "member_domains": []any{},
		"production": production})
}

// role is a GCP binding held directly by a person, or by nobody known when
// person is empty.
func role(g *graph.Graph, person graph.ID, proj, r, memberType string, admin, destructive, known, production bool) graph.ID {
	id := graph.ID("gcp:binding/" + proj + "/" + r + "/" + memberType)
	if person != "" {
		id += "-" + graph.ID(string(person)[len("person:"):])
	}
	node(g, string(id), graph.KindGCPBinding, map[string]any{"project": proj, "role": r, "member_type": memberType,
		"member": "", "member_domain": "", "google_managed": false, "default_account": false, "conditional": false,
		"is_admin": admin, "destructive": destructive, "power_known": known, "production": production})
	g.Edge(graph.Edge{From: graph.ID("gcp:project/" + proj), To: id, Kind: graph.EdgeOwns, Source: "gcp"})
	if person != "" {
		holds(g, person, id)
	}
	return id
}

// apiRule is acme/api's default branch rule with who can bypass it, and the
// repo people scan that read it.
func apiRule(g *graph.Graph, known bool, actors ...string) {
	list := []any{}
	for _, a := range actors {
		list = append(list, map[string]any{"kind": "user", "id": "github:user/" + a, "via": "role", "through": ""})
	}
	bypass := "none"
	if len(actors) > 0 {
		bypass = "allowed"
	}
	if !known {
		bypass = "unknown"
	}
	node(g, "github:branch-rule/acme/api/default", graph.KindBranchRule, map[string]any{
		"required_approvals": int64(1), "dismiss_stale": true, "code_owner_review": false,
		"bypass": bypass, "bypass_source": "api", "force_push_allowed": false, "deletion_allowed": false,
		"bypass_actors_known": known, "bypass_actors": list})
	node(g, string(graph.ScanID("github_repo_people", "acme/api")), graph.KindScan, map[string]any{
		"scanner": "github_repo_people", "scope": "acme/api", "inspected": int64(1)})
}

// prodRepo is acme/api deploying to a production environment, with its rule.
func prodRepo(g *graph.Graph, known bool, actors ...string) {
	ghRepo(g, "team", true)
	prodEnv(g, []any{"@a"}, true)
	apiRule(g, known, actors...)
	readGitHub(g)
}

// ownerEntry is an owners.yaml entry joined to a binding.
func ownerEntry(g *graph.Graph, binding graph.ID, owner string) {
	node(g, "config-owner:"+owner, graph.KindConfigOwner, map[string]any{"principal": "ci@acme-prod.iam.gserviceaccount.com", "owner": owner})
	g.Edge(graph.Edge{From: graph.ID("config-owner:" + owner), To: binding, Kind: graph.EdgeOwns, Source: "link"})
}

// unknownGroup is a group binding whose members could not be read.
func unknownGroup(g *graph.Graph, proj, r string) {
	b := role(g, "", proj, r, "group", true, true, true, true)
	node(g, "google:group/admins", graph.KindGoogleGroup, map[string]any{"members_known": false, "member_count": int64(0),
		"external_members": false, "all_users": false})
	g.Edge(graph.Edge{From: "google:group/admins", To: b, Kind: graph.EdgeBoundTo, Source: "link"})
	node(g, string(graph.ScanID("google_groups", "")), graph.KindScan, map[string]any{"scanner": "google_groups", "scope": "",
		"inspected": int64(1), "partial": "the members of 1 of 1 groups that hold a GCP role could not be read"})
}

// agentFiles is acme/api read by the files connector: an agent config when
// agent is true, and the given secrets, under the repo name given.
func agentRepoFiles(g *graph.Graph, repo string, agent bool, secrets ...map[string]any) {
	configs := 0
	if agent {
		configs = 1
		node(g, "agent:"+repo+"/.claude/settings.json", graph.KindAgentConfig, map[string]any{"repo": repo, "tool": "claude-code",
			"scope": "repo", "file": ".claude/settings.json", "allowed_commands": []any{}, "denied_commands": []any{},
			"deny_read_paths": []any{}, "unguarded_destructive": []any{}, "mcp_servers": []any{}, "gitignored": false,
			"local_override": false})
	}
	scan(g, "agent_configs", repo, configs)
	scan(g, "secrets", repo, 4)
	for _, s := range secrets {
		s["repo"] = repo
		node(g, "secret:"+s["hash"].(string)+"@"+repo+"/"+s["file"].(string), graph.KindSecretSeen, s)
	}
}

// humanToken is a GitHub token of a kind that acts as a person.
func humanToken(kind, file string, readable bool) map[string]any {
	return map[string]any{"kind": kind, "file": file, "line": int64(3), "env_class": "unknown", "hash": "9f2c4e1a7b3d5f60a8c2e4b6d8f0a1c3",
		"agent_readable": readable, "key_id": "", "in_agent_config": true, "gitignored": true}
}

// tier2Cases are the four cross-system drills, each built from the incident
// or audit finding it names.
func tier2Cases() []drillCase {
	return []drillCase{
		// Binance: one laptop could reach the money.
		{"paths/no-single-person-code-to-prod-data", tag.Fail, "one person can bypass review and delete production data", func(g *graph.Graph) {
			prodRepo(g, true, "ana")
			project(g, "acme-prod", true)
			ana := human(g, "ana", "gcp", "github")
			repoEdge(g, githubUser(g, ana, "ana", "admin"), graph.EdgeCanBypass)
			role(g, ana, "acme-prod", "roles/owner", "user", true, true, true, true)
		}},
		{"paths/no-single-person-code-to-prod-data", tag.Pass, "the person who can bypass cannot delete production data", func(g *graph.Graph) {
			prodRepo(g, true, "ana")
			project(g, "acme-prod", true)
			ana := human(g, "ana", "gcp", "github")
			repoEdge(g, githubUser(g, ana, "ana", "admin"), graph.EdgeCanBypass)
			role(g, ana, "acme-prod", "roles/viewer", "user", false, false, true, true)
			bo := human(g, "bo", "gcp", "github")
			githubUser(g, bo, "bo", "member")
			role(g, bo, "acme-prod", "roles/owner", "user", true, true, true, true)
		}},
		{"paths/no-single-person-code-to-prod-data", tag.Pass, "delete rights only outside production", func(g *graph.Graph) {
			prodRepo(g, true, "ana")
			project(g, "acme-prod", true)
			project(g, "acme-dev", false)
			ana := human(g, "ana", "gcp", "github")
			repoEdge(g, githubUser(g, ana, "ana", "admin"), graph.EdgeCanBypass)
			role(g, ana, "acme-dev", "roles/owner", "user", true, true, true, false)
		}},
		{"paths/no-single-person-code-to-prod-data", tag.Warn, "who can bypass is unknown", func(g *graph.Graph) {
			prodRepo(g, false)
			project(g, "acme-prod", true)
			bo := human(g, "bo", "gcp")
			role(g, bo, "acme-prod", "roles/owner", "user", true, true, true, true)
		}},
		{"paths/no-single-person-code-to-prod-data", tag.Warn, "an unlinked GitHub account can bypass", func(g *graph.Graph) {
			prodRepo(g, true, "ghost")
			project(g, "acme-prod", true)
			repoEdge(g, githubUser(g, "", "ghost", "admin"), graph.EdgeCanBypass)
		}},
		{"paths/no-single-person-code-to-prod-data", tag.Warn, "the bypassing person holds a custom role nobody could read", func(g *graph.Graph) {
			prodRepo(g, true, "ana")
			project(g, "acme-prod", true)
			ana := human(g, "ana", "gcp", "github")
			repoEdge(g, githubUser(g, ana, "ana", "admin"), graph.EdgeCanBypass)
			role(g, ana, "acme-prod", "projects/acme-prod/roles/deployer", "user", false, false, false, true)
		}},
		{"paths/no-single-person-code-to-prod-data", tag.NA, "no production environment", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			apiRule(g, true, "ana")
			readGitHub(g)
			project(g, "acme-prod", true)
			ana := human(g, "ana", "gcp", "github")
			repoEdge(g, githubUser(g, ana, "ana", "admin"), graph.EdgeCanBypass)
			role(g, ana, "acme-prod", "roles/owner", "user", true, true, true, true)
		}},

		// The recurring audit finding: a leaver still holds access somewhere.
		{"access/leavers-gone-everywhere", tag.Fail, "leaver still active in Google Workspace", func(g *graph.Graph) {
			readGoogle(g)
			dee := gone(g, "dee", "2026-10-01", "google")
			workspaceUser(g, dee, "dee", false, false)
		}},
		{"access/leavers-gone-everywhere", tag.Fail, "leaver suspended in Google but still holds a GCP role", func(g *graph.Graph) {
			readGoogle(g)
			project(g, "acme-prod", true)
			dee := gone(g, "dee", "2026-10-01", "gcp", "google")
			workspaceUser(g, dee, "dee", false, true)
			role(g, dee, "acme-prod", "roles/storage.objectAdmin", "user", false, true, true, true)
		}},
		{"access/leavers-gone-everywhere", tag.Fail, "leaver suspended in Google but still in the GitHub org", func(g *graph.Graph) {
			readGoogle(g)
			readGitHub(g)
			dee := gone(g, "dee", "2026-10-01", "github", "google")
			workspaceUser(g, dee, "dee", false, true)
			githubUser(g, dee, "dee", "member")
		}},
		{"access/leavers-gone-everywhere", tag.Pass, "every account of the leaver is closed", func(g *graph.Graph) {
			readGoogle(g)
			readGitHub(g)
			project(g, "acme-prod", true)
			dee := gone(g, "dee", "2026-10-01", "google")
			workspaceUser(g, dee, "dee", false, true)
			ana := human(g, "ana", "github", "google")
			workspaceUser(g, ana, "ana", true, false)
			githubUser(g, ana, "ana", "admin")
		}},
		{"access/leavers-gone-everywhere", tag.Pass, "only GitHub connected and the leaver is gone from it", func(g *graph.Graph) {
			readGitHub(g)
			gone(g, "dee", "2026-10-01")
			ana := human(g, "ana", "github")
			githubUser(g, ana, "ana", "admin")
		}},
		{"access/leavers-gone-everywhere", tag.Warn, "a GitHub account maps to nobody", func(g *graph.Graph) {
			readGitHub(g)
			gone(g, "dee", "2026-10-01")
			githubUser(g, "", "x7k2q9vz4m8w", "member")
		}},
		{"access/leavers-gone-everywhere", tag.NA, "leave date still ahead", func(g *graph.Graph) {
			readGoogle(g)
			dee := gone(g, "dee", "2027-01-01", "google")
			workspaceUser(g, dee, "dee", false, false)
		}},

		// The recurring audit finding: admin power nobody answers for.
		{"access/every-admin-is-someone", tag.Fail, "the default Compute account has Editor and no owner", func(g *graph.Graph) {
			readGoogle(g)
			project(g, "acme-prod", true)
			ana := human(g, "ana", "google")
			workspaceUser(g, ana, "ana", true, false)
			role(g, "", "acme-prod", "roles/editor", "service_account", true, true, true, true)
		}},
		{"access/every-admin-is-someone", tag.Fail, "an org owner who has left", func(g *graph.Graph) {
			readGoogle(g)
			readGitHub(g)
			dee := gone(g, "dee", "2026-10-01", "github", "google")
			workspaceUser(g, dee, "dee", false, true)
			githubUser(g, dee, "dee", "admin")
		}},
		{"access/every-admin-is-someone", tag.Pass, "each admin is a current person or has an owner", func(g *graph.Graph) {
			readGoogle(g)
			project(g, "acme-prod", true)
			ana := human(g, "ana", "gcp", "google")
			workspaceUser(g, ana, "ana", true, false)
			role(g, ana, "acme-prod", "roles/owner", "user", true, true, true, true)
			ownerEntry(g, role(g, "", "acme-prod", "roles/editor", "service_account", true, true, true, true), "platform-team")
		}},
		{"access/every-admin-is-someone", tag.Warn, "the members of an owner group could not be read", func(g *graph.Graph) {
			readGoogle(g)
			project(g, "acme-prod", true)
			ana := human(g, "ana", "google")
			workspaceUser(g, ana, "ana", true, false)
			unknownGroup(g, "acme-prod", "roles/owner")
		}},
		{"access/every-admin-is-someone", tag.Warn, "Google not connected, so whether the owner is current is unknown", func(g *graph.Graph) {
			readGitHub(g)
			ana := human(g, "ana", "github")
			githubUser(g, ana, "ana", "admin")
		}},
		{"access/every-admin-is-someone", tag.Warn, "GitHub owners not mapped to a person", func(g *graph.Graph) {
			// A first run: people.yaml is empty and Google is not connected. A
			// human account Firedrill cannot link is unverified, not nobody's.
			readGitHub(g)
			githubUser(g, "", "ghost", "admin")
			githubUser(g, "", "ivy", "admin")
		}},
		{"access/every-admin-is-someone", tag.Fail, "a bot owns the org with no owner", func(g *graph.Graph) {
			readGitHub(g)
			node(g, "github:user/deploy-bot", graph.KindGitHubUser, map[string]any{"org": "acme", "org_role": "admin", "type": "bot"})
			githubUser(g, "", "ghost", "admin")
		}},
		{"access/every-admin-is-someone", tag.NA, "no admin", func(g *graph.Graph) {
			readGoogle(g)
			ana := human(g, "ana", "google")
			workspaceUser(g, ana, "ana", false, false)
		}},

		// Karakun: an agent pushed to main with the human's own credentials.
		{"agent/agent-has-own-identity", tag.Fail, "a personal GitHub token in a file the agent reads", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			apiRule(g, true)
			readGitHub(g)
			agentRepoFiles(g, "acme/api", true, humanToken("github_token", ".claude/settings.local.json", true))
		}},
		{"agent/agent-has-own-identity", tag.Fail, "a human can bypass review where the agent pushes", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			apiRule(g, true, "ana")
			readGitHub(g)
			agentRepoFiles(g, "acme/api", true)
		}},
		{"agent/agent-has-own-identity", tag.Pass, "the agent has no human token and nobody can bypass", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			apiRule(g, true)
			readGitHub(g)
			agentRepoFiles(g, "acme/api", true, humanToken("github_oauth", ".env.local", false))
		}},
		{"agent/agent-has-own-identity", tag.Warn, "who can bypass is unknown", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			apiRule(g, false)
			readGitHub(g)
			agentRepoFiles(g, "acme/api", true)
		}},
		{"agent/agent-has-own-identity", tag.NA, "no agent config in the repo", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			apiRule(g, true, "ana")
			readGitHub(g)
			agentRepoFiles(g, "acme/api", false, humanToken("github_token", "scripts/deploy.sh", true))
		}},
		{"agent/agent-has-own-identity", tag.NA, "files read under the checkout's name, not the GitHub name", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			apiRule(g, true, "ana")
			readGitHub(g)
			agentRepoFiles(g, "api", true, humanToken("github_token", ".claude/settings.local.json", true))
		}},
	}
}
