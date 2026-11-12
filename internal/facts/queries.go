package facts

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/graph"
)

func init() {
	registerTargets()
	registerGitHub()
	registerIdentity()
	registerAWS()
	registerGCP()
	registerFiles()
	registerDoors()
	registerOAuthApps()
	registerBackups()
	registerAIKeys()
	registerGitHubPeople()
	registerPeople()
}

func registerTargets() {
	Register(Def{
		Name:  "repos",
		Shape: List(Obj(map[string]*Shape{"name": Str, "local": Bool})),
		Fn: func(g graph.Reader, _ Args) (Result, error) {
			return listOf(g, graph.KindTargetRepo, "config", "name", "local"), nil
		},
	})
	Register(Def{
		Name:  "config.domains",
		Shape: List(Obj(map[string]*Shape{"domain": Str, "verified": Bool})),
		Fn: func(g graph.Reader, _ Args) (Result, error) {
			r := Result{Source: "config"}
			rows := []any{}
			for _, n := range g.Nodes(graph.KindConfigDomain) {
				if v, _ := n.Attrs["verified"].(bool); !v {
					continue
				}
				rows = append(rows, attrsOf(n, "domain", "verified"))
				r.Read = append(r.Read, n.ID)
			}
			r.Data = rows
			return r, nil
		},
	})
	Register(Def{
		Name:  "config.hosts",
		Shape: List(Obj(map[string]*Shape{"host": Str, "owner": Str})),
		Fn: func(g graph.Reader, _ Args) (Result, error) {
			return listOf(g, graph.KindConfigHost, "config", "host", "owner"), nil
		},
	})
}

func listOf(g graph.Reader, kind, source string, fields ...string) Result {
	r := Result{Source: source}
	rows := []any{}
	for _, n := range g.Nodes(kind) {
		rows = append(rows, attrsOf(n, fields...))
		r.Read = append(r.Read, n.ID)
	}
	r.Data = rows
	return r
}

func registerGitHub() {
	Register(Def{
		Name: "github.repos", Connector: "github",
		Shape: List(Obj(map[string]*Shape{"name": Str, "private": Bool, "plan": Str, "protection_available": Bool})),
		Fn: func(g graph.Reader, _ Args) (Result, error) {
			return listOf(g, graph.KindGitHubRepo, "api", "name", "private", "plan", "protection_available"), nil
		},
	})
	Register(Def{
		Name: "github.branch_rules", Connector: "github", Args: []string{"branch"},
		Shape: Obj(map[string]*Shape{
			"required_approvals": Int, "dismiss_stale": Bool, "code_owner_review": Bool,
			"bypass": Str, "bypass_source": Str, "force_push_allowed": Bool, "deletion_allowed": Bool,
			"bypass_actors_known": Bool,
		}),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			branch := a.String("branch")
			if branch == "" {
				branch = "default"
			}
			id := "github:branch-rule/" + a.TargetName() + "/" + branch
			n, ok := g.Get(graph.ID(id))
			if !ok {
				return Result{}, notCollected("github.branch_rules", id)
			}
			// An admin export carries the commit and who made it into the tag.
			src := strAttr(n, "bypass_detail")
			if src == "" {
				src = "api"
			}
			return Result{Read: []graph.ID{n.ID}, Source: src, Data: attrsOf(n,
				"required_approvals", "dismiss_stale", "code_owner_review", "bypass", "bypass_source",
				"force_push_allowed", "deletion_allowed", "bypass_actors_known")}, nil
		},
	})
	Register(Def{
		Name: "github.environment", Connector: "github", Args: []string{"name"},
		Shape: Obj(map[string]*Shape{
			"exists": Bool, "reviewers_available": Bool, "required_reviewers": List(Str),
			"prevent_self_review": Bool, "admin_bypass": Bool, "protected_branches_only": Bool,
		}),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			repo := a.TargetName()
			repoNode, ok := g.Get(graph.ID("github:repo/" + repo))
			if !ok {
				return Result{}, notCollected("github.environment", repo)
			}
			reviewers := reviewersAvailable(repoNode)
			id := graph.ID("github:env/" + repo + "/" + a.String("name"))
			n, ok := g.Get(id)
			if !ok {
				return Result{Read: []graph.ID{repoNode.ID}, Source: "api", Data: map[string]any{
					"exists": false, "reviewers_available": reviewers, "required_reviewers": []any{},
					"prevent_self_review": false, "admin_bypass": false, "protected_branches_only": false,
				}}, nil
			}
			row := attrsOf(n, "required_reviewers", "prevent_self_review", "admin_bypass", "protected_branches_only")
			row["exists"] = true
			row["reviewers_available"] = reviewers
			return Result{Read: []graph.ID{n.ID, repoNode.ID}, Source: "api", Data: row}, nil
		},
	})
	Register(Def{
		Name: "github.actions_permissions", Connector: "github",
		Shape: Obj(map[string]*Shape{"can_approve_pull_requests": Bool, "default_token_permission": Str}),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			id := "github:actions/" + a.TargetName()
			n, ok := g.Get(graph.ID(id))
			if !ok {
				return Result{}, notCollected("github.actions_permissions", id)
			}
			return Result{Read: []graph.ID{n.ID}, Source: "api",
				Data: attrsOf(n, "can_approve_pull_requests", "default_token_permission")}, nil
		},
	})
}

// reviewersAvailable says whether the plan offers required reviewers on
// environments. Public repos always have them. Private repos need Enterprise.
func reviewersAvailable(repo graph.Node) bool {
	private, _ := repo.Attrs["private"].(bool)
	return !private || strAttr(repo, "plan") == "enterprise"
}

func registerIdentity() {
	Register(Def{
		Name: "identity.users", Connector: "google",
		Shape: List(Obj(map[string]*Shape{
			"email": Str, "suspended": Bool, "is_admin": Bool, "is_delegated_admin": Bool,
			"mfa_enrolled": Bool, "mfa_enforced": Bool, "last_login": Str,
			"days_since_login": Int, "days_since_created": Int,
		})),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			r := Result{Source: "api"}
			rows := []any{}
			for _, n := range g.Nodes(graph.KindIdentityUser) {
				row := attrsOf(n, "suspended", "is_admin", "is_delegated_admin", "mfa_enrolled", "mfa_enforced", "last_login")
				row["email"], _ = n.Private["email"].(string)
				row["days_since_login"] = daysSince(strAttr(n, "last_login"), a.Now)
				row["days_since_created"] = daysSince(strAttr(n, "created"), a.Now)
				rows = append(rows, row)
				r.Read = append(r.Read, n.ID)
			}
			r.Data = rows
			return r, nil
		},
	})
	Register(Def{
		Name: "hr.leavers", Connector: "hr",
		// id is the person ID, person: and the hash of the address, so a drill
		// can match a leaver to people.powers without putting the address in
		// its evidence.
		Shape: List(Obj(map[string]*Shape{"id": Str, "email": Str, "leave_date": Str})),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			r := Result{Source: "file"}
			rows := []any{}
			today := a.Now.UTC().Format("2006-01-02")
			for _, n := range g.Nodes(graph.KindLeaver) {
				date := strAttr(n, "leave_date")
				// An account is due to be locked once the leave date has passed,
				// compared by UTC date. Future dates wait until they arrive.
				if date >= today {
					continue
				}
				email, _ := n.Private["email"].(string)
				rows = append(rows, map[string]any{"id": string(n.ID), "email": strings.ToLower(email), "leave_date": date})
				r.Read = append(r.Read, n.ID)
			}
			r.Data = rows
			return r, nil
		},
	})
}

func registerAWS() {
	Register(Def{
		Name: "aws.principals", Connector: "aws",
		Shape: List(Obj(map[string]*Shape{
			"account": Str, "kind": Str, "name": Str, "last_used": Str, "keys": List(Str),
			"is_admin": Bool, "destructive_actions": List(Str), "excluded": Bool,
			"days_since_used": Int, "days_since_created": Int, "github_oidc": Bool, "github_oidc_unscoped": Bool,
		})),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			r := Result{Source: "api"}
			rows := []any{}
			for _, n := range g.Nodes(graph.KindAWSPrincipal) {
				row := attrsOf(n, "account", "name", "last_used", "keys", "is_admin", "destructive_actions", "excluded",
					"github_oidc", "github_oidc_unscoped")
				row["kind"] = strAttr(n, "principal_kind")
				row["days_since_used"] = daysSince(strAttr(n, "last_used"), a.Now)
				row["days_since_created"] = daysSince(strAttr(n, "created"), a.Now)
				rows = append(rows, row)
				r.Read = append(r.Read, n.ID)
			}
			r.Data = rows
			return r, nil
		},
	})
	Register(Def{
		Name: "aws.agent_keys", Connector: "aws",
		Shape: List(Obj(map[string]*Shape{
			"key_id": Str, "files": List(Str), "agents": List(Str), "account": Str, "user": Str,
			"unknown_account": Bool, "is_admin": Bool, "destructive_actions": List(Str),
		})),
		Fn: agentKeys,
	})
}

// gcpRows lists one target project's nodes of a kind. A project that could not
// be read is an error, so its drills give ERROR rather than a clean result.
func gcpRows(g graph.Reader, kind, project string, fields ...string) ([]graph.Node, Result, error) {
	r := Result{Source: "api"}
	if p, ok := g.Get(graph.ID("gcp:project/" + project)); ok {
		if msg := strAttr(p, "error"); msg != "" {
			return nil, r, fmt.Errorf("could not read %s: %s", project, msg)
		}
	}
	var nodes []graph.Node
	for _, n := range g.Nodes(kind) {
		if strAttr(n, "project") != project {
			continue
		}
		nodes = append(nodes, n)
		r.Read = append(r.Read, n.ID)
	}
	return nodes, r, nil
}

func registerGCP() {
	Register(Def{
		Name: "gcp.projects", Connector: "gcp",
		Shape: List(Obj(map[string]*Shape{"name": Str, "number": Str, "member_domains": List(Str)})),
		Fn: func(g graph.Reader, _ Args) (Result, error) {
			return listOf(g, graph.KindGCPProject, "api", "name", "number", "member_domains"), nil
		},
	})
	Register(Def{
		Name: "gcp.iam_bindings", Connector: "gcp",
		Shape: List(Obj(map[string]*Shape{
			"role": Str, "member_type": Str, "member_domain": Str, "member": Str,
			"google_managed": Bool, "default_account": Bool, "conditional": Bool,
		})),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			nodes, r, err := gcpRows(g, graph.KindGCPBinding, a.TargetName())
			if err != nil {
				return Result{}, err
			}
			rows := []any{}
			for _, n := range nodes {
				rows = append(rows, attrsOf(n, "role", "member_type", "member_domain", "member",
					"google_managed", "default_account", "conditional"))
			}
			r.Data = rows
			return r, nil
		},
	})
	Register(Def{
		Name: "gcp.buckets", Connector: "gcp",
		Shape: List(Obj(map[string]*Shape{
			"name": Str, "public_grants": List(Str), "public_access_prevention": Str, "uniform_access": Bool,
		})),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			nodes, r, err := gcpRows(g, graph.KindGCPBucket, a.TargetName())
			if err != nil {
				return Result{}, err
			}
			rows := []any{}
			for _, n := range nodes {
				rows = append(rows, attrsOf(n, "name", "public_grants", "public_access_prevention", "uniform_access"))
				if readable, ok := n.Attrs["policy_readable"].(bool); ok && !readable {
					r.Partial = "the access policy of some buckets could not be read"
				}
			}
			r.Data = rows
			return r, nil
		},
	})
	Register(Def{
		Name: "gcp.sa_keys", Connector: "gcp",
		Shape: List(Obj(map[string]*Shape{
			"service_account": Str, "key_id": Str, "disabled": Bool, "last_use_known": Bool,
			"days_since_created": Int, "days_since_used": Int,
		})),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			nodes, r, err := gcpRows(g, graph.KindGCPKey, a.TargetName())
			if err != nil {
				return Result{}, err
			}
			rows := []any{}
			for _, n := range nodes {
				row := attrsOf(n, "service_account", "key_id", "disabled", "last_use_known")
				row["days_since_created"] = daysSince(strAttr(n, "created"), a.Now)
				row["days_since_used"] = daysSince(strAttr(n, "last_used"), a.Now)
				rows = append(rows, row)
			}
			r.Data = rows
			return r, nil
		},
	})
}

func agentKeys(g graph.Reader, _ Args) (Result, error) {
	r := Result{Source: "api"}
	type seen struct {
		files  map[string]bool
		agents map[string]bool
	}
	keys := map[string]*seen{}
	agentsByRepo := map[string][]string{}
	for _, c := range g.Nodes(graph.KindAgentConfig) {
		repo := strAttr(c, "repo")
		agentsByRepo[repo] = append(agentsByRepo[repo], strAttr(c, "tool"))
	}
	for _, n := range g.Nodes(graph.KindSecretSeen) {
		id := strAttr(n, "key_id")
		readable, _ := n.Attrs["agent_readable"].(bool)
		if id == "" || !readable {
			continue
		}
		s := keys[id]
		if s == nil {
			s = &seen{files: map[string]bool{}, agents: map[string]bool{}}
			keys[id] = s
		}
		repo := strAttr(n, "repo")
		s.files[repo+"/"+strAttr(n, "file")] = true
		for _, a := range agentsByRepo[repo] {
			s.agents[a] = true
		}
		r.Read = append(r.Read, n.ID)
	}
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	rows := []any{}
	for _, id := range ids {
		row := map[string]any{"key_id": id, "files": sortedKeys(keys[id].files), "agents": sortedKeys(keys[id].agents),
			"account": "", "user": "", "unknown_account": true, "is_admin": false, "destructive_actions": []any{}}
		if kn, ok := g.Get(graph.ID("aws:key/" + id)); ok {
			r.Read = append(r.Read, kn.ID)
			row["account"], row["user"] = strAttr(kn, "account"), strAttr(kn, "user")
			row["unknown_account"] = false
			pid := graph.ID("aws:iam-user/" + strAttr(kn, "account") + "/" + strAttr(kn, "user"))
			if pn, ok := g.Get(pid); ok {
				r.Read = append(r.Read, pn.ID)
				row["is_admin"], _ = pn.Attrs["is_admin"].(bool)
				if d, ok := pn.Attrs["destructive_actions"]; ok {
					row["destructive_actions"] = d
				}
			}
		}
		rows = append(rows, row)
	}
	r.Data = rows
	return r, nil
}

func sortedKeys(m map[string]bool) []any {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// repoScan builds a scanning fact over nodes of one kind in the target repo.
func repoScan(g graph.Reader, a Args, scanner, kind string, fields ...string) (Result, map[string]any) {
	repo := a.TargetName()
	r := Result{Source: "file"}
	rows := []any{}
	for _, n := range g.Nodes(kind) {
		if strAttr(n, "repo") != repo {
			continue
		}
		rows = append(rows, attrsOf(n, fields...))
		r.Read = append(r.Read, n.ID)
	}
	inspected, partial, scanID, ok := scanOf(g, scanner, repo)
	if ok {
		r.Read = append(r.Read, scanID)
	}
	r.Inspected, r.Partial = inspected, partial
	data := map[string]any{"found": rows, "inspected": int64(inspected)}
	r.Data = data
	return r, data
}

func foundShape(elem map[string]*Shape, extra map[string]*Shape) *Shape {
	fields := map[string]*Shape{"found": List(Obj(elem)), "inspected": Int}
	maps.Copy(fields, extra)
	return Obj(fields)
}

func registerFiles() {
	Register(Def{
		Name: "files.secrets", Scanning: true,
		Shape: foundShape(map[string]*Shape{
			"kind": Str, "file": Str, "line": Int, "env_class": Str, "hash": Str, "agent_readable": Bool, "key_id": Str,
			"in_agent_config": Bool, "gitignored": Bool,
		}, map[string]*Shape{"shared_prod_staging": List(Str)}),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			r, data := repoScan(g, a, "secrets", graph.KindSecretSeen,
				"kind", "file", "line", "env_class", "hash", "agent_readable", "key_id", "in_agent_config", "gitignored")
			data["shared_prod_staging"] = sharedProdStaging(g)
			return r, nil
		},
	})
	Register(Def{
		Name: "files.agent_configs", Scanning: true,
		Shape: foundShape(map[string]*Shape{
			"tool": Str, "scope": Str, "file": Str, "allowed_commands": List(Str), "denied_commands": List(Str),
			"deny_read_paths": List(Str), "unguarded_destructive": List(Str), "gitignored": Bool, "local_override": Bool,
			"egress": Str, "egress_hosts": List(Str), "egress_unbounded": Bool,
			"mcp_servers": List(Obj(map[string]*Shape{
				"name": Str, "credentials": List(Str), "transport": Str, "host": Str, "host_known": Bool,
				"command": Str, "package": Str, "version": Str, "pinned": Bool, "package_known": Bool,
			})),
		}, map[string]*Shape{"shared_credentials": List(Str)}),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			r, data := repoScan(g, a, "agent_configs", graph.KindAgentConfig,
				"tool", "scope", "file", "allowed_commands", "denied_commands", "deny_read_paths",
				"unguarded_destructive", "mcp_servers", "gitignored", "local_override", "egress", "egress_hosts", "egress_unbounded")
			data["shared_credentials"] = sharedCredentials(data["found"].([]any))
			return r, nil
		},
	})
	Register(Def{
		Name: "files.workflows", Scanning: true,
		Shape: foundShape(map[string]*Shape{
			"file": Str, "permissions": Str, "unpinned_actions": List(Str), "pull_request_target_checkout": Bool,
			"triggers": List(Str), "secrets": List(Str), "unfrozen_installs": List(Str), "cloud_key_secrets": List(Str),
			"uses_oidc": Bool,
		}, nil),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			r, _ := repoScan(g, a, "workflows", graph.KindWorkflow,
				"file", "permissions", "unpinned_actions", "pull_request_target_checkout", "triggers", "secrets",
				"unfrozen_installs", "cloud_key_secrets", "uses_oidc")
			return r, nil
		},
	})
	Register(Def{
		Name: "files.manifests", Scanning: true,
		Shape: foundShape(map[string]*Shape{
			"file": Str, "manager": Str, "lockfile": Str, "lockfile_committed": Bool,
			"install_scripts": List(Str), "install_scripts_known": Bool, "new_install_scripts": List(Str),
		}, nil),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			r, _ := repoScan(g, a, "manifests", graph.KindManifest,
				"file", "manager", "lockfile", "lockfile_committed", "install_scripts", "install_scripts_known", "new_install_scripts")
			return r, nil
		},
	})
	Register(Def{
		Name: "files.terraform", Scanning: true,
		Shape: foundShape(map[string]*Shape{
			"name": Str, "file": Str, "public_acl": Bool, "public_policy": Bool, "public_access_block": Bool,
		}, nil),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			r, _ := repoScan(g, a, "terraform", graph.KindTFBucket, "name", "file", "public_acl", "public_policy", "public_access_block")
			return r, nil
		},
	})
	for _, name := range []string{"files.json", "files.yaml"} {
		Register(Def{Name: name, Scanning: true, Args: []string{"path"}, Shape: Any,
			Fn: func(g graph.Reader, a Args) (Result, error) {
				id := graph.ID("file:" + a.TargetName() + "/" + a.String("path"))
				r := Result{Source: "file"}
				n, ok := g.Get(id)
				if !ok {
					r.Data = map[string]any{}
					return r, nil
				}
				r.Inspected = 1
				r.Read = []graph.ID{id}
				r.Data = n.Private["content"]
				return r, nil
			}})
	}
	Register(Def{
		Name: "semgrep.results", Connector: "semgrep", Scanning: true,
		Shape: foundShape(map[string]*Shape{"rule": Str, "severity": Str, "file": Str, "line": Int}, nil),
		Fn: func(g graph.Reader, _ Args) (Result, error) {
			r := listOf(g, graph.KindSemgrep, "file", "rule", "severity", "file", "line")
			inspected, partial, id, ok := scanOf(g, "semgrep", "")
			if ok {
				r.Read = append(r.Read, id)
			}
			r.Inspected, r.Partial = inspected, partial
			r.Data = map[string]any{"found": r.Data, "inspected": int64(inspected)}
			return r, nil
		},
	})
}

// sharedProdStaging lists secret hashes seen in both a production and a staging
// file, across every repo.
func sharedProdStaging(g graph.Reader) []any {
	classes := map[string]map[string]bool{}
	for _, n := range g.Nodes(graph.KindSecretSeen) {
		h := strAttr(n, "hash")
		if classes[h] == nil {
			classes[h] = map[string]bool{}
		}
		classes[h][strAttr(n, "env_class")] = true
	}
	shared := map[string]bool{}
	for h, c := range classes {
		if c["prod"] && c["staging"] {
			shared[h] = true
		}
	}
	return sortedKeys(shared)
}

// sharedCredentials lists credentials passed to more than one MCP server.
func sharedCredentials(configs []any) []any {
	count := map[string]int{}
	for _, c := range configs {
		cfg, _ := c.(map[string]any)
		servers, _ := cfg["mcp_servers"].([]any)
		for _, s := range servers {
			srv, _ := s.(map[string]any)
			creds, _ := srv["credentials"].([]any)
			for _, cr := range creds {
				if v, ok := cr.(string); ok {
					count[v]++
				}
			}
		}
	}
	shared := map[string]bool{}
	for k, n := range count {
		if n > 1 {
			shared[k] = true
		}
	}
	return sortedKeys(shared)
}

// domainScan builds a scanning fact over nodes of one kind on a verified domain.
func domainScan(scanner, kind, source string, fields ...string) Func {
	return func(g graph.Reader, a Args) (Result, error) {
		domain := a.String("domain")
		r := Result{Source: source}
		rows := []any{}
		for _, n := range g.Nodes(kind) {
			if strAttr(n, "domain") != domain {
				continue
			}
			rows = append(rows, attrsOf(n, fields...))
			r.Read = append(r.Read, n.ID)
		}
		inspected, partial, id, ok := scanOf(g, scanner, domain)
		if ok {
			r.Read = append(r.Read, id)
		}
		r.Inspected, r.Partial = inspected, partial
		r.Data = map[string]any{"found": rows, "inspected": int64(inspected)}
		return r, nil
	}
}

func registerDoors() {
	Register(Def{Name: "ctlog.hosts", Connector: "ctlog", Scanning: true, Args: []string{"domain"},
		Shape: foundShape(map[string]*Shape{"host": Str}, nil),
		Fn:    domainScan("ctlog", graph.KindHost, "api", "host")})
	Register(Def{Name: "dns.cnames", Connector: "dns", Scanning: true, Args: []string{"domain"},
		Shape: foundShape(map[string]*Shape{"host": Str, "target": Str, "target_resolves": Bool}, nil),
		Fn:    domainScan("dns", graph.KindCNAME, "api", "host", "target", "target_resolves")})
	Register(Def{Name: "web.source_maps", Connector: "web", Scanning: true, Args: []string{"domain"},
		Shape: foundShape(map[string]*Shape{"host": Str, "bundle": Str, "map_url": Str}, nil),
		Fn:    domainScan("web_source_maps", graph.KindSourceMap, "api", "host", "bundle", "map_url")})
	Register(Def{Name: "web.public_secrets", Connector: "web", Scanning: true, Args: []string{"domain"},
		Shape: foundShape(map[string]*Shape{
			"host": Str, "path": Str, "kind": Str, "hash": Str, "key_id": Str, "client_side": Bool, "live": Str,
		}, nil),
		Fn: publicSecrets})
	Register(Def{Name: "web.page_scripts", Connector: "web", Scanning: true, Args: []string{"domain"},
		Shape: foundShape(map[string]*Shape{
			"host": Str, "page": Str, "script_host": Str, "script_path": Str, "script_hash": Str,
			"has_integrity": Bool, "crossorigin": Bool, "owned": Bool,
		}, nil),
		Fn: domainScan("web_page_scripts", graph.KindPageScript, "api",
			"host", "page", "script_host", "script_path", "script_hash", "has_integrity", "crossorigin", "owned")})
	Register(Def{Name: "web.api_docs", Connector: "web", Scanning: true, Args: []string{"domain"},
		Shape: foundShape(map[string]*Shape{"host": Str, "path": Str, "status": Int}, nil),
		Fn:    domainScan("web_api_docs", graph.KindAPIDoc, "api", "host", "path", "status")})
	Register(Def{Name: "dns.records", Connector: "dns", Args: []string{"host"},
		Shape: Obj(map[string]*Shape{"cname": Str, "resolves": Bool, "txt": List(Str)}),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			id := "dns:" + a.String("host")
			n, ok := g.Get(graph.ID(id))
			if !ok {
				return Result{}, notCollected("dns.records", id)
			}
			return Result{Read: []graph.ID{n.ID}, Source: "api", Data: attrsOf(n, "cname", "resolves", "txt")}, nil
		}})
	Register(Def{Name: "web.get", Connector: "web", Args: []string{"host", "path"},
		Shape: Obj(map[string]*Shape{"status": Int, "headers": Any, "head": Str, "tail": Str}),
		Fn: func(g graph.Reader, a Args) (Result, error) {
			id := "web:" + a.String("host") + a.String("path")
			n, ok := g.Get(graph.ID(id))
			if !ok {
				return Result{}, notCollected("web.get", id)
			}
			return Result{Read: []graph.ID{n.ID}, Source: "api", Data: attrsOf(n, "status", "headers", "head", "tail")}, nil
		}})
}

// publicSecrets lists the credentials found in a domain's public bundles and
// source maps, each with whether its key is live. The join is made here, from
// whatever the graph holds when the drill runs, so it does not matter which
// connector ran first. Key IDs are matched against the Google Cloud service
// account keys the GCP connector read, which only a service account key's
// private_key_id can equal: a match is live when that key is not disabled,
// and not live when it is. A key the inventory does not hold,
// including a deleted one, which the keys list no longer shows, is unknown,
// and so is every secret with no readable ID. AWS access key IDs are not
// matched.
func publicSecrets(g graph.Reader, a Args) (Result, error) {
	r, err := domainScan("web_public_secrets", graph.KindPublicSecret, "api",
		"host", "path", "kind", "hash", "key_id", "client_side")(g, a)
	if err != nil {
		return r, err
	}
	keys := map[string]graph.Node{}
	for _, n := range g.Nodes(graph.KindGCPKey) {
		if id := strAttr(n, "key_id"); id != "" {
			keys[id] = n
		}
	}
	data := r.Data.(map[string]any)
	for _, row := range data["found"].([]any) {
		m := row.(map[string]any)
		live := "unknown"
		if id, _ := m["key_id"].(string); id != "" {
			if k, ok := keys[id]; ok {
				live = "yes"
				if isTrue(k.Attrs["disabled"]) {
					live = "no"
				}
				r.Read = append(r.Read, k.ID)
			}
		}
		m["live"] = live
	}
	return r, nil
}

// settingsInt reads one threshold from the config settings node, or its
// default when the node is missing, as in a graph built by hand.
func settingsInt(g graph.Reader, name string, def int64) int64 {
	if n, ok := g.Get(graph.ID("config:settings")); ok {
		if v, ok := n.Attrs[name].(int64); ok {
			return v
		}
	}
	return def
}

// daysSinceDate returns whole days since a YYYY-MM-DD date, 0 for a date not
// yet reached, or -1 when it is empty or unreadable.
func daysSinceDate(date string, now time.Time) int64 {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return -1
	}
	return max(0, int64(now.UTC().Sub(t).Hours()/24))
}

// scanOrError reads a scan record that also carries a connector's error for
// one collection. Missing, it was never read; with an error, the error is
// returned, so the drill gives ERROR rather than a clean result.
func scanOrError(g graph.Reader, fact, scanner, scope string) (graph.Node, error) {
	id := graph.ScanID(scanner, scope)
	n, ok := g.Get(id)
	if !ok {
		return n, notCollected(fact, string(id))
	}
	if msg := strAttr(n, "error"); msg != "" {
		return n, fmt.Errorf("%s", msg)
	}
	return n, nil
}

func registerOAuthApps() {
	Register(Def{
		Name: "identity.oauth_apps", Connector: "google",
		Shape: List(Obj(map[string]*Shape{
			"client_id": Str, "name": Str, "scopes": List(Str), "sensitive_scopes": List(Str), "high_risk": Bool,
			"user_count": Int, "native": Bool, "anonymous": Bool,
			"owner": Str, "reviewed": Str, "days_since_review": Int, "review_current": Bool,
		})),
		Fn: oauthApps,
	})
}

// oauthApps joins each third-party app users granted access with its entry in
// apps.yaml. The scan record is written by the google connector's OAuth tokens
// collection, scanner oauth_tokens.
func oauthApps(g graph.Reader, a Args) (Result, error) {
	scan, err := scanOrError(g, "identity.oauth_apps", "oauth_tokens", "")
	if err != nil {
		return Result{}, err
	}
	r := Result{Source: "api", Read: []graph.ID{scan.ID}, Partial: strAttr(scan, "partial")}
	reviewDays := settingsInt(g, "review_days", 180)
	register := map[string]graph.Node{}
	for _, n := range g.Nodes(graph.KindConfigApp) {
		register[strAttr(n, "client_id")] = n
	}
	rows := []any{}
	for _, n := range g.Nodes(graph.KindOAuthApp) {
		row := attrsOf(n, "client_id", "name", "scopes", "sensitive_scopes", "high_risk", "user_count", "native", "anonymous")
		row["owner"], row["reviewed"] = "", ""
		if reg, ok := register[strAttr(n, "client_id")]; ok {
			row["owner"], row["reviewed"] = strAttr(reg, "owner"), strAttr(reg, "reviewed")
			r.Read = append(r.Read, reg.ID)
		}
		days := daysSinceDate(row["reviewed"].(string), a.Now)
		row["days_since_review"] = days
		row["review_current"] = days >= 0 && days <= reviewDays
		rows = append(rows, row)
		r.Read = append(r.Read, n.ID)
	}
	r.Data = rows
	return r, nil
}

// backupShape is the shape of aws.backups, gcp.backups and recovery.databases.
var backupShape = Obj(map[string]*Shape{
	"found": List(Obj(map[string]*Shape{
		"system": Str, "account": Str, "project": Str, "region": Str, "name": Str, "engine": Str,
		"production": Bool, "production_basis": Str, "automated_backups": Bool, "retention_days": Int, "retention_ok": Bool,
		"deletion_protection": Bool, "separate_copy": Str, "copy_detail": Str,
		"last_restore_days": Int, "restore_source": Str, "restore_current": Bool, "restore_known": Bool, "restore_detail": Str,
	})),
	"systems": List(Str), "min_retention_days": Int, "restore_days": Int,
})

// backupScanners are the scan records the aws and gcp connectors write for
// each profile or project whose databases they read.
var backupScanners = map[string]string{"aws": "aws_backups", "gcp": "gcp_backups"}

func registerBackups() {
	Register(Def{Name: "aws.backups", Connector: "aws", Shape: backupShape,
		Fn: func(g graph.Reader, a Args) (Result, error) { return backupRows(g, a, "aws.backups", "aws") }})
	Register(Def{Name: "gcp.backups", Connector: "gcp", Shape: backupShape,
		Fn: func(g graph.Reader, a Args) (Result, error) { return backupRows(g, a, "gcp.backups", "gcp") }})
	Register(Def{Name: "recovery.databases", AnyConnector: []string{"aws", "gcp"}, Shape: backupShape,
		Fn: func(g graph.Reader, a Args) (Result, error) {
			return backupRows(g, a, "recovery.databases", "aws", "gcp")
		}})
}

// backupRows lists the databases of the given systems that were read. A
// database is production when its account or project is named under
// production, or it is tagged so; when nothing anywhere is named or tagged,
// every database is judged and production_basis says so. A copy declared in
// backups.yaml counts where the API shows none.
//
// Each row also says when the database was last restored: from the Cloud SQL
// operations the gcp connector read, or a restore declared in restores.yaml,
// whichever is later. restore_known is false when no restore was found and
// the operations could not all be read, so nothing found never reads as never
// restored. AWS restores are not read, so an AWS row has only what
// restores.yaml declares.
func backupRows(g graph.Reader, a Args, fact string, systems ...string) (Result, error) {
	r := Result{Source: "api"}
	read := []any{}
	var partial []string
	for _, sys := range systems {
		got := false
		for _, n := range g.Nodes(graph.KindScan) {
			if strAttr(n, "scanner") != backupScanners[sys] {
				continue
			}
			if msg := strAttr(n, "error"); msg != "" {
				return Result{}, fmt.Errorf("%s: %s", fact, msg)
			}
			if p := strAttr(n, "partial"); p != "" {
				partial = append(partial, p)
			}
			r.Read = append(r.Read, n.ID)
			got = true
		}
		if got {
			read = append(read, sys)
		}
	}
	if len(read) == 0 {
		return Result{}, fmt.Errorf("%s: no databases were read from %s", fact, strings.Join(systems, " or "))
	}
	r.Partial = strings.Join(partial, "; ")
	minDays := settingsInt(g, "min_retention_days", 7)
	declared := map[string]graph.Node{}
	for _, n := range g.Nodes(graph.KindConfigBackup) {
		declared[strAttr(n, "database")] = n
	}
	restoreDays := settingsInt(g, "restore_days", 90)
	restores := map[string]graph.Node{}
	for _, n := range g.Nodes(graph.KindConfigRestore) {
		db := strAttr(n, "database")
		if prev, ok := restores[db]; !ok || strAttr(n, "restored") > strAttr(prev, "restored") {
			restores[db] = n
		}
	}
	var dbs []graph.Node
	anyProduction := settingsInt(g, "production_markers", 0) > 0
	for _, n := range g.Nodes(graph.KindDatabase) {
		for _, sys := range read {
			if strAttr(n, "system") == sys {
				dbs = append(dbs, n)
				if isTrue(n.Attrs["production"]) {
					anyProduction = true
				}
			}
		}
	}
	rows := []any{}
	for _, n := range dbs {
		row := attrsOf(n, "system", "account", "project", "region", "name", "engine", "production", "automated_backups",
			"retention_days", "deletion_protection", "separate_copy", "copy_detail")
		basis := ""
		switch {
		case isTrue(n.Attrs["production_marked"]):
			basis = "named under production in config"
		case isTrue(n.Attrs["production"]):
			basis = "tagged env=prod"
		case !anyProduction:
			row["production"] = true
			basis = "nothing is named or tagged production, so every database is judged"
		}
		row["production_basis"] = basis
		days, _ := n.Attrs["retention_days"].(int64)
		row["retention_ok"] = days >= minDays
		reg, ok := declared[strAttr(n, "name")]
		if !ok {
			reg, ok = declared[string(n.ID)]
		}
		if ok && strAttr(n, "separate_copy") != "yes" {
			row["separate_copy"] = "declared"
			row["copy_detail"] = strings.TrimPrefix(strAttr(n, "copy_detail")+"; declared copy: "+strAttr(reg, "copy_location")+
				", verified "+strAttr(reg, "verified"), "; ")
			r.Read = append(r.Read, reg.ID)
		}
		decl, ok := restores[strAttr(n, "name")]
		if !ok {
			decl, ok = restores[string(n.ID)]
		}
		if ok {
			r.Read = append(r.Read, decl.ID)
		}
		restoreFields(row, n, decl, ok, restoreDays, a.Now)
		rows = append(rows, row)
		r.Read = append(r.Read, n.ID)
	}
	r.Data = map[string]any{"found": rows, "systems": read, "min_retention_days": minDays, "restore_days": restoreDays}
	return r, nil
}

// restoreFields fills in a database row's last restore: the later of what the
// API showed and what restores.yaml declares.
func restoreFields(row map[string]any, db, decl graph.Node, declared bool, window int64, now time.Time) {
	days, source, detail := int64(-1), "none", strAttr(db, "restore_detail")
	if strAttr(db, "system") == "aws" {
		detail = "AWS restores are not read (out of scope for now); a restore can be declared in restores.yaml"
	}
	if at := strAttr(db, "last_restore"); at != "" {
		days, source = daysSince(at, now), "api"
	}
	if declared {
		if d := daysSinceDate(strAttr(decl, "restored"), now); d >= 0 && (days < 0 || d < days) {
			days, source = d, "declared"
			detail = strings.TrimPrefix(detail+"; declared restore on "+strAttr(decl, "restored")+" by "+strAttr(decl, "by"), "; ")
		}
	}
	row["last_restore_days"] = days
	row["restore_source"] = source
	row["restore_current"] = days >= 0 && days <= window
	row["restore_known"] = days >= 0 || isTrue(db.Attrs["restores_readable"])
	row["restore_detail"] = detail
}

func isTrue(v any) bool {
	b, _ := v.(bool)
	return b
}

// aiKeyShape is the shape of anthropic.keys, openai.keys and keys.ai.
var aiKeyShape = Obj(map[string]*Shape{
	"found": List(Obj(map[string]*Shape{
		"provider": Str, "key_id": Str, "hint": Str, "name": Str, "status": Str,
		"workspace": Str, "workspace_name": Str, "project": Str, "project_name": Str,
		"owner_kind": Str, "has_owner": Bool, "owner": Str, "owner_source": Str,
		"limit_readable": Bool, "capped": Bool, "limit_scope": Str, "cap_source": Str, "days_since_created": Int,
	})),
	"providers": List(Str),
})

func registerAIKeys() {
	Register(Def{Name: "anthropic.keys", Connector: "anthropic", Shape: aiKeyShape,
		Fn: func(g graph.Reader, a Args) (Result, error) { return aiKeyRows(g, a, "anthropic.keys", "anthropic") }})
	Register(Def{Name: "openai.keys", Connector: "openai", Shape: aiKeyShape,
		Fn: func(g graph.Reader, a Args) (Result, error) { return aiKeyRows(g, a, "openai.keys", "openai") }})
	Register(Def{Name: "keys.ai", AnyConnector: []string{"anthropic", "openai"}, Shape: aiKeyShape,
		Fn: func(g graph.Reader, a Args) (Result, error) {
			return aiKeyRows(g, a, "keys.ai", "anthropic", "openai")
		}})
}

// aiKeyRows lists the AI provider keys of the given providers that were read,
// joined with ai-keys.yaml. A register entry names a key, a workspace or a
// project; it gives an owner where the provider records none, and a declared
// cap where the API shows none.
func aiKeyRows(g graph.Reader, a Args, fact string, providers ...string) (Result, error) {
	r := Result{Source: "api"}
	read := []any{}
	var partial []string
	for _, p := range providers {
		n, ok := g.Get(graph.ScanID("ai_keys", p))
		if !ok {
			continue
		}
		if msg := strAttr(n, "error"); msg != "" {
			return Result{}, fmt.Errorf("%s: %s", fact, msg)
		}
		if msg := strAttr(n, "partial"); msg != "" {
			partial = append(partial, p+": "+msg)
		}
		r.Read = append(r.Read, n.ID)
		read = append(read, p)
	}
	if len(read) == 0 {
		return Result{}, fmt.Errorf("%s: no keys were read from %s", fact, strings.Join(providers, " or "))
	}
	r.Partial = strings.Join(partial, "; ")
	register := g.Nodes(graph.KindConfigAIKey)
	rows := []any{}
	for _, n := range g.Nodes(graph.KindAIKey) {
		prov := strAttr(n, "provider")
		wanted := false
		for _, p := range read {
			wanted = wanted || p == prov
		}
		if !wanted {
			continue
		}
		row := attrsOf(n, "provider", "key_id", "hint", "name", "status", "workspace", "workspace_name", "project", "project_name",
			"owner_kind", "has_owner", "owner", "limit_readable", "capped", "limit_scope")
		row["owner_source"] = ""
		if isTrue(n.Attrs["has_owner"]) {
			row["owner_source"] = "provider"
		}
		capSource := "unknown"
		switch {
		case isTrue(n.Attrs["capped"]):
			capSource = "api"
		case isTrue(n.Attrs["limit_readable"]):
			capSource = "none"
		}
		for _, reg := range register {
			if !aiKeyMatches(reg, n) {
				continue
			}
			r.Read = append(r.Read, reg.ID)
			if !isTrue(row["has_owner"]) && strAttr(reg, "owner") != "" {
				row["has_owner"], row["owner"], row["owner_source"] = true, strAttr(reg, "owner"), "declared"
			}
			if limit, _ := reg.Attrs["monthly_limit_usd"].(float64); limit > 0 && !isTrue(row["capped"]) {
				row["capped"], row["limit_readable"], row["limit_scope"] = true, true, "declared"
				capSource = "declared"
			}
		}
		row["cap_source"] = capSource
		row["days_since_created"] = daysSince(strAttr(n, "created"), a.Now)
		rows = append(rows, row)
		r.Read = append(r.Read, n.ID)
	}
	r.Data = map[string]any{"found": rows, "providers": read}
	return r, nil
}

// aiKeyMatches says whether a register entry names a key: by its ID, or by the
// ID or name of its workspace or project.
func aiKeyMatches(reg, key graph.Node) bool {
	if strAttr(reg, "provider") != strAttr(key, "provider") {
		return false
	}
	match := func(want string, have ...string) bool {
		if want == "" {
			return false
		}
		for _, h := range have {
			if h != "" && h == want {
				return true
			}
		}
		return false
	}
	return match(strAttr(reg, "key_id"), strAttr(key, "key_id")) ||
		match(strAttr(reg, "workspace"), strAttr(key, "workspace"), strAttr(key, "workspace_name")) ||
		match(strAttr(reg, "project"), strAttr(key, "project"), strAttr(key, "project_name"))
}
