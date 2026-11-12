// Package files reads repos and runs nothing: no build step, no script, no
// package install. That is why it works on a repo in any language.
package files

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/secrets"
)

// Connector reads committed and local files.
type Connector struct{ connector.Base }

// New returns the connector.
func New() *Connector {
	return &Connector{ConnectorName: "files"}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{
		Name:       "repo files",
		Nodes:      []string{graph.KindSecretSeen, graph.KindAgentConfig, graph.KindWorkflow, graph.KindTFBucket, graph.KindCodeowners, graph.KindManifest, graph.KindEgressBoundary},
		Permission: "Contents read, for remote repos",
		Calls:      []string{"GET https://api.github.com/repos/{repo}/tarball, one per listed repo with no local checkout", "read local checkouts passed with --path"},
	}}
}

// Available is true whenever there is a repo to read.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if len(connector.RepoTargets(s)) == 0 {
		return false, "pass --path, or connect github"
	}
	return true, ""
}

// Collect scans every repo in scope.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	for _, t := range connector.RepoTargets(s) {
		var all []File
		var err error
		if t.Path != "" {
			all, err = WalkLocal(t.Path)
		} else {
			if s.Tarball == nil {
				return fmt.Errorf("%s: no way to read this repo", t.Name)
			}
			r, terr := s.Tarball(ctx, t.Name)
			if terr != nil {
				return fmt.Errorf("%s: %w", t.Name, terr)
			}
			all, err = ReadTarball(r)
			_ = r.Close()
		}
		if err != nil {
			return fmt.Errorf("%s: %w", t.Name, err)
		}
		if err := scanRepo(t, all, s, out); err != nil {
			return fmt.Errorf("%s: %w", t.Name, err)
		}
	}
	return nil
}

// agentFiles are the agent config files parsed for their settings. Every
// other agent config path (see IsAgentConfig) is still scanned for secrets.
var agentFiles = map[string]bool{
	".claude/settings.json": true, ".claude/settings.local.json": true, ".mcp.json": true,
	".cursor/mcp.json": true, ".cursor/sandbox.json": true, ".vscode/mcp.json": true, ".cursorignore": true, ".gemini/settings.json": true,
}

// localOverride reports an agent file meant to stay on one machine, such as
// .claude/settings.local.json.
func localOverride(rel string) bool {
	return strings.HasSuffix(path.Base(rel), ".local.json")
}

var workflowFile = regexp.MustCompile(`^\.github/workflows/[^/]+\.ya?ml$`)

func scanRepo(t connector.RepoTarget, all []File, s connector.Scope, out graph.Writer) error {
	repo := t.Name
	node := func(id, kind string, attrs map[string]any) {
		attrs["repo"] = repo
		out.Node(graph.Node{ID: graph.ID(id), Kind: kind, Attrs: attrs, Source: "files", SeenAt: s.Now})
	}
	classes := classesFrom(s)
	destructive := append(append([]string{}, DestructiveCommands...), s.Project.Config.Agents.DestructiveCommands...)

	// Agent settings come first, since they decide what agents may read. They
	// are all parsed before any is written, since a tool's settings across
	// files decide each file's egress.
	var denyRead []string
	type parsed struct {
		cfg        *AgentConfig
		id         string
		gitignored bool
		rel        string
	}
	var parsedConfigs []parsed
	addConfig := func(rel, id string, data []byte, scope string, gitignored bool) error {
		cfg, err := ParseAgentFile(rel, data, scope)
		if err != nil {
			return err
		}
		denyRead = append(denyRead, cfg.DenyRead...)
		parsedConfigs = append(parsedConfigs, parsed{cfg: cfg, id: id, gitignored: gitignored, rel: rel})
		return nil
	}
	for _, f := range all {
		if agentFiles[f.Path] {
			if err := addConfig(f.Path, "agent:"+repo+"/"+f.Path, f.Data, "repo", f.Ignored); err != nil {
				// A broken settings file is reported, not silently treated as none.
				return err
			}
		}
	}
	if s.IncludeHome && t.Path != "" && s.HomeDir != "" {
		for _, rel := range []string{".claude/settings.json", ".cursor/mcp.json", ".cursor/sandbox.json", ".vscode/mcp.json", ".gemini/settings.json"} {
			data, err := os.ReadFile(filepath.Join(s.HomeDir, rel))
			if err != nil {
				continue
			}
			if err := addConfig(rel, "agent:"+repo+"/~/"+rel, data, "user", false); err != nil {
				return err
			}
		}
	}
	cfgs := make([]*AgentConfig, len(parsedConfigs))
	for i, p := range parsedConfigs {
		cfgs[i] = p.cfg
	}
	egress := JudgeEgress(cfgs)
	// configs counts every agent file; agents counts those that configure an
	// agent whose egress can be judged, so a .cursorignore alone counts as
	// no agent for the egress boundary.
	configs, agents := 0, 0
	for _, p := range parsedConfigs {
		cfg := p.cfg
		configs++
		if !cfg.NoEgress {
			agents++
		}
		servers := []any{}
		for _, srv := range cfg.Servers {
			servers = append(servers, map[string]any{
				"name": srv.Name, "credentials": credentials(srv, s, t.Path != ""),
				"transport": srv.Transport, "host": srv.Host, "host_known": hostKnown(srv.Host, s),
				"command": srv.Command, "package": srv.Package, "version": srv.Version, "pinned": srv.Pinned,
				"package_known": packageKnown(srv.Package, s),
			})
			mcp := graph.ID("mcp:" + repo + "/" + srv.Name)
			out.Node(graph.Node{ID: mcp, Kind: "mcp_server", Attrs: map[string]any{"repo": repo, "name": srv.Name}, Source: "files", SeenAt: s.Now})
		}
		e := egress[cfg]
		node(p.id, graph.KindAgentConfig, map[string]any{
			"tool": cfg.Tool, "scope": cfg.Scope, "file": cfg.File,
			"allowed_commands": toAny(cfg.Allowed), "denied_commands": toAny(cfg.Denied),
			"deny_read_paths": toAny(cfg.DenyRead), "unguarded_destructive": toAny(Unguarded(cfg, destructive)),
			"mcp_servers": servers, "gitignored": p.gitignored, "local_override": cfg.Scope == "repo" && localOverride(p.rel),
			"egress": e.Egress, "egress_hosts": toAny(e.Hosts), "egress_unbounded": e.Unbounded,
		})
	}
	graph.WriteScan(out, "files", "agent_configs", repo, configs, "", s.Now)

	inspected, workflows := 0, 0
	var tfFiles []File
	var agentJobs []AgentJob
	for _, f := range all {
		if f.Unscanned {
			continue
		}
		inspected++
		for _, finding := range secrets.Scan(string(f.Data)) {
			hash := s.Hasher.Sum(finding.Value)
			fileID := graph.ID("file:" + repo + "/" + f.Path)
			id := fmt.Sprintf("secret:%s@%s/%s:%d", hash, repo, f.Path, finding.Line)
			node(id, graph.KindSecretSeen, map[string]any{
				"kind": finding.Kind, "file": f.Path, "line": int64(finding.Line),
				"env_class": classes.Class(f.Path), "hash": hash,
				"agent_readable": !DenyMatch(denyRead, f.Path), "key_id": finding.KeyID,
				"in_agent_config": IsAgentConfig(f.Path), "gitignored": f.Ignored,
			})
			out.Node(graph.Node{ID: graph.ID("secret:" + hash), Kind: graph.KindSecret, Source: "files", SeenAt: s.Now})
			out.Edge(graph.Edge{From: graph.ID("secret:" + hash), To: fileID, Kind: graph.EdgeFoundIn, Source: "files"})
		}
		switch {
		case workflowFile.MatchString(f.Path):
			w, err := ParseWorkflow(f.Path, f.Data)
			if err != nil {
				return err
			}
			workflows++
			agentJobs = append(agentJobs, AgentJobs(f.Path, f.Data, w)...)
			node("github:workflow/"+repo+"/"+f.Path, graph.KindWorkflow, map[string]any{
				"file": w.File, "permissions": w.Permissions, "unpinned_actions": toAny(w.Unpinned),
				"pull_request_target_checkout": w.PRTarget, "triggers": toAny(w.Triggers), "secrets": toAny(w.Secrets),
				"unfrozen_installs": toAny(w.Unfrozen), "cloud_key_secrets": toAny(w.CloudKeys), "uses_oidc": w.OIDC,
			})
		case strings.HasSuffix(f.Path, ".tf"):
			tfFiles = append(tfFiles, f)
		case f.Path == "CODEOWNERS" || f.Path == ".github/CODEOWNERS" || f.Path == "docs/CODEOWNERS":
			node("codeowners:"+repo, graph.KindCodeowners, map[string]any{"rules": ParseCodeowners(f.Data)})
		}
	}
	graph.WriteScan(out, "files", "secrets", repo, inspected, "", s.Now)
	graph.WriteScan(out, "files", "workflows", repo, workflows, "", s.Now)
	writeBoundary(repo, all, agentJobs, agents > 0, s.IncludeHome && t.Path != "", node)
	places := len(agentJobs)
	if agents > 0 {
		places++
	}
	graph.WriteScan(out, "files", "egress_boundary", repo, places, "", s.Now)

	// new_install_scripts is filled in by the run, against the previous run.
	manifests := ScanManifests(all)
	for _, m := range manifests {
		node("manifest:"+repo+"/"+m.File, graph.KindManifest, map[string]any{
			"file": m.File, "manager": m.Manager, "lockfile": m.Lockfile, "lockfile_committed": m.Committed,
			"install_scripts": toAny(m.Scripts), "install_scripts_known": m.ScriptsKnown, "new_install_scripts": []any{},
		})
	}
	graph.WriteScan(out, "files", "manifests", repo, len(manifests), "", s.Now)

	buckets, err := ParseTerraform(tfFiles)
	if err != nil {
		return err
	}
	for _, b := range buckets {
		node("tf:bucket/"+repo+"/"+b.Name, graph.KindTFBucket, map[string]any{
			"name": b.Name, "file": b.File, "public_acl": b.PublicACL, "public_policy": b.PublicPolicy, "public_access_block": b.HasBlock,
		})
	}
	graph.WriteScan(out, "files", "terraform", repo, len(tfFiles), "", s.Now)

	byPath := map[string][]byte{}
	for _, f := range all {
		if !f.Unscanned {
			byPath[f.Path] = f.Data
		}
	}
	for _, p := range s.FilePaths {
		data, ok := byPath[p]
		if !ok {
			continue
		}
		var doc any
		var err error
		if path.Ext(p) == ".json" {
			err = json.Unmarshal(data, &doc)
		} else {
			err = yaml.Unmarshal(data, &doc)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		// The content stays out of attributes, so it never reaches a snapshot.
		out.Node(graph.Node{ID: graph.ID("file:" + repo + "/" + p), Kind: graph.KindFileDoc, Source: "files", SeenAt: s.Now,
			Attrs: map[string]any{"repo": repo, "path": p}, Private: map[string]any{"content": doc}})
	}
	return nil
}

// credentials names what an MCP server is given: a literal secret by its hash,
// or a reference by its variable name. On a laptop a set variable is hashed from
// the environment, so two names holding one value count as one credential.
func credentials(srv MCPServer, s connector.Scope, local bool) []any {
	out := []any{}
	for _, v := range srv.Values {
		refs := VarRefs(v)
		if len(refs) == 0 {
			if secrets.LooksLikeSecret(v) {
				out = append(out, "secret:"+s.Hasher.Sum(v))
			}
			continue
		}
		for _, name := range refs {
			if local && s.Getenv != nil {
				if val := s.Getenv(name); val != "" {
					out = append(out, "secret:"+s.Hasher.Sum(val))
					continue
				}
			}
			out = append(out, "var:"+name)
		}
	}
	return out
}

// hostKnown says whether an MCP server's host is owned or allowed: under a
// verified domain, a host in hosts.yaml or an entry of agents.mcp_hosts, or
// loopback. An empty host, as from a URL built from a variable, is unknown.
func hostKnown(host string, s connector.Scope) bool {
	if host == "" {
		return false
	}
	if Loopback(host) {
		return true
	}
	return connector.HostOwned(host, s, s.Project.Config.Agents.MCPHosts...)
}

// packageKnown says whether an MCP server runs no fetched package, or one named
// exactly in agents.mcp_packages.
func packageKnown(pkg string, s connector.Scope) bool {
	if pkg == "" {
		return true
	}
	for _, p := range s.Project.Config.Agents.MCPPackages {
		if strings.EqualFold(strings.TrimSpace(p), pkg) {
			return true
		}
	}
	return false
}

func classesFrom(s connector.Scope) secrets.Classes {
	c := secrets.DefaultClasses()
	cfg := s.Project.Config.Secrets
	c.ProdWords = append(c.ProdWords, cfg.ProdWords...)
	c.StagingWords = append(c.StagingWords, cfg.StagingWords...)
	c.ExamplePaths = append(c.ExamplePaths, cfg.ExamplePaths...)
	return c
}

func toAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// writeBoundary records whether the places agents run in this repo have an
// egress boundary outside the agent.
func writeBoundary(repo string, all []File, jobs []AgentJob, localAgents, home bool, node func(id, kind string, attrs map[string]any)) {
	managed := ManagedNotRead
	if home && localAgents {
		managed = Managed(ManagedSettingsPaths())
	}
	dev := Devcontainer(all)
	ids, bounded, exposed := []any{}, []any{}, []any{}
	for _, j := range jobs {
		ids = append(ids, j.ID)
		if j.Bounded {
			bounded = append(bounded, j.ID)
		}
		if j.Exposed {
			exposed = append(exposed, j.ID)
		}
	}
	node("egress-boundary:"+repo, graph.KindEgressBoundary, map[string]any{
		"ci_agent_jobs": ids, "ci_agent_jobs_bounded": bounded, "ci_agent_jobs_exposed": exposed,
		"devcontainer": dev, "managed": managed, "agents_configured": localAgents || len(jobs) > 0,
		"boundary": Boundary(jobs, localAgents, dev, managed),
	})
}
