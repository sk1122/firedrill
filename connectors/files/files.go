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
		Nodes:      []string{graph.KindSecretSeen, graph.KindAgentConfig, graph.KindWorkflow, graph.KindTFBucket, graph.KindCodeowners},
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

var agentFiles = map[string]bool{
	".claude/settings.json": true, ".claude/settings.local.json": true, ".mcp.json": true,
	".cursor/mcp.json": true, ".vscode/mcp.json": true, ".cursorignore": true,
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

	// Agent settings come first, since they decide what agents may read.
	var denyRead []string
	configs := 0
	addConfig := func(rel, id string, data []byte, scope string) error {
		cfg, err := ParseAgentFile(rel, data, scope)
		if err != nil {
			return err
		}
		configs++
		denyRead = append(denyRead, cfg.DenyRead...)
		servers := []any{}
		for _, srv := range cfg.Servers {
			servers = append(servers, map[string]any{"name": srv.Name, "credentials": credentials(srv, s, t.Path != "")})
			mcp := graph.ID("mcp:" + repo + "/" + srv.Name)
			out.Node(graph.Node{ID: mcp, Kind: "mcp_server", Attrs: map[string]any{"repo": repo, "name": srv.Name}, Source: "files", SeenAt: s.Now})
		}
		node(id, graph.KindAgentConfig, map[string]any{
			"tool": cfg.Tool, "scope": cfg.Scope, "file": cfg.File,
			"allowed_commands": toAny(cfg.Allowed), "denied_commands": toAny(cfg.Denied),
			"deny_read_paths": toAny(cfg.DenyRead), "unguarded_destructive": toAny(Unguarded(cfg, destructive)),
			"mcp_servers": servers,
		})
		return nil
	}
	for _, f := range all {
		if agentFiles[f.Path] {
			if err := addConfig(f.Path, "agent:"+repo+"/"+f.Path, f.Data, "repo"); err != nil {
				// A broken settings file is reported, not silently treated as none.
				return err
			}
		}
	}
	if s.IncludeHome && t.Path != "" && s.HomeDir != "" {
		for _, rel := range []string{".claude/settings.json", ".cursor/mcp.json", ".vscode/mcp.json"} {
			data, err := os.ReadFile(filepath.Join(s.HomeDir, rel))
			if err != nil {
				continue
			}
			if err := addConfig(rel, "agent:"+repo+"/~/"+rel, data, "user"); err != nil {
				return err
			}
		}
	}
	graph.WriteScan(out, "files", "agent_configs", repo, configs, "", s.Now)

	inspected, workflows := 0, 0
	var tfFiles []File
	for _, f := range all {
		inspected++
		for _, finding := range secrets.Scan(string(f.Data)) {
			hash := s.Hasher.Sum(finding.Value)
			fileID := graph.ID("file:" + repo + "/" + f.Path)
			id := fmt.Sprintf("secret:%s@%s/%s:%d", hash, repo, f.Path, finding.Line)
			node(id, graph.KindSecretSeen, map[string]any{
				"kind": finding.Kind, "file": f.Path, "line": int64(finding.Line),
				"env_class": classes.Class(f.Path), "hash": hash,
				"agent_readable": !DenyMatch(denyRead, f.Path), "key_id": finding.KeyID,
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
			node("github:workflow/"+repo+"/"+f.Path, graph.KindWorkflow, map[string]any{
				"file": w.File, "permissions": w.Permissions, "unpinned_actions": toAny(w.Unpinned),
				"pull_request_target_checkout": w.PRTarget,
			})
		case strings.HasSuffix(f.Path, ".tf"):
			tfFiles = append(tfFiles, f)
		case f.Path == "CODEOWNERS" || f.Path == ".github/CODEOWNERS" || f.Path == "docs/CODEOWNERS":
			node("codeowners:"+repo, graph.KindCodeowners, map[string]any{"rules": ParseCodeowners(f.Data)})
		}
	}
	graph.WriteScan(out, "files", "secrets", repo, inspected, "", s.Now)
	graph.WriteScan(out, "files", "workflows", repo, workflows, "", s.Now)

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
		byPath[f.Path] = f.Data
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
