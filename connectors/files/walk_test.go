package files

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

// fakeToken is not a real credential; it has the shape the scanner flags. It is
// built at run time so this file holds no secret-shaped literal.
var fakeToken = "Zx8mQ2pL" + "9vT4rW7yB1nC6dF3"

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func walked(t *testing.T, root string) map[string]File {
	t.Helper()
	all, err := WalkLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]File{}
	for _, f := range all {
		out[f.Path] = f
	}
	return out
}

func TestWalkLocalReadsIgnoredAgentConfig(t *testing.T) {
	root := writeTree(t, map[string]string{
		".gitignore":                  ".claude/settings.local.json\n.gemini/\n.cursor/\n.env*\nbuild/\n",
		".firedrillignore":            ".cursor/rules/private.mdc\n",
		".claude/settings.local.json": `{"permissions":{"allow":["Bash(npm test)"]}}`,
		".claude/settings.json":       `{}`,
		".claude/commands/ship.md":    "ship it",
		".claude/worktrees/x/big":     "a copy of the repo",
		".claude/projects/p/log":      "transcript",
		".gemini/settings.json":       `{}`,
		".gemini/tmp/chat.json":       `{}`,
		".cursor/rules/team.mdc":      "rule",
		".cursor/rules/private.mdc":   "rule",
		".env.local":                  "X=1",
		"build/out.js":                "x",
		"src/main.go":                 "package main",
	})
	got := walked(t, root)
	want := map[string]bool{
		".claude/settings.local.json": true, ".gemini/settings.json": true, ".cursor/rules/team.mdc": true, ".env.local": true,
		".claude/settings.json": false, ".claude/commands/ship.md": false, "src/main.go": false,
		".gitignore": false, ".firedrillignore": false,
	}
	for p, ignored := range want {
		f, ok := got[p]
		if !ok {
			t.Errorf("%s was not read", p)
			continue
		}
		if f.Ignored != ignored {
			t.Errorf("%s: Ignored = %v, want %v", p, f.Ignored, ignored)
		}
	}
	for _, p := range []string{".claude/worktrees/x/big", ".claude/projects/p/log", ".gemini/tmp/chat.json", ".cursor/rules/private.mdc", "build/out.js"} {
		if _, ok := got[p]; ok {
			t.Errorf("%s was read", p)
		}
	}
	if len(got) != len(want) {
		t.Errorf("read %d files, want %d: %v", len(got), len(want), got)
	}
}

func TestWalkLocalUnignoredLocalSettings(t *testing.T) {
	root := writeTree(t, map[string]string{".claude/settings.local.json": `{}`, ".gitignore": "node_modules/\n"})
	f, ok := walked(t, root)[".claude/settings.local.json"]
	if !ok || f.Ignored {
		t.Fatalf("read %v, ignored %v", ok, f.Ignored)
	}
}

func TestAgentConfigPaths(t *testing.T) {
	for p, want := range map[string]bool{
		".claude/settings.local.json": true, ".claude/agents/a.md": true, ".cursor/mcp.json": true,
		".gemini/settings.json": true, ".mcp.json": true, ".vscode/mcp.json": true, ".cursorignore": true,
		".vscode/settings.json": false, ".claude/worktrees/x/.mcp.json": false, ".claude/projects/a.jsonl": false,
		".claude/node_modules/x/a.json": false, "apps/web/.mcp.json": false, "src/.claude.go": false,
	} {
		if got := IsAgentConfig(p); got != want {
			t.Errorf("%s: got %v, want %v", p, got, want)
		}
	}
}

func TestScanRepoWritesAgentAndWorkflowFields(t *testing.T) {
	root := writeTree(t, map[string]string{
		".gitignore":                  ".gemini/\n",
		".claude/settings.local.json": `{"permissions":{"allow":["Bash(ANTHROPIC_API_KEY=` + fakeToken + ` npm test)"]}}`,
		".gemini/settings.json":       `{"mcpServers":{}}`,
		"scripts/deploy.sh":           "DEPLOY_TOKEN=" + fakeToken + "\n",
		".github/workflows/review.yml": "on:\n  pull_request_target:\njobs:\n  r:\n    steps:\n" +
			"      - uses: acme/agent-action@v1\n        with:\n          key: ${{ secrets.ANTHROPIC_API_KEY }}\n",
	})
	all, err := WalkLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	g := graph.New()
	s := connector.Scope{Project: &config.Project{}, Hasher: graph.NewHasher("salt"), Now: time.Unix(0, 0)}
	if err := scanRepo(connector.RepoTarget{Name: "acme/api", Path: root}, all, s, g); err != nil {
		t.Fatal(err)
	}

	secretsByFile := map[string]graph.Node{}
	for _, n := range g.Nodes(graph.KindSecretSeen) {
		secretsByFile[n.Attrs["file"].(string)] = n
	}
	for file, want := range map[string][2]bool{
		".claude/settings.local.json": {true, false},
		"scripts/deploy.sh":           {false, false},
	} {
		n, ok := secretsByFile[file]
		if !ok {
			t.Fatalf("no secret seen in %s: %v", file, secretsByFile)
		}
		if n.Attrs["in_agent_config"] != want[0] || n.Attrs["gitignored"] != want[1] {
			t.Errorf("%s: %v", file, n.Attrs)
		}
	}

	configs := map[string]graph.Node{}
	for _, n := range g.Nodes(graph.KindAgentConfig) {
		configs[n.Attrs["file"].(string)] = n
	}
	if n := configs[".claude/settings.local.json"]; n.Attrs["local_override"] != true || n.Attrs["gitignored"] != false {
		t.Errorf("local settings: %v", n.Attrs)
	}
	if n := configs[".gemini/settings.json"]; n.Attrs["tool"] != "gemini" || n.Attrs["local_override"] != false || n.Attrs["gitignored"] != true {
		t.Errorf("gemini settings: %v", n.Attrs)
	}

	wfs := g.Nodes(graph.KindWorkflow)
	if len(wfs) != 1 {
		t.Fatalf("workflows: %v", wfs)
	}
	if tr, sec := wfs[0].Attrs["triggers"].([]any), wfs[0].Attrs["secrets"].([]any); len(tr) != 1 || tr[0] != "pull_request_target" || len(sec) != 1 || sec[0] != "ANTHROPIC_API_KEY" {
		t.Errorf("workflow: %v", wfs[0].Attrs)
	}
}
