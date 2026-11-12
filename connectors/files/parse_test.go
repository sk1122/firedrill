package files

import (
	"reflect"
	"strings"
	"testing"
)

func TestWorkflowTriggersInEveryForm(t *testing.T) {
	cases := map[string][]string{
		"on: push\njobs: {}\n":                             {"push"},
		"on: [push, pull_request_target]\njobs: {}\n":      {"pull_request_target", "push"},
		"on:\n  - workflow_dispatch\n  - push\njobs: {}\n": {"push", "workflow_dispatch"},
		"on:\n  pull_request_target:\n    types: [opened]\n  issue_comment:\n  push:\n    branches: [main]\njobs: {}\n": {
			"issue_comment", "pull_request_target", "push"},
		"jobs: {}\n": nil,
	}
	for src, want := range cases {
		w, err := ParseWorkflow("a.yml", []byte(src))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(w.Triggers, want) {
			t.Errorf("%q: got %v, want %v", src, w.Triggers, want)
		}
	}
}

func TestWorkflowSecretNames(t *testing.T) {
	src := `on: pull_request_target
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: acme/agent-action@v1
        with:
          api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          token: ${{secrets.GITHUB_TOKEN}}
          other: ${{ secrets . npm_token }}
          again: ${{ secrets.ANTHROPIC_API_KEY }}
          both: ${{ secrets['DEPLOY_KEY'] || secrets["NPM_TOKEN"] }}
          gh: ${{ github.token }}
          input: ${{ inputs.secrets.NOT_A_SECRET }}
      - run: cat config/secrets.yaml
  shared:
    uses: ./.github/workflows/reusable.yml
    secrets: inherit
`
	w, err := ParseWorkflow("a.yml", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ANTHROPIC_API_KEY", "DEPLOY_KEY", "NPM_TOKEN", "inherit"}
	if !reflect.DeepEqual(w.Secrets, want) {
		t.Fatalf("got %v, want %v", w.Secrets, want)
	}
	if !reflect.DeepEqual(w.Triggers, []string{"pull_request_target"}) {
		t.Fatalf("triggers %v", w.Triggers)
	}

	none, err := ParseWorkflow("b.yml", []byte("on: push\njobs:\n  a:\n    steps:\n      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if none.Secrets == nil || len(none.Secrets) != 0 {
		t.Fatalf("GITHUB_TOKEN is not counted, and the list is empty, not nil: %#v", none.Secrets)
	}
}

func TestGeminiSettingsParse(t *testing.T) {
	src := `{
  // Gemini CLI allows comments.
  "theme": "Default",
  "mcpServers": {
    "db": {"command": "acme-db-mcp", "env": {"DB_URL": "${DB_URL}"}, "args": ["--read-only"]} /* trailing */
  }
}`
	c, err := ParseAgentFile(".gemini/settings.json", []byte(src), "repo")
	if err != nil {
		t.Fatal(err)
	}
	if c.Tool != "gemini" || len(c.Servers) != 1 || c.Servers[0].Name != "db" {
		t.Fatalf("%+v", c)
	}
	if !reflect.DeepEqual(c.Servers[0].Values, []string{"${DB_URL}", "--read-only"}) {
		t.Fatalf("values %v", c.Servers[0].Values)
	}
	if got := stripComments([]byte(`{"u": "http://a/*b*/"} // x`)); string(got) != `{"u": "http://a/*b*/"}     ` {
		t.Fatalf("comment markers inside strings are kept: %q", got)
	}
}

func TestMCPServerDetail(t *testing.T) {
	type want struct {
		transport, host, command, pkg, version string
		pinned                                 bool
	}
	cases := map[string]want{
		`{"type":"http","url":"https://User:Tok@MCP.Acme.com:8443/v1/sse?key=abc"}`:             {"http", "mcp.acme.com", "", "", "", true},
		`{"serverUrl":"https://mcp.acme.com/x"}`:                                                {"http", "mcp.acme.com", "", "", "", true},
		`{"httpUrl":"http://127.0.0.1:3000/mcp"}`:                                               {"http", "127.0.0.1", "", "", "", true},
		`{"url":"https://${MCP_HOST}/mcp"}`:                                                     {"http", "", "", "", "", true},
		`{"command":"npx","args":["-y","@acme/mcp-fs@1.4.2","--root","."]}`:                     {"stdio", "", "npx", "@acme/mcp-fs", "1.4.2", true},
		`{"command":"npx","args":["-y","some-mcp"]}`:                                            {"stdio", "", "npx", "some-mcp", "", false},
		`{"command":"npx","args":["@acme/mcp-fs@latest"]}`:                                      {"stdio", "", "npx", "@acme/mcp-fs", "", false},
		`{"command":"npx","args":["acme-mcp@^1.2.0"]}`:                                          {"stdio", "", "npx", "acme-mcp", "", false},
		`{"command":"npx","args":["acme-mcp@1"]}`:                                               {"stdio", "", "npx", "acme-mcp", "", false},
		`{"command":"npx","args":["--package=acme-mcp@2.0.0","acme-mcp-bin"]}`:                  {"stdio", "", "npx", "acme-mcp", "2.0.0", true},
		`{"command":"npx -y acme-mcp@2.0.0"}`:                                                   {"stdio", "", "npx", "acme-mcp", "2.0.0", true},
		`{"command":"npx","args":["./tools/server"]}`:                                           {"stdio", "", "npx", "", "", true},
		`{"command":"bunx","args":["acme-mcp@3.1.0-beta.1"]}`:                                   {"stdio", "", "bunx", "acme-mcp", "3.1.0-beta.1", true},
		`{"command":"pnpm","args":["dlx","acme-mcp"]}`:                                          {"stdio", "", "pnpm", "acme-mcp", "", false},
		`{"command":"yarn","args":["dlx","acme-mcp@1.0.0"]}`:                                    {"stdio", "", "yarn", "acme-mcp", "1.0.0", true},
		`{"command":"uvx","args":["acme-mcp==0.3.1"]}`:                                          {"stdio", "", "uvx", "acme-mcp", "0.3.1", true},
		`{"command":"uvx","args":["acme-mcp>=0.3"]}`:                                            {"stdio", "", "uvx", "acme-mcp", "", false},
		`{"command":"uvx","args":["--from","Acme-MCP[cli]==1.2","acme"]}`:                       {"stdio", "", "uvx", "acme-mcp", "1.2", true},
		`{"command":"uvx","args":["acme-mcp@latest"]}`:                                          {"stdio", "", "uvx", "acme-mcp", "", false},
		`{"command":"pipx","args":["run","acme-mcp==2.0.0"]}`:                                   {"stdio", "", "pipx", "acme-mcp", "2.0.0", true},
		`{"command":"docker","args":["run","-i","--rm","-e","TOKEN","ghcr.io/acme/mcp:1.2.3"]}`: {"stdio", "", "docker", "ghcr.io/acme/mcp", "1.2.3", true},
		`{"command":"docker","args":["run","-i","--rm","ghcr.io/acme/mcp"]}`:                    {"stdio", "", "docker", "ghcr.io/acme/mcp", "", false},
		`{"command":"docker","args":["run","--rm","localhost:5000/mcp:latest"]}`:                {"stdio", "", "docker", "localhost:5000/mcp", "", false},
		`{"command":"docker","args":["run","-i","ghcr.io/acme/mcp:main@sha256:` + strings.Repeat("ab12", 16) + `"]}`: {
			"stdio", "", "docker", "ghcr.io/acme/mcp", "sha256:ab12ab12ab12", true},
		`{"command":"node","args":["./server.js"]}`:                                            {"stdio", "", "node", "", "", true},
		`{"command":"/Users/someone/bin/acme-mcp"}`:                                            {"stdio", "", "acme-mcp", "", "", true},
		`{"command":"./scripts/mcp.sh"}`:                                                       {"stdio", "", "scripts/mcp.sh", "", "", true},
		`{"command":"npx","args":["-y","mcp-remote@0.1.2","https://mcp.unknown.example/sse"]}`: {"http", "mcp.unknown.example", "npx", "mcp-remote", "0.1.2", true},
		`{"command":"npx","args":["github:acme/mcp#main"]}`:                                    {"stdio", "", "npx", "github:acme/mcp", "", false},
		`{"command":"npx","args":["git+https://tok@git.acme.com/x.git#` + strings.Repeat("a1", 20) + `"]}`: {
			"stdio", "", "npx", "url:git.acme.com", "commit:a1a1a1a1a1a1", true},
	}
	for entry, w := range cases {
		c, err := ParseAgentFile(".mcp.json", []byte(`{"mcpServers":{"s":`+entry+`}}`), "repo")
		if err != nil {
			t.Fatalf("%s: %v", entry, err)
		}
		s := c.Servers[0]
		got := want{s.Transport, s.Host, s.Command, s.Package, s.Version, s.Pinned}
		if got != w {
			t.Errorf("%s:\n got %+v\nwant %+v", entry, got, w)
		}
	}
	// VS Code names them servers.
	c, err := ParseAgentFile(".vscode/mcp.json", []byte(`{"servers":{"s":{"type":"sse","url":"https://mcp.acme.com/sse"}}}`), "repo")
	if err != nil || c.Servers[0].Host != "mcp.acme.com" || c.Servers[0].Transport != "http" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestLoopback(t *testing.T) {
	for h, want := range map[string]bool{"localhost": true, "api.localhost": true, "127.0.0.1": true, "127.1.2.3": true, "::1": true,
		"0.0.0.0": false, "localhost.acme.com": false, "10.0.0.1": false} {
		if Loopback(h) != want {
			t.Errorf("%s: want %v", h, want)
		}
	}
}
