package files

import (
	"reflect"
	"testing"
)

func judge(t *testing.T, files map[string]string, scope map[string]string) map[string]Egress {
	t.Helper()
	var cfgs []*AgentConfig
	byFile := map[*AgentConfig]string{}
	for rel, body := range files {
		sc := "repo"
		if scope[rel] != "" {
			sc = scope[rel]
		}
		c, err := ParseAgentFile(rel, []byte(body), sc)
		if err != nil {
			t.Fatal(err)
		}
		cfgs = append(cfgs, c)
		byFile[c] = rel
	}
	out := map[string]Egress{}
	for c, e := range JudgeEgress(cfgs) {
		out[byFile[c]] = e
	}
	return out
}

func TestClaudeEgress(t *testing.T) {
	cases := []struct {
		name      string
		files     map[string]string
		egress    string
		hosts     []string
		unbounded bool
	}{
		{"nothing restricts it", map[string]string{".claude/settings.json": `{"permissions":{"allow":["Bash(npm test)"]}}`},
			EgressOpen, []string{}, false},
		{"fetch allow rules alone restrict nothing", map[string]string{".claude/settings.json": `{"permissions":{"allow":["WebFetch(domain:docs.acme.com)"]}}`},
			EgressOpen, []string{"docs.acme.com"}, false},
		{"web tools restricted, shell not", map[string]string{".claude/settings.json": `{"permissions":{"deny":["WebFetch","WebSearch","Bash(curl:*)"]}}`},
			EgressPartial, []string{}, false},
		{"sandbox allowlist", map[string]string{".claude/settings.json": `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,
			"network":{"allowedDomains":["github.com","*.npmjs.org","registry.acme.com:443"]}},
			"permissions":{"allow":["WebFetch(domain:docs.acme.com)"]}}`},
			EgressAllowlist, []string{"*.npmjs.org", "docs.acme.com", "github.com", "registry.acme.com"}, false},
		{"sandbox with the retry outside it left on", map[string]string{".claude/settings.json": `{"sandbox":{"enabled":true,"network":{"allowedDomains":["github.com"]}}}`},
			EgressPartial, []string{"github.com"}, false},
		{"sandbox with excluded commands", map[string]string{".claude/settings.json": `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,"excludedCommands":["docker *"]}}`},
			EgressPartial, []string{}, false},
		{"sandbox with every fetch allowed", map[string]string{".claude/settings.json": `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false},"permissions":{"allow":["WebFetch"]}}`},
			EgressPartial, []string{}, false},
		{"wildcard allowlist", map[string]string{".claude/settings.json": `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,"network":{"allowedDomains":["*"]}}}`},
			EgressAllowlist, []string{"*"}, true},
		{"fetch to every domain opens the sandbox too", map[string]string{".claude/settings.json": `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false},"permissions":{"allow":["WebFetch(domain:*)"]}}`},
			EgressAllowlist, []string{"*"}, true},
		{"a local file turns the sandbox off", map[string]string{
			".claude/settings.json":       `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,"network":{"allowedDomains":["github.com"]}}}`,
			".claude/settings.local.json": `{"sandbox":{"enabled":false}}`},
			EgressOpen, []string{"github.com"}, false},
		{"lists add up across files", map[string]string{
			".claude/settings.json":       `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,"network":{"allowedDomains":["github.com"]}}}`,
			".claude/settings.local.json": `{"sandbox":{"network":{"allowedDomains":["pypi.org"]}}}`},
			EgressAllowlist, []string{"github.com", "pypi.org"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := judge(t, c.files, nil)
			for rel, e := range got {
				if e.Egress != c.egress || !reflect.DeepEqual(e.Hosts, c.hosts) || e.Unbounded != c.unbounded {
					t.Fatalf("%s: got %+v", rel, e)
				}
			}
		})
	}
}

func TestMCPAndOtherToolsEgress(t *testing.T) {
	got := judge(t, map[string]string{
		".claude/settings.json": `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,"network":{"allowedDomains":["github.com"]}}}`,
		".mcp.json":             `{"mcpServers":{"docs":{"url":"https://mcp.acme.com/sse?token=x"}}}`,
		".cursor/mcp.json":      `{"mcpServers":{"fs":{"command":"npx","args":["-y","@acme/mcp-fs@1.0.0"]}}}`,
		".cursor/sandbox.json":  `{"networkPolicy":{"default":"deny","allow":["registry.npmjs.org","*.acme.com"]}}`,
		".cursorignore":         ".env\n",
		".vscode/mcp.json": `{"servers":{"boxed":{"type":"stdio","command":"npx","args":["-y","@acme/mcp-a@1.0.0"],"sandboxEnabled":true,
			"sandbox":{"network":{"allowedDomains":["api.acme.com"]}}},"remote":{"url":"https://mcp.acme.com/"}}}`,
		".gemini/settings.json": `{"mcpServers":{}}`,
	}, nil)
	want := map[string]Egress{
		".claude/settings.json": {EgressAllowlist, []string{"github.com"}, false},
		// A remote server is one more host; the agent's own boundary still holds.
		".mcp.json": {EgressAllowlist, []string{"github.com", "mcp.acme.com"}, false},
		// Cursor has no setting that limits a local MCP server.
		".cursor/mcp.json":      {EgressUnsupported, []string{"*.acme.com", "registry.npmjs.org"}, false},
		".cursor/sandbox.json":  {EgressAllowlist, []string{"*.acme.com", "registry.npmjs.org"}, false},
		".cursorignore":         {EgressAllowlist, []string{"*.acme.com", "registry.npmjs.org"}, false},
		".vscode/mcp.json":      {EgressAllowlist, []string{"api.acme.com", "mcp.acme.com"}, false},
		".gemini/settings.json": {EgressUnsupported, []string{}, false},
	}
	for rel, w := range want {
		if e := got[rel]; e.Egress != w.Egress || !reflect.DeepEqual(e.Hosts, w.Hosts) || e.Unbounded != w.Unbounded {
			t.Errorf("%s: got %+v, want %+v", rel, e, w)
		}
	}

	open := judge(t, map[string]string{
		".vscode/mcp.json":     `{"servers":{"loose":{"type":"stdio","command":"node","args":["server.js"]}}}`,
		".cursor/sandbox.json": `{"networkPolicy":{"default":"allow","deny":["evil.example"]}}`,
		".mcp.json":            `{"mcpServers":{}}`,
	}, nil)
	for _, rel := range []string{".vscode/mcp.json", ".cursor/sandbox.json", ".mcp.json"} {
		if open[rel].Egress != EgressOpen {
			t.Errorf("%s: got %+v", rel, open[rel])
		}
	}
	if e := judge(t, map[string]string{".cursor/sandbox.json": `{"type":"insecure_none","networkPolicy":{"allow":["a.acme.com"]}}`}, nil)[".cursor/sandbox.json"]; e.Egress != EgressOpen {
		t.Errorf("the sandbox turned off: %+v", e)
	}
	if e := judge(t, map[string]string{".cursor/sandbox.json": `{"networkPolicy":{"allow":["0.0.0.0/0"]}}`}, nil)[".cursor/sandbox.json"]; !e.Unbounded || e.Egress != EgressAllowlist {
		t.Errorf("every address: %+v", e)
	}
	if EgressRank(EgressOpen) <= EgressRank(EgressUnsupported) || EgressRank(EgressPartial) <= EgressRank(EgressAllowlist) {
		t.Fatal("rank")
	}
}
