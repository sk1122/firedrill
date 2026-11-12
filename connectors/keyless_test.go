// Package connectors_test runs the keyless drills end to end: real files, real
// connectors, the real engine and the real starter drills.
package connectors_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/connectors/configsrc"
	"github.com/sk1122/firedrill/connectors/ctlog"
	"github.com/sk1122/firedrill/connectors/dns"
	"github.com/sk1122/firedrill/connectors/files"
	"github.com/sk1122/firedrill/connectors/hrcsv"
	"github.com/sk1122/firedrill/connectors/semgrep"
	"github.com/sk1122/firedrill/connectors/web"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
	"github.com/sk1122/firedrill/packs"
)

var now = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)

const railwayToken = "6f1b9d2e-7c44-4a10-9e3b-2d5ac81f0e77"

func writeRepo(t *testing.T, name string, files map[string]string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), name)
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func drillOf(t *testing.T, id string) *drill.Drill {
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

func runFiles(t *testing.T, id, root string, extra ...string) *run.Outcome {
	t.Helper()
	return runFilesWith(t, id, root, &config.Project{Dir: filepath.Join(root, ".firedrill")}, nil, extra...)
}

// runFilesWith runs one files drill with a project's config and verified
// domains.
func runFilesWith(t *testing.T, id, root string, p *config.Project, verified []string, extra ...string) *run.Outcome {
	t.Helper()
	c := run.Config{
		Project: p, Drills: []*drill.Drill{drillOf(t, id)},
		Connectors: []connector.Connector{configsrc.New(), files.New()},
		Scope: connector.Scope{Project: p, Now: now, Log: &connector.CallLog{}, Hasher: graph.NewHasher("salt"),
			Paths: append([]string{root}, extra...), Getenv: func(string) string { return "" }, VerifiedDomains: verified},
		Stream: "local", Records: t.TempDir(), WriteRecords: true,
	}
	res, err := run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) == 0 {
		t.Fatalf("no outcomes, skips: %+v", res.Skips)
	}
	return res.Outcomes[0]
}

func TestPocketOSReplicaFails(t *testing.T) {
	// A prefix-less token in an unrelated script, and no agent config.
	root := writeRepo(t, "pocketos", map[string]string{
		"src/main.go":        "package main\n",
		"scripts/domains.sh": "#!/bin/sh\nRAILWAY_TOKEN=" + railwayToken + "\ncurl https://example.test\n",
	})
	o := runFiles(t, "agent/no-prod-secrets-in-agent-reach", root)
	if o.Verdict != tag.Fail {
		t.Fatalf("the PocketOS replica must FAIL, got %s: %s", o.Verdict, o.Reason)
	}
	if !strings.Contains(o.Reason, "scripts/domains.sh") || !strings.Contains(o.Reason, "unknown") {
		t.Fatalf("reason: %s", o.Reason)
	}
	b, _ := json.Marshal(o.Facts)
	if strings.Contains(string(b), railwayToken) {
		t.Fatal("the raw token reached the evidence")
	}
}

func TestSecretDrillVerdicts(t *testing.T) {
	cases := []struct {
		name, want string
		files      map[string]string
	}{
		{"fake key in a .example file does not fail", tag.Pass, map[string]string{"k.env.example": "API_KEY=" + railwayToken, "a.txt": "x"}},
		{"example file does not fail", tag.Pass, map[string]string{".env.example": "API_KEY=" + railwayToken}},
		{"prod env file fails", tag.Fail, map[string]string{".env.production": "API_KEY=" + railwayToken}},
		{"known prefix fails", tag.Fail, map[string]string{"lib/x.py": `k = "sk_live_abcdefghijklmnop"`}},
		{"denied to the agent passes", tag.Pass, map[string]string{
			".env.production":       "API_KEY=" + railwayToken,
			".claude/settings.json": `{"permissions":{"deny":["Read(./.env.production)"]}}`,
			".cursorignore":         ".env.production\n",
		}},
		{"clean scan passes", tag.Pass, map[string]string{"README.md": "hello"}},
		{"empty repo is N/A", tag.NA, map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := runFiles(t, "agent/no-prod-secrets-in-agent-reach", writeRepo(t, "r", c.files))
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
		})
	}
}

func TestGitignoredEnvFileIsStillRead(t *testing.T) {
	root := writeRepo(t, "r", map[string]string{".gitignore": ".env*\nbuild/\n", ".env.production": "API_KEY=" + railwayToken, "build/x": "API_KEY=" + railwayToken})
	o := runFiles(t, "agent/no-prod-secrets-in-agent-reach", root)
	if o.Verdict != tag.Fail {
		t.Fatalf("got %s", o.Verdict)
	}
	if strings.Contains(o.Reason, "build/") {
		t.Fatalf("ordinary ignored paths stay ignored: %s", o.Reason)
	}
}

func TestSharedProdKeys(t *testing.T) {
	shared := runFiles(t, "access/no-shared-prod-keys", writeRepo(t, "r", map[string]string{".env.production": "API_KEY=" + railwayToken, ".env.staging": "API_KEY=" + railwayToken}))
	if shared.Verdict != tag.Fail {
		t.Fatalf("got %s", shared.Verdict)
	}
	apart := runFiles(t, "access/no-shared-prod-keys", writeRepo(t, "r", map[string]string{".env.production": "API_KEY=" + railwayToken, ".env.staging": "API_KEY=Zx8mQ2pL9vT4rW7yB1nC6dF3"}))
	if apart.Verdict != tag.Pass {
		t.Fatalf("got %s", apart.Verdict)
	}
}

func TestAgentConfigDrills(t *testing.T) {
	if o := runFiles(t, "agent/destructive-commands-gated", writeRepo(t, "r", map[string]string{"a.txt": "x"})); o.Verdict != tag.NA || !strings.Contains(o.Reason, "--include-home") {
		t.Fatalf("no config: %s %s", o.Verdict, o.Reason)
	}
	cases := []struct {
		name, settings, want string
	}{
		{"nothing allowed", `{"permissions":{"allow":["Read"]}}`, tag.Pass},
		{"safe commands", `{"permissions":{"allow":["Bash(go test:*)"]}}`, tag.Pass},
		{"rm allowed", `{"permissions":{"allow":["Bash(rm -rf:*)"]}}`, tag.Fail},
		{"all bash", `{"permissions":{"allow":["Bash"]}}`, tag.Fail},
		{"git push allows force", `{"permissions":{"allow":["Bash(git push:*)"]}}`, tag.Fail},
		{"bypass mode", `{"permissions":{"defaultMode":"bypassPermissions"}}`, tag.Fail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := runFiles(t, "agent/destructive-commands-gated", writeRepo(t, "r", map[string]string{".claude/settings.json": c.settings}))
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
		})
	}
	shared := `{"mcpServers":{"a":{"env":{"T":"${GH_TOKEN}"}},"b":{"env":{"T":"${GH_TOKEN}"}}}}`
	if o := runFiles(t, "agent/no-shared-agent-keys", writeRepo(t, "r", map[string]string{".mcp.json": shared})); o.Verdict != tag.Fail {
		t.Fatalf("got %s", o.Verdict)
	}
	own := `{"mcpServers":{"a":{"env":{"T":"${A_TOKEN}"}},"b":{"env":{"T":"${B_TOKEN}"}}}}`
	if o := runFiles(t, "agent/no-shared-agent-keys", writeRepo(t, "r", map[string]string{".mcp.json": own})); o.Verdict != tag.Pass {
		t.Fatalf("got %s", o.Verdict)
	}
	if o := runFiles(t, "agent/no-shared-agent-keys", writeRepo(t, "r", map[string]string{"a": "x"})); o.Verdict != tag.NA {
		t.Fatalf("got %s", o.Verdict)
	}
}

func TestWorkflowDrills(t *testing.T) {
	pinned := "permissions:\n  contents: read\non: push\njobs:\n  a:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n      - uses: acme/tool@0123456789abcdef0123456789abcdef01234567\n"
	unpinned := "permissions: read-all\non: push\njobs:\n  a:\n    steps:\n      - uses: acme/tool@v1\n"
	risky := "permissions: read-all\non: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
	noperm := "on: push\njobs:\n  a:\n    steps:\n      - run: echo\n"
	jobperm := "on: push\njobs:\n  a:\n    permissions:\n      contents: write\n    steps:\n      - run: echo\n"
	wf := func(c string) string {
		return writeRepo(t, "r", map[string]string{".github/workflows/a.yml": c})
	}
	check := func(id, content, want string) {
		t.Helper()
		if o := runFiles(t, id, wf(content)); o.Verdict != want {
			t.Errorf("%s: got %s (%s), want %s", id, o.Verdict, o.Reason, want)
		}
	}
	check("change/actions-pinned", pinned, tag.Pass)
	check("change/actions-pinned", unpinned, tag.Fail)
	check("change/workflow-tokens-read-only", pinned, tag.Pass)
	check("change/workflow-tokens-read-only", risky, tag.Fail)
	check("change/workflow-tokens-read-only", noperm, tag.Fail)
	check("change/workflow-tokens-read-only", jobperm, tag.Pass)
	if o := runFiles(t, "change/actions-pinned", writeRepo(t, "r", map[string]string{"a": "x"})); o.Verdict != tag.NA {
		t.Errorf("got %s", o.Verdict)
	}
}

func TestPRTargetWithSecretsDrill(t *testing.T) {
	// The PR-title attack: an agent run on pull_request_target, the title in its
	// prompt, an API key and the default token.
	incident := "on:\n  pull_request_target:\n    types: [opened]\njobs:\n  review:\n    runs-on: ubuntu-latest\n    steps:\n" +
		"      - uses: acme/agent-action@v1\n        with:\n          api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n" +
		"          prompt: Review ${{ github.event.pull_request.title }}\n"
	readWithSecret := "permissions: read-all\n" + incident
	readOnly := "permissions:\n  contents: read\non: pull_request_target\njobs:\n  a:\n    steps:\n      - run: echo ${{ secrets.GITHUB_TOKEN }}\n"
	inherits := "permissions: read-all\non: [pull_request_target]\njobs:\n  a:\n    uses: ./.github/workflows/r.yml\n    secrets: inherit\n"
	plainPR := "on: pull_request\njobs:\n  a:\n    steps:\n      - run: npm publish\n        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
	id := "change/no-pr-target-with-secrets"
	for _, c := range []struct{ name, wf, want string }{
		{"incident", incident, tag.Fail},
		{"read-only with a secret", readWithSecret, tag.Fail},
		{"inherits every secret", inherits, tag.Fail},
		{"read-only, no secrets", readOnly, tag.Pass},
		{"pull_request with a secret", plainPR, tag.Pass},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := runFiles(t, id, writeRepo(t, "r", map[string]string{".github/workflows/review.yml": c.wf}))
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
			if c.want == tag.Fail && !strings.Contains(o.Reason, ".github/workflows/review.yml") {
				t.Fatalf("reason: %s", o.Reason)
			}
		})
	}
	if o := runFiles(t, id, writeRepo(t, "r", map[string]string{"a": "x"})); o.Verdict != tag.NA {
		t.Errorf("no workflows: got %s", o.Verdict)
	}
}

func TestSecretsInAgentConfigDrill(t *testing.T) {
	id := "agent/no-secrets-in-agent-config"
	// The Claude Code leak: a "don't ask again" rule holding a token, in a local
	// settings file that is not gitignored.
	leak := `{"permissions":{"allow":["Bash(ANTHROPIC_API_KEY=` + railwayToken + ` npm test)"]}}`
	clean := `{"permissions":{"allow":["Bash(npm test)"]}}`
	cases := []struct {
		name, want string
		files      map[string]string
	}{
		{"incident", tag.Fail, map[string]string{".claude/settings.local.json": leak}},
		{"committed local settings", tag.Fail, map[string]string{".claude/settings.local.json": clean}},
		{"gitignored local settings with a secret", tag.Fail, map[string]string{
			".gitignore": ".claude/settings.local.json\n", ".claude/settings.local.json": leak}},
		{"secret in gemini settings", tag.Fail, map[string]string{
			".gemini/settings.json": `{"mcpServers":{"db":{"env":{"DB_TOKEN":"` + railwayToken + `"}}}}`}},
		{"gitignored local settings", tag.Pass, map[string]string{
			".gitignore": ".claude/settings.local.json\n", ".claude/settings.local.json": clean}},
		{"no agent config", tag.Pass, map[string]string{"scripts/x.sh": "API_KEY=" + railwayToken}},
		{"empty repo", tag.NA, map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := runFiles(t, id, writeRepo(t, "r", c.files))
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
			b, _ := json.Marshal(o.Facts)
			if strings.Contains(string(b), railwayToken) {
				t.Fatal("the raw token reached the evidence")
			}
		})
	}
}

func TestMCPServersKnownDrill(t *testing.T) {
	id := "agent/mcp-servers-known"
	project := func(root string) *config.Project {
		p := &config.Project{Dir: filepath.Join(root, ".firedrill"), Hosts: []config.Host{{Host: "mcp.acme.com", Owner: "@platform"}}}
		p.Config.Agents.MCPHosts = []string{"mcp.vendor.example"}
		p.Config.Agents.MCPPackages = []string{"@acme/mcp-fs"}
		return p
	}
	cases := []struct {
		name, mcp, want, reason string
	}{
		{"owned host, pinned allowlisted package, local script", `{"mcpServers":{
			"docs":{"type":"http","url":"https://mcp.acme.com/v1?token=abc"},
			"vendor":{"type":"http","url":"https://eu.mcp.vendor.example/sse"},
			"verified":{"type":"http","url":"https://tools.acme.dev/mcp"},
			"local":{"type":"http","url":"http://localhost:3000/mcp"},
			"fs":{"command":"npx","args":["-y","@acme/mcp-fs@1.4.2"]},
			"tools":{"command":"./scripts/mcp.sh"}}}`, tag.Pass, ""},
		// The MCP incident: an agent pointed at a server on a host nobody owns.
		{"unknown remote host", `{"mcpServers":{"helper":{"type":"http","url":"https://mcp.unknown-tools.example/sse"}}}`, tag.Fail, ".mcp.json"},
		{"unknown host through mcp-remote", `{"mcpServers":{"helper":{"command":"npx","args":["-y","mcp-remote@0.1.2","https://mcp.unknown-tools.example/sse"]}}}`, tag.Fail, ".mcp.json"},
		{"unpinned npx package", `{"mcpServers":{"helper":{"command":"npx","args":["-y","some-mcp"]}}}`, tag.Fail, ".mcp.json"},
		{"latest", `{"mcpServers":{"fs":{"command":"npx","args":["@acme/mcp-fs@latest"]}}}`, tag.Fail, ".mcp.json"},
		{"pinned but unknown package", `{"mcpServers":{"search":{"command":"uvx","args":["acme-mcp-search==0.3.1"]}}}`, tag.Warn, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := writeRepo(t, "r", map[string]string{".mcp.json": c.mcp})
			o := runFilesWith(t, id, root, project(root), []string{"acme.dev"})
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
			// The reason names the config file; the evidence names the server.
			if c.reason != "" && !strings.Contains(o.Reason, c.reason) {
				t.Fatalf("reason: %s", o.Reason)
			}
			b, _ := json.Marshal(o.Facts)
			if strings.Contains(string(b), "token=abc") || strings.Contains(string(b), "/sse") {
				t.Fatalf("more than the host of a URL reached the evidence: %s", b)
			}
		})
	}
	if o := runFiles(t, id, writeRepo(t, "r", map[string]string{"a": "x"})); o.Verdict != tag.NA || !strings.Contains(o.Reason, "--include-home") {
		t.Fatalf("no agent config: %s %s", o.Verdict, o.Reason)
	}
	// Settings with no MCP servers pass.
	if o := runFiles(t, id, writeRepo(t, "r", map[string]string{".claude/settings.json": `{}`})); o.Verdict != tag.Pass {
		t.Fatalf("no servers: %s %s", o.Verdict, o.Reason)
	}
}

func TestInstallsFromLockfileDrill(t *testing.T) {
	id := "supply/installs-from-lockfile"
	lock := `{"lockfileVersion":3,"packages":{"node_modules/esbuild":{"hasInstallScript":true}}}`
	frozen := "on: push\njobs:\n  a:\n    steps:\n      - run: npm ci && npm test\n"
	cases := []struct {
		name, want string
		files      map[string]string
	}{
		{"committed lockfile, frozen install", tag.Pass, map[string]string{
			"package.json": `{}`, "package-lock.json": lock, ".github/workflows/ci.yml": frozen}},
		{"workspace member locked at the root", tag.Pass, map[string]string{
			"package.json": `{"workspaces":["packages/*"]}`, "pnpm-lock.yaml": "lockfileVersion: '6.0'\n", "packages/web/package.json": `{}`}},
		{"package.json and no workflows", tag.Pass, map[string]string{"package.json": `{}`, "yarn.lock": "x"}},
		{"no lockfile", tag.Fail, map[string]string{"package.json": `{"dependencies":{"left-pad":"^1.3.0"}}`}},
		{"lockfile gitignored", tag.Fail, map[string]string{"package.json": `{}`, "package-lock.json": lock, ".gitignore": "package-lock.json\n"}},
		{"npm install in CI", tag.Fail, map[string]string{"package.json": `{}`, "package-lock.json": lock,
			".github/workflows/ci.yml": "on: push\njobs:\n  a:\n    steps:\n      - run: npm install\n"}},
		{"workflows but no package.json", tag.NA, map[string]string{".github/workflows/ci.yml": frozen}},
		{"empty repo", tag.NA, map[string]string{"a": "x"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := runFiles(t, id, writeRepo(t, "r", c.files))
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
		})
	}
}

// TestNewInstallScriptAcrossRuns runs the drill over one checkout four times,
// keeping the records between runs, as CI does.
func TestNewInstallScriptAcrossRuns(t *testing.T) {
	id := "supply/installs-from-lockfile"
	root := writeRepo(t, "r", map[string]string{"package.json": `{}`})
	records := t.TempDir()
	lock := func(scripts ...string) {
		pkgs := []string{`"node_modules/esbuild":{"hasInstallScript":true}`, `"node_modules/acme-colors":{"version":"1.0.1"}`}
		for _, s := range scripts {
			pkgs = append(pkgs, `"node_modules/`+s+`":{"hasInstallScript":true}`)
		}
		data := `{"lockfileVersion":3,"packages":{` + strings.Join(pkgs, ",") + `}}`
		if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	step := 0
	runOnce := func() *run.Outcome {
		t.Helper()
		step++
		p := &config.Project{Dir: filepath.Join(root, ".firedrill")}
		c := run.Config{
			Project: p, Drills: []*drill.Drill{drillOf(t, id)}, Connectors: []connector.Connector{configsrc.New(), files.New()},
			Scope: connector.Scope{Project: p, Now: now.AddDate(0, 0, step), Log: &connector.CallLog{}, Hasher: graph.NewHasher("salt"),
				Paths: []string{root}, Getenv: func(string) string { return "" }},
			Stream: "local", Records: records, WriteRecords: true,
		}
		res, err := run.Run(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		return res.Outcomes[0]
	}
	newScripts := func(o *run.Outcome) string {
		b, _ := json.Marshal(o.Facts["manifests"])
		return string(b)
	}

	// The first run sets the baseline: esbuild's script is known, not new.
	lock()
	if o := runOnce(); o.Verdict != tag.Pass {
		t.Fatalf("baseline run: %s %s", o.Verdict, o.Reason)
	}
	// A release of acme-colors adds an install script.
	lock("acme-colors")
	o := runOnce()
	if o.Verdict != tag.Fail || !strings.Contains(newScripts(o), "acme-colors") || strings.Contains(newScripts(o), "esbuild") {
		t.Fatalf("new install script: %s %s %s", o.Verdict, o.Reason, newScripts(o))
	}
	// Nothing changes: the script is still new, so the finding stays.
	if o := runOnce(); o.Verdict != tag.Fail || !strings.Contains(newScripts(o), "acme-colors") {
		t.Fatalf("an unaccepted new script must stay new: %s %s", o.Verdict, newScripts(o))
	}
	// The dependency is rolled back: it passes, and the baseline moves.
	lock()
	if o := runOnce(); o.Verdict != tag.Pass {
		t.Fatalf("rolled back: %s %s", o.Verdict, o.Reason)
	}
	lock("acme-colors")
	if o := runOnce(); o.Verdict != tag.Fail {
		t.Fatalf("the script coming back is new again: %s", o.Verdict)
	}
}

func TestCIUsesOIDCDrill(t *testing.T) {
	id := "change/ci-uses-oidc-not-keys"
	// The supply-chain harvest: a long-lived AWS key stored as a secret, in
	// reach of every step a poisoned dependency runs in.
	incident := "on: push\njobs:\n  deploy:\n    steps:\n      - run: npm install\n" +
		"      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n" +
		"          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}\n          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}\n"
	oidc := "on: push\npermissions:\n  id-token: write\n  contents: read\njobs:\n  deploy:\n    steps:\n" +
		"      - uses: aws-actions/configure-aws-credentials@v4\n        with:\n          role-to-assume: arn:aws:iam::123456789012:role/deploy\n"
	gcp := "on: push\njobs:\n  deploy:\n    steps:\n      - uses: google-github-actions/auth@v2\n        with:\n          credentials_json: ${{ secrets.GCP_DEPLOY }}\n"
	plain := "on: push\njobs:\n  a:\n    steps:\n      - run: npm publish\n        env:\n          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}\n"
	for _, c := range []struct{ name, wf, want string }{
		{"incident", incident, tag.Fail},
		{"credentials_json", gcp, tag.Fail},
		{"OIDC", oidc, tag.Pass},
		{"no cloud access", plain, tag.Pass},
	} {
		t.Run(c.name, func(t *testing.T) {
			o := runFiles(t, id, writeRepo(t, "r", map[string]string{".github/workflows/deploy.yml": c.wf}))
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
			if c.want == tag.Fail && !strings.Contains(o.Reason, ".github/workflows/deploy.yml") {
				t.Fatalf("reason: %s", o.Reason)
			}
		})
	}
	if o := runFiles(t, id, writeRepo(t, "r", map[string]string{"a": "x"})); o.Verdict != tag.NA {
		t.Errorf("no workflows: got %s", o.Verdict)
	}
}

func TestTerraformDrill(t *testing.T) {
	cases := []struct {
		name, tf, want string
	}{
		{"private", `resource "aws_s3_bucket" "a" { bucket = "x" }`, tag.Pass},
		{"public acl inline", `resource "aws_s3_bucket" "a" { acl = "public-read" }`, tag.Fail},
		{"public acl resource", `resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket_acl" "b" {
  bucket = aws_s3_bucket.a.id
  acl    = "public-read"
}`, tag.Fail},
		{"public policy", `resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket_policy" "b" {
  bucket = aws_s3_bucket.a.id
  policy = jsonencode({ Statement = [{ Principal = "*", Effect = "Allow" }] })
}`, tag.Fail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := runFiles(t, "doors/no-public-buckets-in-terraform", writeRepo(t, "r", map[string]string{"main.tf": c.tf}))
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
		})
	}
	if o := runFiles(t, "doors/no-public-buckets-in-terraform", writeRepo(t, "r", map[string]string{"a": "x"})); o.Verdict != tag.NA {
		t.Fatalf("got %s", o.Verdict)
	}
}

func TestTarballReader(t *testing.T) {
	// Exercised through the same scanning path as a local checkout in the GitHub
	// connector's tests; here we only check a bad archive is an error.
	if _, err := files.ReadTarball(strings.NewReader("not a tarball")); err == nil {
		t.Fatal("a bad tarball must be an error")
	}
}

// fileRun runs one file-backed connector drill.
func fileRun(t *testing.T, id string, conn connector.Connector, cfg func(*config.Config), dirFiles map[string]string) *run.Outcome {
	t.Helper()
	root := writeRepo(t, "proj", dirFiles)
	p := &config.Project{Dir: filepath.Join(root, ".firedrill")}
	cfg(&p.Config)
	c := run.Config{Project: p, Drills: []*drill.Drill{drillOf(t, id)}, Connectors: []connector.Connector{configsrc.New(), conn},
		Scope:  connector.Scope{Project: p, Now: now, Log: &connector.CallLog{}, Hasher: graph.NewHasher("s")},
		Stream: "local", Records: t.TempDir(), WriteRecords: true}
	res, err := run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) == 0 {
		return &run.Outcome{Verdict: tag.Skip}
	}
	return res.Outcomes[0]
}

func TestSemgrep(t *testing.T) {
	set := func(c *config.Config) { c.Semgrep.Results = "s.json" }
	check := func(body, want string) {
		t.Helper()
		if o := fileRun(t, "code/rules-clean", semgrep.New(), set, map[string]string{"s.json": body}); o.Verdict != want {
			t.Errorf("got %s (%s), want %s", o.Verdict, o.Reason, want)
		}
	}
	check(`{"results":[]}`, tag.Pass)
	check(`{"results":[{"check_id":"r","path":"a.go","start":{"line":3},"extra":{"severity":"ERROR"}}]}`, tag.Fail)
	check(`{"results":[{"check_id":"r","path":"a.go","start":{"line":3},"extra":{"severity":"WARNING"}}]}`, tag.Pass)
	check(`{"nope":1}`, tag.Error)
	if o := fileRun(t, "code/rules-clean", semgrep.New(), set, map[string]string{}); o.Verdict != tag.Skip {
		t.Errorf("a missing results file is SKIP, got %s", o.Verdict)
	}
}

// fakeDNS is a Resolver for tests.
type fakeDNS struct {
	cname    map[string]string
	resolves map[string]bool
	txt      map[string][]string
}

func (f fakeDNS) CNAME(_ context.Context, h string) (string, error) { return f.cname[h], nil }
func (f fakeDNS) Resolves(_ context.Context, h string) (bool, error) {
	return f.resolves[h], nil
}
func (f fakeDNS) TXT(_ context.Context, h string) ([]string, error) { return f.txt[h], nil }

func TestVerifyDomain(t *testing.T) {
	h := graph.NewHasher("s")
	r := fakeDNS{txt: map[string][]string{dns.VerifyRecord("acme.com"): {dns.VerifyValue(h, "acme.com")}}}
	got := dns.VerifyDomains(context.Background(), r, h, []string{"acme.com", "other.com"})
	if len(got) != 1 || got[0] != "acme.com" {
		t.Fatal(got)
	}
	if dns.IsVerified(context.Background(), r, graph.NewHasher("different"), "acme.com") {
		t.Fatal("a different salt must not verify")
	}
}

// rewrite sends every request to a fake server, keeping the original URL for the guard.
type rewrite struct {
	server *httptest.Server
	seen   *[]string
}

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	*r.seen = append(*r.seen, req.Method+" "+req.URL.Host+req.URL.Path)
	u, _ := url.Parse(r.server.URL)
	c := req.Clone(req.Context())
	c.Header.Set("X-Original-Host", req.URL.Host)
	c.URL.Scheme, c.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(c)
}

func doorsRun(t *testing.T, id string, handler http.HandlerFunc, resolver fakeDNS) (*run.Outcome, []string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	var seen []string
	tr := rewrite{server: srv, seen: &seen}
	ct := ctlog.New()
	ct.Next, ct.Limit, ct.Burst = tr, 1000, 1000
	w := web.New()
	w.Next, w.Limit, w.Burst = tr, 1000, 1000
	d := dns.New()
	d.Resolver = resolver
	root := writeRepo(t, "proj", map[string]string{})
	p := &config.Project{Dir: filepath.Join(root, ".firedrill")}
	p.Config.Domains = []string{"acme.com"}
	p.Hosts = []config.Host{{Host: "acme.com", Owner: "@a"}, {Host: "www.acme.com", Owner: "@a"}}
	c := run.Config{Project: p, Drills: []*drill.Drill{drillOf(t, id)},
		Connectors: []connector.Connector{configsrc.New(), ct, d, w},
		Scope: connector.Scope{Project: p, Now: now, Log: &connector.CallLog{}, Hasher: graph.NewHasher("s"),
			VerifiedDomains: []string{"acme.com"}},
		Stream: "local", Records: t.TempDir(), WriteRecords: true}
	res, err := run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fatal != "" {
		t.Fatal(res.Fatal)
	}
	return res.Outcomes[0], seen
}

func site(extra http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Original-Host") == "crt.sh" {
			_, _ = io.WriteString(w, `[{"name_value":"acme.com\n*.acme.com"},{"name_value":"www.acme.com"},{"name_value":"outside.io"}]`)
			return
		}
		if r.Header.Get("User-Agent") == "" || !strings.HasPrefix(r.Header.Get("User-Agent"), "firedrill/") {
			http.Error(w, "bad agent", 400)
			return
		}
		extra(w, r)
	}
}

func TestDoorsDrills(t *testing.T) {
	notFound := site(func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	spa := site(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "<html>home</html>")
	})
	swagger := site(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"swagger":"2.0"}`)
			return
		}
		http.NotFound(w, nil)
	})
	maps := site(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<script src="/app.js"></script><script src="https://cdn.other.io/x.js"></script>`)
		case "/app.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = io.WriteString(w, strings.Repeat("a", 8000)+"\n//# sourceMappingURL=app.js.map\n")
		case "/app.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, nil)
		}
	})
	headerMaps := site(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<script src="app.js"></script>`)
		case "/app.js":
			w.Header().Set("SourceMap", "/maps/app.map")
			_, _ = io.WriteString(w, "x")
		case "/maps/app.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{}`)
		default:
			http.NotFound(w, nil)
		}
	})
	cleanBundle := site(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, `<script src="/app.js"></script>`)
		case "/app.js":
			_, _ = io.WriteString(w, "code")
		default:
			http.NotFound(w, nil)
		}
	})
	empty := fakeDNS{}

	check := func(id string, h http.HandlerFunc, r fakeDNS, want string) []string {
		t.Helper()
		o, seen := doorsRun(t, id, h, r)
		if o.Verdict != want {
			t.Errorf("%s: got %s (%s), want %s", id, o.Verdict, o.Reason, want)
		}
		return seen
	}
	check("doors/no-public-api-docs", notFound, empty, tag.Pass)
	check("doors/no-public-api-docs", spa, empty, tag.Pass)
	check("doors/no-public-api-docs", swagger, empty, tag.Fail)
	check("doors/no-public-source-maps", cleanBundle, empty, tag.Pass)
	seen := check("doors/no-public-source-maps", maps, empty, tag.Fail)
	check("doors/no-public-source-maps", headerMaps, empty, tag.Fail)
	check("doors/no-public-source-maps", notFound, empty, tag.NA)
	for _, s := range seen {
		if strings.Contains(s, "outside.io") || strings.Contains(s, "cdn.other.io") {
			t.Errorf("requested a host outside the verified domain: %s", s)
		}
		if !strings.HasPrefix(s, "GET ") {
			t.Errorf("not a GET: %s", s)
		}
	}
	check("doors/every-host-owned", notFound, empty, tag.Pass)
	check("doors/no-dangling-dns", notFound, fakeDNS{cname: map[string]string{"www.acme.com": "gone.herokuapp.test"}}, tag.Fail)
	check("doors/no-dangling-dns", notFound, fakeDNS{cname: map[string]string{"www.acme.com": "ok.test"}, resolves: map[string]bool{"ok.test": true}}, tag.Pass)
}

func TestUnownedHostFails(t *testing.T) {
	srv := site(func(w http.ResponseWriter, _ *http.Request) { http.NotFound(w, nil) })
	s := httptest.NewServer(srv)
	defer s.Close()
	var seen []string
	ct := ctlog.New()
	ct.Next, ct.Limit, ct.Burst = rewrite{server: s, seen: &seen}, 1000, 1000
	root := writeRepo(t, "p", map[string]string{})
	p := &config.Project{Dir: filepath.Join(root, ".firedrill")}
	p.Config.Domains = []string{"acme.com"}
	c := run.Config{Project: p, Drills: []*drill.Drill{drillOf(t, "doors/every-host-owned")},
		Connectors: []connector.Connector{configsrc.New(), ct},
		Scope:      connector.Scope{Project: p, Now: now, Log: &connector.CallLog{}, Hasher: graph.NewHasher("s"), VerifiedDomains: []string{"acme.com"}},
		Stream:     "local", Records: t.TempDir(), WriteRecords: true}
	res, err := run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcomes[0].Verdict != tag.Fail {
		t.Fatalf("got %s", res.Outcomes[0].Verdict)
	}
}

func TestCrtShDownGivesWarn(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) }))
	defer s.Close()
	var seen []string
	ct := ctlog.New()
	ct.Next, ct.Limit, ct.Burst = rewrite{server: s, seen: &seen}, 1000, 1000
	root := writeRepo(t, "p", map[string]string{})
	p := &config.Project{Dir: filepath.Join(root, ".firedrill")}
	p.Config.Domains = []string{"acme.com"}
	// Seed a stale cache, so the run has something to check while crt.sh is down.
	cache := filepath.Join(p.Dir, "local", "crtsh-acme.com.json")
	if err := os.MkdirAll(filepath.Dir(cache), 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]any{"time": now.AddDate(0, 0, -3), "names": []string{"a.acme.com"}})
	if err := os.WriteFile(cache, b, 0o644); err != nil {
		t.Fatal(err)
	}
	p.Hosts = []config.Host{{Host: "a.acme.com", Owner: "@a"}}
	c := run.Config{Project: p, Drills: []*drill.Drill{drillOf(t, "doors/every-host-owned")},
		Connectors: []connector.Connector{configsrc.New(), ct},
		Scope:      connector.Scope{Project: p, Now: now, Log: &connector.CallLog{}, Hasher: graph.NewHasher("s"), VerifiedDomains: []string{"acme.com"}},
		Stream:     "local", Records: t.TempDir(), WriteRecords: true}
	res, err := run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcomes[0].Verdict != tag.Warn {
		t.Fatalf("got %s: %s", res.Outcomes[0].Verdict, res.Outcomes[0].Reason)
	}
	if len(seen) != 1 {
		t.Fatalf("calls: %v", seen)
	}

	// A fresh cache means no call at all.
	seen = nil
	b, _ = json.Marshal(map[string]any{"time": now.Add(-time.Hour), "names": []string{"a.acme.com"}})
	if err := os.WriteFile(cache, b, 0o644); err != nil {
		t.Fatal(err)
	}
	c.Records = t.TempDir()
	res, err = run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcomes[0].Verdict != tag.Pass || len(seen) != 0 {
		t.Fatalf("got %s, calls %v", res.Outcomes[0].Verdict, seen)
	}
}

func TestHRCSV(t *testing.T) {
	c := hrcsv.New()
	root := writeRepo(t, "p", map[string]string{"leavers.csv": "email,leave_date\nA@x.com,2026-10-01\nb@x.com,2027-01-01\n"})
	p := &config.Project{Dir: filepath.Join(root, ".firedrill")}
	p.Config.HR.LeaversCSV = "leavers.csv"
	s := connector.Scope{Project: p, Now: now, Hasher: graph.NewHasher("s")}
	if ok, _ := c.Available(s); !ok {
		t.Fatal("file exists")
	}
	g := graph.New()
	if err := c.Collect(context.Background(), c.Collections()[0], s, g); err != nil {
		t.Fatal(err)
	}
	nodes := g.Nodes(graph.KindLeaver)
	if len(nodes) != 2 {
		t.Fatal(nodes)
	}
	for _, n := range nodes {
		if strings.Contains(string(n.ID), "@") || n.Attrs["email"] != nil {
			t.Fatalf("emails stay out of IDs and attributes: %+v", n)
		}
	}
	bad := writeRepo(t, "p", map[string]string{"leavers.csv": "email,leave_date\na@x.com,soon\n"})
	p2 := &config.Project{Dir: filepath.Join(bad, ".firedrill")}
	p2.Config.HR.LeaversCSV = "leavers.csv"
	if err := c.Collect(context.Background(), c.Collections()[0], connector.Scope{Project: p2, Now: now, Hasher: graph.NewHasher("s")}, graph.New()); err == nil {
		t.Fatal("a bad date must be an error")
	}
	p3 := &config.Project{Dir: filepath.Join(root, ".firedrill")}
	p3.Config.HR.LeaversCSV = "missing.csv"
	if ok, _ := c.Available(connector.Scope{Project: p3}); ok {
		t.Fatal("a missing file gives SKIP")
	}
}

func TestDrillReadingAConfigFileCannotStoreARawSecret(t *testing.T) {
	yaml := `firedrill: v0
id: custom/config-rule
safeguard: "The app config names a password."
severity: low
for_each: repos
fetch:
  app: { fact: files.yaml, args: { path: app.yaml } }
pass_when:
  - app.db.password == "nope"
`
	d, issues := drill.Load("custom", []byte(yaml))
	if drill.HasErrors(issues) {
		t.Fatal(issues)
	}
	raw := "Zx8mQ2pL9vT4rW7yB1nC6dF3"
	root := writeRepo(t, "r", map[string]string{"app.yaml": "db:\n  password: " + raw + "\n  host: localhost\n"})
	p := &config.Project{Dir: filepath.Join(root, ".firedrill")}
	records := t.TempDir()
	c := run.Config{Project: p, Drills: []*drill.Drill{d}, Connectors: []connector.Connector{configsrc.New(), files.New()},
		Scope:  connector.Scope{Project: p, Now: now, Log: &connector.CallLog{}, Hasher: graph.NewHasher("s"), Paths: []string{root}},
		Stream: "local", Records: records, WriteRecords: true}
	res, err := run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcomes[0].Verdict != tag.Fail {
		t.Fatalf("got %s: %s", res.Outcomes[0].Verdict, res.Outcomes[0].Reason)
	}
	_ = filepath.WalkDir(records, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), raw) {
			t.Errorf("%s holds the raw secret", p)
		}
		return nil
	})
	h, _ := tag.Store{Root: records}.History(d.ID, "r")
	if len(h) != 1 || len(h[0].Header.ScannerNotes) == 0 {
		t.Fatalf("the tag must carry a scanner note: %+v", h[0].Header)
	}
}

func TestWebOverLimitGivesWarn(t *testing.T) {
	var scripts strings.Builder
	for i := range 30 {
		fmt.Fprintf(&scripts, `<script src="/b%d.js"></script>`, i)
	}
	h := site(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, scripts.String())
			return
		}
		if strings.HasSuffix(r.URL.Path, ".js") {
			_, _ = io.WriteString(w, "code")
			return
		}
		http.NotFound(w, nil)
	})
	o, seen := doorsRun(t, "doors/no-public-source-maps", h, fakeDNS{})
	if o.Verdict != tag.Warn || !strings.Contains(o.Reason, "over the limit") {
		t.Fatalf("got %s: %s", o.Verdict, o.Reason)
	}
	perHost := map[string]int{}
	for _, s := range seen {
		// The source-map drill's own requests: home pages and bundles. API doc
		// paths belong to the other drill, which has its own budget.
		if !strings.Contains(s, "crt.sh") && !strings.HasSuffix(s, "/env.js") && (strings.HasSuffix(s, ".js") || strings.HasSuffix(s, ".com/")) {
			perHost[strings.SplitN(strings.TrimPrefix(s, "GET "), "/", 2)[0]]++
		}
	}
	for host, n := range perHost {
		if n > web.PerHostLimit {
			t.Errorf("%s got %d requests", host, n)
		}
	}
}

func TestWebRefusesUnverifiedHostAndWontFollowOffDomainRedirects(t *testing.T) {
	h := site(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			http.Redirect(w, r, "https://evil.example/steal", http.StatusFound)
			return
		}
		http.NotFound(w, nil)
	})
	o, seen := doorsRun(t, "doors/no-public-api-docs", h, fakeDNS{})
	if o.Verdict != tag.Pass {
		t.Fatalf("a redirect is not an exposed file, got %s: %s", o.Verdict, o.Reason)
	}
	for _, s := range seen {
		if strings.Contains(s, "evil.example") {
			t.Fatal("followed a redirect off the verified domain")
		}
	}
}

func TestEgressAllowlistedDrill(t *testing.T) {
	id := "agent/egress-allowlisted"
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		// UK AISI: nothing outside the agent limited where it could reach.
		{"no restriction", map[string]string{".claude/settings.json": `{"permissions":{"allow":["Bash(npm test)"]}}`}, tag.Fail},
		{"wildcard allowlist", map[string]string{".claude/settings.json": `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,"network":{"allowedDomains":["*"]}}}`}, tag.Fail},
		{"web tools restricted only", map[string]string{".claude/settings.json": `{"permissions":{"deny":["WebFetch","Bash(curl:*)"]}}`}, tag.Warn},
		{"sandbox allowlist", map[string]string{".claude/settings.json": `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,
			"network":{"allowedDomains":["github.com","*.npmjs.org"]}}}`}, tag.Pass},
		{"cursor sandbox.json", map[string]string{".cursor/sandbox.json": `{"networkPolicy":{"default":"deny","allow":["registry.npmjs.org"]}}`, ".cursorignore": ".env\n"}, tag.Pass},
		{"gemini has no host allowlist", map[string]string{".gemini/settings.json": `{"tools":{"sandbox":true}}`}, tag.Warn},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := runFiles(t, id, writeRepo(t, "r", c.files))
			if o.Verdict != c.want {
				t.Fatalf("got %s: %s", o.Verdict, o.Reason)
			}
		})
	}
	if o := runFiles(t, id, writeRepo(t, "r", map[string]string{"a": "x"})); o.Verdict != tag.NA {
		t.Fatalf("no agent config: %s %s", o.Verdict, o.Reason)
	}
}
