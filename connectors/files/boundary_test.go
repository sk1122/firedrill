package files

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

const claudeJob = `on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
%s      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
`

const harden = `      - uses: step-security/harden-runner@0123456789abcdef0123456789abcdef01234567
        with:
          egress-policy: %s
          allowed-endpoints: >
            api.anthropic.com:443
            github.com:443
`

func jobsOf(t *testing.T, body string) []AgentJob {
	t.Helper()
	w, err := ParseWorkflow(".github/workflows/claude.yml", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return AgentJobs(".github/workflows/claude.yml", []byte(body), w)
}

func TestAgentJobs(t *testing.T) {
	sprintf := func(f string, a ...any) string { return fmtSprintf(f, a...) }
	cases := []struct {
		name             string
		body             string
		jobs             int
		bounded, exposed bool
		endpoints        int
	}{
		{"agent action, secret, no control", sprintf(claudeJob, ""), 1, false, true, 0},
		{"harden-runner block first", sprintf(claudeJob, sprintf(harden, "block")), 1, true, false, 2},
		{"harden-runner audit only logs", sprintf(claudeJob, sprintf(harden, "audit")), 1, false, true, 0},
		{"harden-runner default is block", sprintf(claudeJob, "      - uses: step-security/harden-runner@0123456789abcdef0123456789abcdef01234567\n"), 1, true, false, 0},
		{"harden-runner not first", sprintf(claudeJob, "      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567\n"+sprintf(harden, "block")), 1, false, true, 0},
		{"no agent", "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go test ./...\n", 0, false, false, 0},
		{"claude cli in a run step, read token, no secret", "on: push\npermissions: read-all\njobs:\n  fix:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          npm ci\n          claude -p \"fix the lint\"\n", 1, false, false, 0},
		{"codex through npx with write token", "on: push\npermissions:\n  contents: write\njobs:\n  fix:\n    runs-on: ubuntu-latest\n    steps:\n      - run: npx -y @openai/codex@1.2.3 exec \"fix\"\n", 1, false, true, 0},
		{"container with no network", "on: push\njobs:\n  fix:\n    runs-on: ubuntu-latest\n    container:\n      image: node:22\n      options: --network none\n    steps:\n      - run: aider --yes\n", 1, true, false, 0},
		{"harden-runner in a container job does not work", "on: push\njobs:\n  fix:\n    runs-on: ubuntu-latest\n    container: node:22\n    steps:\n" +
			sprintf(harden, "block") + "      - run: gemini -p hi\n", 1, false, true, 0},
	}
	for _, c := range cases {
		jobs := jobsOf(t, c.body)
		if len(jobs) != c.jobs {
			t.Errorf("%s: %d jobs", c.name, len(jobs))
			continue
		}
		if c.jobs == 0 {
			continue
		}
		j := jobs[0]
		if j.Bounded != c.bounded || j.Exposed != c.exposed || j.AllowedEndpoints != c.endpoints {
			t.Errorf("%s: %+v", c.name, j)
		}
	}
}

func TestDevcontainer(t *testing.T) {
	// The reference container's pattern, with comments and a trailing comma.
	firewall := `{
  // Claude Code's reference container
  "runArgs": ["--cap-add=NET_ADMIN", "--cap-add=NET_RAW"],
  "remoteUser": "node",
  "postStartCommand": "sudo /usr/local/bin/init-firewall.sh",
}`
	cases := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"none", map[string]string{"README.md": "x"}, DevNone},
		{"firewall", map[string]string{".devcontainer/devcontainer.json": firewall}, DevFirewall},
		{"script without NET_ADMIN cannot set rules", map[string]string{".devcontainer/devcontainer.json": `{"postCreateCommand":"sudo init-firewall.sh"}`}, DevOpen},
		{"no network", map[string]string{".devcontainer/devcontainer.json": `{"runArgs":["--network=none"]}`}, DevNoNetwork},
		{"open", map[string]string{".devcontainer/devcontainer.json": `{"image":"node:22"}`}, DevOpen},
		{"the worst of two", map[string]string{".devcontainer/devcontainer.json": firewall, ".devcontainer/py/devcontainer.json": `{"image":"python"}`}, DevOpen},
		{"compose service with no network", map[string]string{
			".devcontainer/devcontainer.json": `{"dockerComposeFile":"compose.yml","service":"agent"}`,
			".devcontainer/compose.yml":       "services:\n  agent:\n    image: node\n    network_mode: none\n"}, DevNoNetwork},
		{"compose service on an internal network", map[string]string{
			".devcontainer/devcontainer.json": `{"dockerComposeFile":["../docker-compose.yml"],"service":"agent"}`,
			"docker-compose.yml":              "services:\n  agent:\n    networks: [sealed]\nnetworks:\n  sealed:\n    internal: true\n"}, DevNoNetwork},
		{"compose service on the default network", map[string]string{
			".devcontainer/devcontainer.json": `{"dockerComposeFile":"compose.yml","service":"agent"}`,
			".devcontainer/compose.yml":       "services:\n  agent:\n    image: node\n"}, DevOpen},
	}
	for _, c := range cases {
		var all []File
		for p, b := range c.files {
			all = append(all, File{Path: p, Data: []byte(b)})
		}
		if got := Devcontainer(all); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestManagedSettings(t *testing.T) {
	dir := t.TempDir()
	w := func(name, body string) string {
		p := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := w("managed-settings.json", `{"sandbox":{"enabled":true,"network":{"allowedDomains":["github.com"]}}}`)
	if got := Managed([]string{filepath.Join(dir, "missing.json")}); got != ManagedAbsent {
		t.Fatal(got)
	}
	if got := Managed([]string{base}); got != ManagedPartial {
		t.Fatalf("projects may still add domains: %s", got)
	}
	lock := w("managed-settings.d/10-lock.json", `{"sandbox":{"network":{"allowManagedDomainsOnly":true,"allowedDomains":["registry.npmjs.org"]}}}`)
	if got := Managed([]string{base, lock}); got != ManagedAllowlist {
		t.Fatal(got)
	}
	wild := w("managed-settings.d/20-wild.json", `{"sandbox":{"network":{"allowedDomains":["*"]}}}`)
	if got := Managed([]string{base, lock, wild}); got != ManagedPartial {
		t.Fatal(got)
	}
	off := w("off.json", `{"permissions":{}}`)
	if got := Managed([]string{off}); got != ManagedNone {
		t.Fatal(got)
	}
}

func TestBoundary(t *testing.T) {
	b, o := AgentJob{Bounded: true}, AgentJob{}
	for _, c := range []struct {
		jobs    []AgentJob
		local   bool
		dev     string
		managed string
		want    string
	}{
		{nil, false, DevNone, ManagedNotRead, BoundaryUnknown},
		{nil, true, DevNone, ManagedNotRead, BoundaryUnknown},
		{nil, true, DevOpen, ManagedNotRead, BoundaryNone},
		{nil, true, DevFirewall, ManagedNotRead, BoundaryEnforced},
		{nil, true, DevNone, ManagedAllowlist, BoundaryEnforced},
		{nil, true, DevNone, ManagedAbsent, BoundaryNone},
		{[]AgentJob{b}, false, DevNone, ManagedNotRead, BoundaryEnforced},
		{[]AgentJob{b, o}, false, DevNone, ManagedNotRead, BoundaryPartial},
		{[]AgentJob{o}, false, DevNone, ManagedNotRead, BoundaryNone},
		{[]AgentJob{b}, true, DevNone, ManagedNotRead, BoundaryPartial},
		{[]AgentJob{b}, true, DevNoNetwork, ManagedNotRead, BoundaryEnforced},
	} {
		if got := Boundary(c.jobs, c.local, c.dev, c.managed); got != c.want {
			t.Errorf("%+v: %s, want %s", c, got, c.want)
		}
	}
}

func TestScanRepoWritesEgressBoundary(t *testing.T) {
	root := writeTree(t, map[string]string{
		".claude/settings.json":           `{"sandbox":{"enabled":true,"allowUnsandboxedCommands":false,"network":{"allowedDomains":["github.com"]}}}`,
		".devcontainer/devcontainer.json": `{"runArgs":["--cap-add=NET_ADMIN"],"postStartCommand":"sudo /usr/local/bin/init-firewall.sh"}`,
		".github/workflows/claude.yml":    fmtSprintf(claudeJob, ""),
	})
	all, err := WalkLocal(root)
	if err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(t.TempDir(), "managed-settings.json")
	_ = os.WriteFile(managed, []byte(`{"sandbox":{"enabled":true,"network":{"allowManagedDomainsOnly":true,"allowedDomains":["github.com"]}}}`), 0o644)
	was := ManagedSettingsPaths
	ManagedSettingsPaths = func() []string { return []string{managed} }
	t.Cleanup(func() { ManagedSettingsPaths = was })
	for _, home := range []bool{false, true} {
		g := graph.New()
		s := connector.Scope{Project: &config.Project{}, Hasher: graph.NewHasher("salt"), Now: time.Unix(0, 0), IncludeHome: home, HomeDir: t.TempDir()}
		if err := scanRepo(connector.RepoTarget{Name: "acme/api", Path: root}, all, s, g); err != nil {
			t.Fatal(err)
		}
		n, ok := g.Get("egress-boundary:acme/api")
		if !ok {
			t.Fatal("no boundary node")
		}
		want := map[string]any{"ci_agent_jobs": []any{".github/workflows/claude.yml#review"}, "ci_agent_jobs_bounded": []any{},
			"ci_agent_jobs_exposed": []any{".github/workflows/claude.yml#review"}, "devcontainer": DevFirewall, "managed": ManagedNotRead,
			"agents_configured": true, "boundary": BoundaryPartial, "repo": "acme/api"}
		if home {
			want["managed"] = ManagedAllowlist
		}
		if !reflect.DeepEqual(n.Attrs, want) {
			t.Errorf("home %v:\n%#v\nwant\n%#v", home, n.Attrs, want)
		}
		if scan, ok := g.Get(graph.ScanID("egress_boundary", "acme/api")); !ok || scan.Attrs["inspected"] != int64(2) {
			t.Errorf("one CI job and the local agents: %+v", scan.Attrs)
		}
	}
}

func fmtSprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }
