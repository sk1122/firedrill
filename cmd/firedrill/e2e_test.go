package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sk1122/firedrill/packs"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sk1122/firedrill/connectors/files"
)

var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "firedrill-e2e")
	if err != nil {
		panic(err)
	}
	binary = filepath.Join(dir, "firedrill")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		panic(fmt.Sprintf("build: %v\n%s", err, out))
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

type env struct {
	t    *testing.T
	home string
	work string
	vars []string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, home: t.TempDir(), work: t.TempDir()}
	e.vars = []string{"HOME=" + e.home, "PATH=/usr/bin:/bin", "USER=tester", "NO_COLOR=1"}
	return e
}

func (e *env) run(args ...string) (string, int) {
	e.t.Helper()
	cmd := exec.Command(binary, args...)
	cmd.Dir = e.work
	cmd.Env = e.vars
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatal(err)
	}
	return string(out), code
}

func (e *env) mustRun(args ...string) string {
	e.t.Helper()
	out, code := e.run(args...)
	if code != 0 {
		e.t.Fatalf("%v exited %d:\n%s", args, code, out)
	}
	return out
}

func (e *env) repo(name string, f map[string]string) string {
	e.t.Helper()
	root := filepath.Join(e.work, name)
	for rel, content := range f {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			e.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			e.t.Fatal(err)
		}
	}
	return root
}

const token = "6f1b9d2e-7c44-4a10-9e3b-2d5ac81f0e77"

func TestFromCleanMachineToFirstFailThenFixedMeansFixed(t *testing.T) {
	e := newEnv(t)
	start := time.Now()
	out := e.mustRun("init", "--yes", "--owner", "@arjun")
	if !strings.Contains(out, "24 starter drills") || !strings.Contains(out, "salt") {
		t.Fatalf("init: %s", out)
	}
	if info, err := os.Stat(filepath.Join(e.home, ".config/firedrill/salt")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("salt file: %v %v", err, info)
	}
	e.mustRun("validate")

	api := e.repo("api", map[string]string{"scripts/domains.sh": "RAILWAY_TOKEN=" + token + "\n", "README.md": "hello\n"})
	out, code := e.run("run", "--path", api)
	if code != 1 {
		t.Fatalf("a newly open critical safeguard exits 1, got %d:\n%s", code, out)
	}
	if !strings.Contains(out, "FAIL") || !strings.Contains(out, "agent/no-prod-secrets-in-agent-reach") || !strings.Contains(out, "scripts/domains.sh") {
		t.Fatalf("no first FAIL:\n%s", out)
	}
	if !strings.Contains(out, "drills waiting") || !strings.Contains(out, "Needs attention: 1 newly open") {
		t.Fatalf("summary lines missing:\n%s", out)
	}
	if time.Since(start) > 5*time.Minute {
		t.Fatalf("took %s", time.Since(start))
	}
	assertNoRawToken(t, e.work)

	// A second run with the leak still there is not new, so CI stays green.
	out, code = e.run("run", "--path", api)
	if code != 0 || !strings.Contains(out, "0 newly open") {
		t.Fatalf("known failure exit %d:\n%s", code, out)
	}
	if _, code := e.run("run", "--path", api, "--fail-on", "open"); code != 1 {
		t.Fatal("--fail-on open exits 1 while open")
	}

	// A ticket saying fixed changes nothing. Verify says it is still open.
	out, code = e.run("verify", "agent/no-prod-secrets-in-agent-reach", "--path", api)
	if code != 1 || !strings.Contains(out, "OPEN") {
		t.Fatalf("verify while broken: %d\n%s", code, out)
	}

	if err := os.WriteFile(filepath.Join(api, "scripts/domains.sh"), []byte("RAILWAY_TOKEN=${RAILWAY_TOKEN}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = e.run("verify", "agent/no-prod-secrets-in-agent-reach", "--path", api)
	if code != 0 || !strings.Contains(out, "CLOSED") {
		t.Fatalf("verify after the fix: %d\n%s", code, out)
	}

	out = e.mustRun("list")
	if !regexp.MustCompile(`CLOSED\s+PASS\s+agent/no-prod-secrets-in-agent-reach`).MatchString(out) {
		t.Fatalf("list:\n%s", out)
	}
	if strings.Contains(out, "CHAIN BROKEN") {
		t.Fatalf("list:\n%s", out)
	}
	out = e.mustRun("explain", "agent/no-prod-secrets-in-agent-reach")
	if !strings.Contains(out, "It passes when") || !strings.Contains(out, "CLOSED") {
		t.Fatalf("explain:\n%s", out)
	}

	out = e.mustRun("report")
	board := filepath.Join(e.work, ".firedrill/report/index.html")
	html, err := os.ReadFile(board)
	if err != nil {
		t.Fatal(err)
	}
	s := string(html)
	for _, want := range []string{"agent/no-prod-secrets-in-agent-reach", "font/woff2;base64", "No owner"} {
		if !strings.Contains(s, want) {
			t.Errorf("board missing %q", want)
		}
	}
	if regexp.MustCompile(`(src|href)="https?://`).MatchString(s) {
		t.Error("the board must load nothing from the network")
	}
	if strings.Contains(s, token) {
		t.Error("the board holds a raw secret")
	}
	if !strings.Contains(out, "index.html") {
		t.Fatal(out)
	}
	if _, err := os.Stat(filepath.Join(e.work, ".firedrill/local/calls.jsonl")); err != nil {
		t.Errorf("call log: %v", err)
	}
}

func assertNoRawToken(t *testing.T, root string) {
	t.Helper()
	dir := filepath.Join(root, ".firedrill/local")
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		if strings.Contains(string(b), token) {
			t.Errorf("%s holds the raw token", p)
		}
		return nil
	})
}

func TestTamperedRecordIsReported(t *testing.T) {
	e := newEnv(t)
	e.mustRun("init", "--yes")
	api := e.repo("api", map[string]string{"s.sh": "RAILWAY_TOKEN=" + token + "\n"})
	e.run("run", "--path", api)
	var tagFile string
	_ = filepath.WalkDir(filepath.Join(e.work, ".firedrill/local/tags/agent/no-prod-secrets-in-agent-reach"), func(p string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() {
			tagFile = p
		}
		return nil
	})
	b, _ := os.ReadFile(tagFile)
	edited := strings.Replace(string(b), "scripts", "elsewhere", 1) + ""
	var doc map[string]any
	if err := json.Unmarshal([]byte(edited), &doc); err != nil {
		t.Fatal(err)
	}
	doc["evidence"].(map[string]any)["read"] = []string{"forged"}
	nb, _ := json.Marshal(doc)
	if err := os.WriteFile(tagFile, nb, 0o644); err != nil {
		t.Fatal(err)
	}
	if out := e.mustRun("list"); !strings.Contains(out, "CHAIN BROKEN") {
		t.Fatalf("list must report an edited tag:\n%s", out)
	}
}

func TestDryRunMakesNoCallsAndWritesNothing(t *testing.T) {
	e := newEnv(t)
	e.mustRun("init", "--yes")
	api := e.repo("api", map[string]string{"s.sh": "x\n"})
	out := e.mustRun("run", "--dry-run", "--path", api)
	if !strings.Contains(out, "None were made") {
		t.Fatal(out)
	}
	if _, err := os.Stat(filepath.Join(e.work, ".firedrill/local/tags")); err == nil {
		t.Fatal("a dry run must write no records")
	}
}

func TestCIWithoutSaltStops(t *testing.T) {
	e := newEnv(t)
	e.vars = append(e.vars, "FIREDRILL_SALT=abc")
	e.mustRun("init", "--yes")
	e.vars = []string{"HOME=" + e.home, "PATH=/usr/bin:/bin", "GITHUB_ACTIONS=true"}
	out, code := e.run("run")
	if code != 2 || !strings.Contains(out, "FIREDRILL_SALT") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestPublicRepoInCIGetsCountsOnly(t *testing.T) {
	e := newEnv(t)
	e.vars = append(e.vars, "FIREDRILL_SALT=abc")
	e.mustRun("init", "--yes")
	api := e.repo("api", map[string]string{"s.sh": "RAILWAY_TOKEN=" + token + "\n"})
	payload := filepath.Join(e.work, "event.json")
	if err := os.WriteFile(payload, []byte(`{"repository":{"private":false}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e.vars = append(e.vars, "GITHUB_ACTIONS=true", "GITHUB_EVENT_PATH="+payload)
	out, _ := e.run("run", "--path", api, "--records", "records", "--json", "r.json")
	if strings.Contains(out, "s.sh") || strings.Contains(out, "agent/") {
		t.Fatalf("a public repo prints only counts:\n%s", out)
	}
	if !strings.Contains(out, "FAIL 1") && !strings.Contains(out, "FAIL ") {
		t.Fatal(out)
	}
	for _, p := range []string{"records", "r.json"} {
		if _, err := os.Stat(filepath.Join(e.work, p)); err == nil {
			t.Errorf("%s must not exist in a public repo", p)
		}
	}
	// A private repo in CI writes the canonical stream.
	if err := os.WriteFile(payload, []byte(`{"repository":{"private":true}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	e.run("run", "--path", api, "--records", "records", "--json", "r.json")
	if _, err := os.Stat(filepath.Join(e.work, "records/tags")); err != nil {
		t.Fatalf("private repo records: %v", err)
	}
	var j struct {
		Stream    string           `json:"stream"`
		NewlyOpen []map[string]any `json:"newly_open"`
	}
	b, err := os.ReadFile(filepath.Join(e.work, "r.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	if j.Stream != "ci" || len(j.NewlyOpen) != 1 {
		t.Fatalf("%+v", j)
	}
	out = e.mustRun("report", "--summary", "r.json")
	if !strings.Contains(out, "Newly open") || strings.Contains(out, "s.sh") {
		t.Fatalf("the summary carries no evidence:\n%s", out)
	}
}

func TestWaiverKeepsFailOutOfExitCode(t *testing.T) {
	e := newEnv(t)
	e.mustRun("init", "--yes")
	api := e.repo("api", map[string]string{"s.sh": "RAILWAY_TOKEN=" + token + "\n"})
	waivers := "- drill: agent/no-prod-secrets-in-agent-reach\n  reason: r\n  approved_by: \"@a\"\n  expires: 2099-01-01\n"
	if err := os.WriteFile(filepath.Join(e.work, ".firedrill/waivers.yaml"), []byte(waivers), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := e.run("run", "--path", api, "--drill", "agent/no-prod-secrets-in-agent-reach")
	if code != 0 || !strings.Contains(out, "FAIL") || !strings.Contains(out, "waived") {
		t.Fatalf("%d\n%s", code, out)
	}
	// The waiver expires: the safeguard counts as newly open.
	expired := strings.Replace(waivers, "2099-01-01", "2020-01-01", 1)
	if err := os.WriteFile(filepath.Join(e.work, ".firedrill/waivers.yaml"), []byte(expired), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = e.run("run", "--path", api, "--drill", "agent/no-prod-secrets-in-agent-reach")
	if code != 1 || !strings.Contains(out, "1 newly open") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestValidateRejectsBrokenFile(t *testing.T) {
	e := newEnv(t)
	bad := filepath.Join(e.work, "bad.yaml")
	if err := os.WriteFile(bad, []byte("firedrill: v9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := e.run("validate", bad)
	if code != 1 || !strings.Contains(out, "unsupported format version") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	e := newEnv(t)
	e.mustRun("init", "--yes")
	if out, code := e.run("init", "--yes"); code == 0 || !strings.Contains(out, "already exists") {
		t.Fatalf("%d %s", code, out)
	}
}

func TestNoConfigGivesClearMessage(t *testing.T) {
	e := newEnv(t)
	if out, code := e.run("run"); code != 2 || !strings.Contains(out, "firedrill init") {
		t.Fatalf("%d %s", code, out)
	}
}

// issueScript pulls the issue step out of the shipped workflow.
func issueScript(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../docs/firedrill-workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string `yaml:"name"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatal(err)
	}
	for _, s := range wf.Jobs["drill"].Steps {
		if s.Name == "Open and close issues" {
			return s.Run
		}
	}
	t.Fatal("no issue step")
	return ""
}

func TestShippedWorkflowFollowsItsOwnRules(t *testing.T) {
	data, err := os.ReadFile("../../docs/firedrill-workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	w, err := files.ParseWorkflow("firedrill.yml", data)
	if err != nil {
		t.Fatal(err)
	}
	if w.Permissions != "read" || len(w.Unpinned) != 0 || w.PRTarget {
		t.Fatalf("%+v", w)
	}
	ci, _ := os.ReadFile("../../.github/workflows/ci.yml")
	if w, err := files.ParseWorkflow("ci.yml", ci); err != nil || w.Permissions != "read" || len(w.Unpinned) != 0 {
		t.Fatalf("%v %+v", err, w)
	}
}

func TestIssueStepOpensAssignsAndCloses(t *testing.T) {
	if _, err := exec.LookPath("jq"); err != nil {
		t.Skip("jq is not installed")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "gh.log")
	// A fake gh that records calls, refuses one assignee, and knows one open issue.
	fake := `#!/bin/bash
echo "$*" >> "` + log + `"
if [ "$1 $2" = "issue list" ]; then
  if [[ "$*" == *'title == "Firedrill: code/rules-clean on global"'* ]]; then echo 42; fi
  if [[ "$*" == *'title == "Firedrill: doors/x on old.acme.com"'* ]]; then echo 43; fi
  exit 0
fi
if [ "$1 $2" = "issue create" ] && [[ "$*" == *"--assignee noaccess"* ]]; then exit 1; fi
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	result := map[string]any{
		"default_owner": "@lead",
		"newly_open": []any{
			map[string]any{"drill": "change/no-solo-ship", "target": "acme/api", "owner": "@arjun", "failing_conditions": []string{"rules.bypass != \"allowed\""}, "fix": "Turn off bypass."},
			map[string]any{"drill": "access/admins-use-mfa", "target": "", "owner": "@noaccess"},
		},
		"newly_closed": []any{map[string]any{"drill": "code/rules-clean", "target": ""}},
		"retired":      []any{map[string]any{"drill": "doors/x", "target": "old.acme.com", "retired": "shut down"}},
	}
	b, _ := json.Marshal(result)
	if err := os.WriteFile(filepath.Join(dir, "result.json"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-e", "-c", issueScript(t))
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin", "RUN_URL=https://example.test/run/1"}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	logged, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	s := string(logged)
	for _, want := range []string{
		"issue create --title Firedrill: change/no-solo-ship on acme/api",
		"--assignee arjun",
		"--assignee noaccess",
		"--assignee lead",
		"who has no access to this repo",
		"issue close 42",
		"Closed by a passing run",
		"issue close 43",
		"Target retired: shut down",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("gh calls missing %q:\n%s", want, s)
		}
	}
}

// hubCopy writes a hub folder seeded with the starter drills and fixtures.
func (e *env) hubCopy() string {
	e.t.Helper()
	root := filepath.Join(e.work, "hub")
	err := fs.WalkDir(packs.FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		b, _ := packs.FS.ReadFile(p)
		dst := filepath.Join(root, "drills", filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "hub.yaml"), []byte("name: t\nofficial: [change, access, agent, doors, code, gcp]\n"), 0o644); err != nil {
		e.t.Fatal(err)
	}
	return root
}

func editFile(t *testing.T, path, old, repl string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s lacks %q", path, old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), old, repl, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHubInstallUpdateAndRefusals(t *testing.T) {
	e := newEnv(t)
	e.vars = append(e.vars, "FIREDRILL_SALT="+strings.Repeat("a", 64))
	h := e.hubCopy()
	e.mustRun("init", "--yes", "--owner", "@me")
	if out := e.mustRun("hub", "--from", h, "index", h, "--out", filepath.Join(e.work, "index.json")); !strings.Contains(out, "24 drills, 83 test cases, 0 with problems") {
		t.Fatal(out)
	}
	if out := e.mustRun("test", filepath.Join(h, "drills")); !strings.Contains(out, "0 failing, 0 drills with problems") {
		t.Fatal(out)
	}
	if out := e.mustRun("hub", "--from", h, "update", "--yes"); !strings.Contains(out, "0 replaced, 0 added, 24 current") {
		t.Fatalf("starters from init are recorded as current:\n%s", out)
	}
	local := filepath.Join(e.work, ".firedrill", "drills")
	editFile(t, filepath.Join(h, "drills", "change", "actions-pinned.drill.yaml"), "severity: medium", "severity: high")
	editFile(t, filepath.Join(h, "drills", "change", "no-solo-ship.drill.yaml"), "severity: critical", "severity: high")
	editFile(t, filepath.Join(local, "change", "no-solo-ship.drill.yaml"), "severity: critical", "severity: medium")
	out := e.mustRun("hub", "--from", h, "update", "--yes")
	if !strings.Contains(out, "- severity: medium\n+ severity: high") || !strings.Contains(out, "no-solo-ship: you edited it") ||
		!strings.Contains(out, "1 replaced, 0 added, 22 current, 1 left alone") {
		t.Fatalf("a hub change is shown and applied; an edited drill is left alone:\n%s", out)
	}
	if b, _ := os.ReadFile(filepath.Join(local, "change", "no-solo-ship.drill.yaml")); !strings.Contains(string(b), "severity: medium") {
		t.Fatal("the edited drill must be untouched")
	}
	// A new official drill is offered by update; a too-new one is refused by add.
	src, _ := os.ReadFile(filepath.Join(h, "drills", "change", "no-force-push-main.drill.yaml"))
	test, _ := os.ReadFile(filepath.Join(h, "drills", "change", "no-force-push-main.test.yaml"))
	newDrill := strings.ReplaceAll(string(src), "change/no-force-push-main", "change/new-one")
	_ = os.WriteFile(filepath.Join(h, "drills", "change", "new-one.drill.yaml"), []byte(newDrill), 0o644)
	_ = os.WriteFile(filepath.Join(h, "drills", "change", "new-one.test.yaml"), []byte(strings.ReplaceAll(string(test), "change/no-force-push-main", "change/new-one")), 0o644)
	if out := e.mustRun("hub", "--from", h, "update", "--yes"); !strings.Contains(out, "New official drill change/new-one") || !strings.Contains(out, "1 added") {
		t.Fatal(out)
	}
	tooNew := strings.Replace(strings.ReplaceAll(newDrill, "change/new-one", "change/too-new"), "severity:", "requires: \">= 99.0.0\"\nseverity:", 1)
	_ = os.WriteFile(filepath.Join(h, "drills", "change", "too-new.drill.yaml"), []byte(tooNew), 0o644)
	_ = os.WriteFile(filepath.Join(h, "drills", "change", "too-new.test.yaml"), []byte(strings.ReplaceAll(string(test), "change/no-force-push-main", "change/too-new")), 0o644)
	if out, code := e.run("hub", "--from", h, "add", "change/too-new"); code == 0 || !strings.Contains(out, "needs Firedrill 99.0.0 or newer") {
		t.Fatalf("%d %s", code, out)
	}
	if out, code := e.run("hub", "--from", h, "add", "nope/none"); code == 0 || !strings.Contains(out, "not in the hub") {
		t.Fatalf("%d %s", code, out)
	}
	lock, _ := os.ReadFile(filepath.Join(e.work, ".firedrill", "hub.lock"))
	if !strings.Contains(string(lock), "change/new-one:") || strings.Contains(string(lock), "change/too-new") {
		t.Fatalf("lock:\n%s", lock)
	}
	if out := e.mustRun("run", "--path", "."); !strings.Contains(out, "drills ran") {
		t.Fatal(out)
	}
}
