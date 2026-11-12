package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/config"
)

// consentProject writes a project whose config lists GitHub repos, with a git
// remote on GitHub and a fake gh CLI that notes when it is asked for a token.
func consentProject(t *testing.T) (ghCalled string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".firedrill")
	if err := os.MkdirAll(filepath.Join(dir, "drills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("github: {org: acme, repos: [api]}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitCfg := "[remote \"origin\"]\n\turl = https://github.com/acme/api.git\n"
	if err := os.WriteFile(filepath.Join(root, ".git", "config"), []byte(gitCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	ghCalled = filepath.Join(bin, "called")
	script := "#!/bin/sh\ntouch " + ghCalled + "\necho ambient-gh-token\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	old := projectDir
	projectDir = dir
	t.Cleanup(func() { projectDir = old })
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("FIREDRILL_SALT", strings.Repeat("a", 64))
	t.Setenv("FIREDRILL_GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_ACTIONS", "")
	return ghCalled
}

func TestPrepareReadsNoGitHubTokenBeforeConnect(t *testing.T) {
	ghCalled := consentProject(t)
	rc, err := prepare(context.Background(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if rc.scope.Token != "" || rc.scope.Tarball != nil {
		t.Fatal("an unconnected GitHub must get no token and no tarball reader")
	}
	if _, err := os.Stat(ghCalled); err == nil {
		t.Fatal("gh auth token must not run before connect github")
	}
	t.Setenv("FIREDRILL_GITHUB_TOKEN", "ambient-env-token")
	if rc, _ := prepare(context.Background(), nil, false); rc.scope.Token != "" {
		t.Fatal("a token in the environment is not consent either")
	}

	// connect github sees the token for its own access check.
	t.Setenv("FIREDRILL_GITHUB_TOKEN", "")
	rc, err = prepareConnecting(context.Background(), nil, false, "github")
	if err != nil {
		t.Fatal(err)
	}
	if rc.scope.Token != "ambient-gh-token" || rc.scope.Tarball == nil {
		t.Fatal("connect github uses the gh login")
	}
	// Once connect has recorded it, every run does.
	if err := config.MarkConnected(projectDir, "github"); err != nil {
		t.Fatal(err)
	}
	rc, err = prepare(context.Background(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if rc.scope.Token != "ambient-gh-token" || rc.scope.Tarball == nil {
		t.Fatal("a connected GitHub gets its token")
	}
}

func TestRecordsAllowedFailsSafeWithoutGitHub(t *testing.T) {
	consentProject(t)
	t.Setenv("FIREDRILL_GITHUB_TOKEN", "ambient-env-token")
	rc, err := prepare(context.Background(), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !recordsAllowed(context.Background(), rc.scope, false, defaultRecords()) {
		t.Fatal("the gitignored default folder takes records while visibility is unknown")
	}
	if recordsAllowed(context.Background(), rc.scope, false, filepath.Join(t.TempDir(), "records")) {
		t.Fatal("with visibility unknown, records must not go anywhere else")
	}
	if !recordsAllowed(context.Background(), rc.scope, true, filepath.Join(t.TempDir(), "records")) {
		t.Fatal("--public-ok still allows them")
	}
	if n := len(rc.scope.Log.Calls()); n != 0 {
		t.Fatalf("the visibility check made %d calls before connect github", n)
	}
}
