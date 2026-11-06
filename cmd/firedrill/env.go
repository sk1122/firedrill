package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sk1122/firedrill/connector"
	dnsconn "github.com/sk1122/firedrill/connectors/dns"
	githubconn "github.com/sk1122/firedrill/connectors/github"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
)

func inCI() bool { return os.Getenv("GITHUB_ACTIONS") == "true" }

func saltPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "firedrill", "salt")
}

// loadSalt reads the org's salt. A CI run without it stops, so secret IDs stay
// the same on every run.
func loadSalt() (string, error) {
	if v := strings.TrimSpace(os.Getenv("FIREDRILL_SALT")); v != "" {
		return v, nil
	}
	if inCI() {
		return "", errors.New("FIREDRILL_SALT is not set. Add it as a repository secret")
	}
	b, err := os.ReadFile(saltPath())
	if err != nil {
		return "", errors.New("no salt found. Run firedrill init, or set FIREDRILL_SALT to your team's value")
	}
	return strings.TrimSpace(string(b)), nil
}

// generateSalt makes 32 random bytes as hex.
func generateSalt() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// githubToken finds a token, reusing the GitHub CLI's login when present. The
// token stays in memory.
func githubToken(ctx context.Context) (token, source string) {
	for _, name := range []string{"FIREDRILL_GITHUB_TOKEN", "GH_TOKEN"} {
		if v := os.Getenv(name); v != "" {
			return v, name
		}
	}
	if path, err := exec.LookPath("gh"); err == nil {
		out, err := exec.CommandContext(ctx, path, "auth", "token").Output() // #nosec G204 -- fixed arguments
		if err == nil && strings.TrimSpace(string(out)) != "" {
			return strings.TrimSpace(string(out)), "gh auth token"
		}
	}
	return "", ""
}

// runContext is everything a command needs to run drills.
type runContext struct {
	project *config.Project
	drills  []*drill.Drill
	warns   []drill.Issue
	scope   connector.Scope
}

// prepare loads the project, its drills and the run scope.
func prepare(ctx context.Context, paths []string, includeHome bool) (*runContext, error) {
	project, err := config.Load(projectDir)
	if err != nil {
		return nil, err
	}
	drills, issues, err := drill.LoadDir(filepath.Join(projectDir, "drills"))
	if err != nil {
		return nil, err
	}
	if drill.HasErrors(issues) {
		for _, i := range issues {
			fmt.Fprintln(os.Stderr, i)
		}
		return nil, errors.New("fix the drill files above, or run firedrill validate")
	}
	salt, err := loadSalt()
	if err != nil {
		return nil, err
	}
	home, _ := os.UserHomeDir()
	token, _ := githubToken(ctx)
	hasher := graph.NewHasher(salt)
	scope := connector.Scope{
		Project: project, Hasher: hasher, Now: time.Now().UTC().Truncate(time.Second), Log: &connector.CallLog{},
		Paths: paths, IncludeHome: includeHome, HomeDir: home, Token: token, Getenv: os.Getenv,
	}
	if gh, ok := connector.Lookup("github"); ok && token != "" {
		scope.Tarball = gh.(*githubconn.Connector).Tarball(scope)
	}
	if d, ok := connector.Lookup("dns"); ok {
		scope.VerifiedDomains = dnsconn.VerifyDomains(ctx, d.(*dnsconn.Connector).Resolver, hasher, project.Config.Domains)
	}
	return &runContext{project: project, drills: drills, warns: issues, scope: scope}, nil
}

func ranBy() string {
	if inCI() {
		return fmt.Sprintf("%s/%s/actions/runs/%s", os.Getenv("GITHUB_SERVER_URL"), os.Getenv("GITHUB_REPOSITORY"), os.Getenv("GITHUB_RUN_ID"))
	}
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "local"
}

var remoteRe = regexp.MustCompile(`github\.com[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?\s*$`)

// gitRemote reads the origin remote from .git/config, running nothing.
func gitRemote(dir string) (owner, repo string) {
	b, err := os.ReadFile(filepath.Join(dir, ".git", "config"))
	if err != nil {
		return "", ""
	}
	inOrigin := false
	for _, line := range strings.Split(string(b), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "[") {
			inOrigin = l == `[remote "origin"]`
			continue
		}
		if inOrigin && strings.HasPrefix(l, "url") {
			if m := remoteRe.FindStringSubmatch(l); m != nil {
				return m[1], m[2]
			}
		}
	}
	return "", ""
}

// recordsAllowed checks the visibility of the repo a run writes into: in GitHub
// Actions from the run's event payload, which needs no extra permission; on a
// laptop through the GitHub connection. In Actions an unreadable payload writes
// nothing. On a laptop with no connection, records stay in a gitignored folder.
func recordsAllowed(ctx context.Context, s connector.Scope, publicOK bool) bool {
	if publicOK {
		return true
	}
	if inCI() {
		b, err := os.ReadFile(os.Getenv("GITHUB_EVENT_PATH"))
		if err != nil {
			return false
		}
		var ev struct {
			Repository *struct {
				Private *bool `json:"private"`
			} `json:"repository"`
		}
		if json.Unmarshal(b, &ev) != nil || ev.Repository == nil || ev.Repository.Private == nil {
			return false
		}
		return *ev.Repository.Private
	}
	owner, repo := gitRemote(filepath.Dir(s.Project.Dir))
	if owner == "" || s.Token == "" {
		return true
	}
	gh, ok := connector.Lookup("github")
	if !ok {
		return true
	}
	public, known := gh.(*githubconn.Connector).RepoIsPublic(ctx, s, owner, repo)
	return !known || !public
}

func defaultRecords() string { return filepath.Join(projectDir, "local") }
