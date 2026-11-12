package connectors_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/connectors/configsrc"
	"github.com/sk1122/firedrill/connectors/files"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
)

// Two runs over the same repos, with nothing changed between them, give no
// change and nothing "not compared". The case is built like the live one:
// several repos, one fingerprint seen in more than one of them, user-level
// agent files read with --include-home, and a checkout whose folder name is
// long and mixed enough to look like a secret to the record scanner.
func TestIdenticalRunsDiffToNothing(t *testing.T) {
	shared := "ACME_" + "TOKEN=" + railwayToken + "\n"
	roots := []string{
		writeRepo(t, "acme-payments-api-2026", map[string]string{".env.production": shared, "src/main.go": "package main\n"}),
		writeRepo(t, "web", map[string]string{"scripts/deploy.sh": shared, ".claude/settings.json": `{"permissions":{"deny":["Read(.env*)"]}}`}),
		writeRepo(t, "tools", map[string]string{"README.md": "tools\n"}),
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", "settings.json"), []byte(`{"permissions":{"allow":["Bash(git status)"]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &config.Project{Dir: filepath.Join(t.TempDir(), ".firedrill")}
	records := t.TempDir()
	var last *run.Result
	for i := range 2 {
		c := run.Config{
			Project: p, Drills: allStarterDrills(t), Connectors: []connector.Connector{configsrc.New(), files.New()},
			Scope: connector.Scope{Project: p, Now: now.Add(time.Duration(i) * time.Hour), Log: &connector.CallLog{}, Hasher: graph.NewHasher("salt"),
				Paths: roots, IncludeHome: true, HomeDir: home, Getenv: func(string) string { return "" }},
			Stream: "local", Records: records, WriteRecords: true,
		}
		res, err := run.Run(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		last = res
	}
	d := last.Diff
	if d == nil {
		t.Fatal("the second run made no diff")
	}
	if len(d.Changes) != 0 {
		t.Errorf("identical runs changed: %+v", d.Changes)
	}
	if len(d.Skipped) != 0 {
		t.Errorf("identical runs left something not compared: %v", d.Skipped)
	}
	for _, s := range d.Skipped {
		if strings.Contains(s, "secret:") {
			t.Errorf("a skip names a raw ID: %s", s)
		}
	}
}
