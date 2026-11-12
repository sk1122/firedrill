package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMarkConnectedKeepsTheRestOfTheFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	orig := "# acme setup\ngithub:\n  org: acme # the org\n  repos: [api]\naws:\n  accounts:\n    - profile: acme-prod\n"
	if err := os.WriteFile(path, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Config.IsConnected("github") || p.Config.IsConnected("aws") {
		t.Fatal("nothing is connected before connect runs")
	}
	for _, s := range []string{"github", "aws", "github"} {
		if err := MarkConnected(dir, s); err != nil {
			t.Fatal(err)
		}
	}
	p, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Config.IsConnected("github") || !p.Config.IsConnected("aws") || p.Config.IsConnected("gcp") {
		t.Fatalf("connected: %v", p.Config.Connected)
	}
	if len(p.Config.Connected) != 2 {
		t.Fatalf("marking twice must not repeat: %v", p.Config.Connected)
	}
	if p.Config.GitHub.Org != "acme" || len(p.Config.AWS.Accounts) != 1 {
		t.Fatalf("the rest of the config must survive: %+v", p.Config)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "# acme setup") || !strings.Contains(string(b), "# the org") {
		t.Fatalf("comments must survive:\n%s", b)
	}
}

func TestMarkConnectedFillsAnEmptyList(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("connected:\ndomains: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := MarkConnected(dir, "gcp"); err != nil {
		t.Fatal(err)
	}
	p, err := Load(dir)
	if err != nil || !p.Config.IsConnected("gcp") {
		t.Fatalf("%v %v", err, p)
	}
}

func TestNoiseRuleDefaultsAndOff(t *testing.T) {
	for _, c := range []struct {
		yaml           string
		shadow, review int
		err            bool
	}{
		{"github: { org: acme }\n", DefaultShadowDays, DefaultReviewAfterDays, false},
		{"shadow_days: 0\nreview_after_days: 0\n", 0, 0, false},
		{"shadow_days: 7\nreview_after_days: 45\n", 7, 45, false},
		{"shadow_days: -1\n", 0, 0, true},
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(c.yaml), 0o644); err != nil {
			t.Fatal(err)
		}
		p, err := Load(dir)
		if c.err {
			if err == nil {
				t.Errorf("%q: want an error", c.yaml)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if p.Config.ShadowWindow() != c.shadow || p.Config.ReviewAfter() != c.review {
			t.Errorf("%q: shadow %d review %d", c.yaml, p.Config.ShadowWindow(), p.Config.ReviewAfter())
		}
	}
}

func TestRegistersAndThresholds(t *testing.T) {
	write := func(dir, name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	write(dir, "config.yaml", "production: [\"111122223333\", acme-prod]\n")
	write(dir, "apps.yaml", "- {client_id: 1234-acme.apps.googleusercontent.com, name: Acme Notes, owner: \"@it\", reviewed: 2026-10-01}\n")
	write(dir, "backups.yaml", "- {database: orders, copy_location: vault in 444455556666, owner: \"@platform\", verified: 2026-11-01}\n")
	write(dir, "ai-keys.yaml", "- {provider: anthropic, workspace: wrkspc_01AcmeProd, owner: \"@ml\", monthly_limit_usd: 500, verified: 2026-11-01}\n")
	p, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Apps) != 1 || len(p.Backups) != 1 || len(p.AIKeys) != 1 || *p.AIKeys[0].MonthlyLimitUSD != 500 {
		t.Fatalf("%+v", p)
	}
	if p.Config.AppReviewDays() != DefaultAppReviewDays || p.Config.MinRetentionDays() != DefaultMinRetentionDays {
		t.Fatal("defaults")
	}
	if !p.Config.IsProduction("acme-staging", "111122223333") || p.Config.IsProduction("acme-staging", "") {
		t.Fatal("production names")
	}

	bad := []struct{ file, body string }{
		{"apps.yaml", "- {name: no id}\n"},
		{"apps.yaml", "- {client_id: x, reviewed: last week}\n"},
		{"apps.yaml", "- {client_id: x, owner: ravi@acme.com}\n"},
		{"backups.yaml", "- {database: orders, copy_location: x}\n"},
		{"backups.yaml", "- {database: orders, copy_location: x, verified: 11/01/2026}\n"},
		{"ai-keys.yaml", "- {provider: other, key_id: k, verified: 2026-11-01}\n"},
		{"ai-keys.yaml", "- {provider: openai, verified: 2026-11-01}\n"},
		{"ai-keys.yaml", "- {provider: openai, project: proj_x}\n"},
		{"ai-keys.yaml", "- {provider: openai, project: proj_x, verified: 2026-11-01, monthly_limit_usd: -1}\n"},
		{"config.yaml", "recovery: {min_retention_days: -1}\n"},
	}
	for _, b := range bad {
		d := t.TempDir()
		write(d, "config.yaml", "github: {org: acme}\n")
		write(d, b.file, b.body)
		if _, err := Load(d); err == nil {
			t.Errorf("%s %q: want an error", b.file, b.body)
		}
	}
}
