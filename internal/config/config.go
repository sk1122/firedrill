// Package config reads the files under .firedrill/.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is .firedrill/config.yaml.
type Config struct {
	GitHub struct {
		Org   string   `yaml:"org"`
		Repos []string `yaml:"repos"`
	} `yaml:"github"`
	Google struct {
		Domain     string `yaml:"domain"`
		AdminEmail string `yaml:"admin_email"`
	} `yaml:"google"`
	AWS struct {
		Accounts []struct {
			Profile string `yaml:"profile"`
		} `yaml:"accounts"`
		BreakGlass []string `yaml:"break_glass"`
	} `yaml:"aws"`
	GCP struct {
		Projects      []string `yaml:"projects"`
		MemberDomains []string `yaml:"member_domains"`
	} `yaml:"gcp"`
	HR struct {
		LeaversCSV string `yaml:"leavers_csv"`
	} `yaml:"hr"`
	Semgrep struct {
		Results string `yaml:"results"`
	} `yaml:"semgrep"`
	Domains      []string  `yaml:"domains"`
	DefaultOwner string    `yaml:"default_owner"`
	Retired      []Retired `yaml:"retired"`
	Secrets      struct {
		ExamplePaths []string `yaml:"example_paths"`
		ProdWords    []string `yaml:"prod_words"`
		StagingWords []string `yaml:"staging_words"`
	} `yaml:"secrets"`
	Agents struct {
		DestructiveCommands []string `yaml:"destructive_commands"`
	} `yaml:"agents"`
	Web struct {
		ExcludeHosts []string `yaml:"exclude_hosts"`
	} `yaml:"web"`
}

// Retired names a target that no longer exists.
type Retired struct {
	Target     string `yaml:"target"`
	Reason     string `yaml:"reason"`
	ApprovedBy string `yaml:"approved_by"`
}

// Waiver is one accepted risk.
type Waiver struct {
	Drill   string `yaml:"drill"`
	Target  string `yaml:"target"`
	Finding *struct {
		File string `yaml:"file"`
		Hash string `yaml:"hash"`
	} `yaml:"finding"`
	Reason     string `yaml:"reason"`
	ApprovedBy string `yaml:"approved_by"`
	Expires    string `yaml:"expires"`
}

// Active says whether a waiver still applies on a date.
func (w Waiver) Active(now time.Time) bool {
	t, err := time.Parse("2006-01-02", w.Expires)
	if err != nil {
		return false
	}
	return !now.UTC().After(t.Add(24*time.Hour - time.Nanosecond))
}

// Host maps a host to its owner.
type Host struct {
	Host  string `yaml:"host"`
	Owner string `yaml:"owner"`
}

// Project is everything under one .firedrill directory.
type Project struct {
	Dir     string
	Config  Config
	Waivers []Waiver
	Hosts   []Host
	People  map[string]string
}

// Load reads a project. Only config.yaml must exist.
func Load(dir string) (*Project, error) {
	p := &Project{Dir: dir, People: map[string]string{}}
	data, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		return nil, fmt.Errorf("no Firedrill config found: %w. Run firedrill init", err)
	}
	if err := yaml.Unmarshal(data, &p.Config); err != nil {
		return nil, fmt.Errorf("config.yaml: %w", err)
	}
	for name, out := range map[string]any{"waivers.yaml": &p.Waivers, "hosts.yaml": &p.Hosts, "people.yaml": &p.People} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := yaml.Unmarshal(data, out); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	for i, w := range p.Waivers {
		if w.Drill == "" || w.Reason == "" || w.ApprovedBy == "" || w.Expires == "" {
			return nil, fmt.Errorf("waivers.yaml entry %d: drill, reason, approved_by and expires are required", i+1)
		}
		if _, err := time.Parse("2006-01-02", w.Expires); err != nil {
			return nil, fmt.Errorf("waivers.yaml entry %d: expires must be YYYY-MM-DD", i+1)
		}
	}
	return p, nil
}

// RetiredTarget returns the retirement entry of a target.
func (c Config) RetiredTarget(target string) *Retired {
	for i := range c.Retired {
		if c.Retired[i].Target == target {
			return &c.Retired[i]
		}
	}
	return nil
}
