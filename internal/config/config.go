// Package config reads the files under .firedrill/.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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
		// ReviewDays is how long a third-party app's review in apps.yaml stays
		// current. Unset means 180.
		ReviewDays *int `yaml:"review_days"`
	} `yaml:"google"`
	AWS struct {
		Accounts []struct {
			Profile string `yaml:"profile"`
		} `yaml:"accounts"`
		BreakGlass []string `yaml:"break_glass"`
		// Regions are where databases and their backups are read. Unset means
		// each profile's own region. IAM is global and ignores this.
		Regions []string `yaml:"regions"`
	} `yaml:"aws"`
	GCP struct {
		Projects      []string `yaml:"projects"`
		MemberDomains []string `yaml:"member_domains"`
	} `yaml:"gcp"`
	HR struct {
		LeaversCSV string `yaml:"leavers_csv"`
	} `yaml:"hr"`
	Hub struct {
		Repo string `yaml:"repo"` // owner/name of the drill hub
		Ref  string `yaml:"ref"`  // branch, tag or commit
	} `yaml:"hub"`
	Semgrep struct {
		Results string `yaml:"results"`
	} `yaml:"semgrep"`
	Domains      []string  `yaml:"domains"`
	DefaultOwner string    `yaml:"default_owner"`
	Retired      []Retired `yaml:"retired"`
	// ShadowDays is how long a drill new to an established install runs in
	// shadow: it reports but never fails a run. Unset means 14; 0 turns it off.
	ShadowDays *int `yaml:"shadow_days"`
	// ReviewAfterDays is how long a safeguard may stay open with no fix and no
	// waiver before it is flagged for review. Unset means 30; 0 turns it off.
	ReviewAfterDays *int `yaml:"review_after_days"`
	Secrets         struct {
		ExamplePaths []string `yaml:"example_paths"`
		ProdWords    []string `yaml:"prod_words"`
		StagingWords []string `yaml:"staging_words"`
	} `yaml:"secrets"`
	Agents struct {
		DestructiveCommands []string `yaml:"destructive_commands"`
		// MCPHosts are hosts or domains an MCP server may point at, besides the
		// verified domains, hosts.yaml and localhost.
		MCPHosts []string `yaml:"mcp_hosts"`
		// MCPPackages are exact package or image names an MCP server may run.
		MCPPackages []string `yaml:"mcp_packages"`
	} `yaml:"agents"`
	Web struct {
		ExcludeHosts []string `yaml:"exclude_hosts"`
	} `yaml:"web"`
	Recovery struct {
		// MinRetentionDays is the fewest days of automated backups a production
		// database may keep. Unset means 7.
		MinRetentionDays *int `yaml:"min_retention_days"`
		// RestoreDays is how many days may pass since a production database
		// was last restored from its backups. Unset means 90.
		RestoreDays *int `yaml:"restore_days"`
	} `yaml:"recovery"`
	// Production names what is production: AWS account IDs, AWS profile names
	// and Google Cloud project IDs. A database tagged or labelled env or
	// environment = prod or production is production too. With nothing named
	// and nothing tagged, every database is judged.
	Production []string `yaml:"production"`
	// Connected lists the systems someone connected on purpose with firedrill
	// connect. Only connect writes it. A system missing here is never called,
	// whatever credentials the machine holds.
	Connected []string `yaml:"connected"`
}

// Defaults of the noise rules.
const (
	DefaultShadowDays       = 14
	DefaultReviewAfterDays  = 30
	DefaultAppReviewDays    = 180
	DefaultMinRetentionDays = 7
	DefaultRestoreDays      = 90
)

// AppReviewDays returns google.review_days, or its default when unset.
func (c Config) AppReviewDays() int {
	if c.Google.ReviewDays == nil {
		return DefaultAppReviewDays
	}
	return *c.Google.ReviewDays
}

// MinRetentionDays returns recovery.min_retention_days, or its default when unset.
func (c Config) MinRetentionDays() int {
	if c.Recovery.MinRetentionDays == nil {
		return DefaultMinRetentionDays
	}
	return *c.Recovery.MinRetentionDays
}

// RestoreDays returns recovery.restore_days, or its default when unset.
func (c Config) RestoreDays() int {
	if c.Recovery.RestoreDays == nil {
		return DefaultRestoreDays
	}
	return *c.Recovery.RestoreDays
}

// IsProduction says whether any of the given names (an account ID, a profile
// or a project ID) is listed under production.
func (c Config) IsProduction(names ...string) bool {
	for _, n := range names {
		if n != "" && slices.Contains(c.Production, n) {
			return true
		}
	}
	return false
}

// ShadowWindow returns shadow_days, or its default when unset.
func (c Config) ShadowWindow() int {
	if c.ShadowDays == nil {
		return DefaultShadowDays
	}
	return *c.ShadowDays
}

// ReviewAfter returns review_after_days, or its default when unset.
func (c Config) ReviewAfter() int {
	if c.ReviewAfterDays == nil {
		return DefaultReviewAfterDays
	}
	return *c.ReviewAfterDays
}

// IsConnected says whether a system was connected on purpose.
func (c Config) IsConnected(system string) bool {
	return slices.Contains(c.Connected, system)
}

// MarkConnected records in dir/config.yaml that a system was connected on
// purpose. It edits only the connected list and keeps the rest of the file,
// comments included.
func MarkConnected(dir, system string) error {
	path := filepath.Join(dir, "config.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("config.yaml: expected a mapping at the top")
	}
	root := doc.Content[0]
	var list *yaml.Node
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "connected" {
			list = root.Content[i+1]
		}
	}
	if list == nil {
		list = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "connected"}, list)
	}
	if list.Kind == yaml.ScalarNode && list.Tag == "!!null" {
		*list = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	}
	if list.Kind != yaml.SequenceNode {
		return errors.New("config.yaml: connected must be a list")
	}
	for _, n := range list.Content {
		if n.Value == system {
			return nil
		}
	}
	list.Content = append(list.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: system})
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o644)
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

// App is one entry of apps.yaml: who owns a third-party OAuth app and when it
// was last reviewed.
type App struct {
	ClientID string `yaml:"client_id"`
	Name     string `yaml:"name"`
	Owner    string `yaml:"owner"`
	Reviewed string `yaml:"reviewed"`
	Note     string `yaml:"note"`
}

// Backup is one entry of backups.yaml: a copy of a database the API cannot
// show, kept somewhere else and checked by someone.
type Backup struct {
	Database     string `yaml:"database"`
	CopyLocation string `yaml:"copy_location"`
	Owner        string `yaml:"owner"`
	Verified     string `yaml:"verified"`
}

// Restore is one entry of restores.yaml: a restore of a database from its
// backups that the team ran and checked, where the API shows none.
type Restore struct {
	Database string `yaml:"database"`
	Restored string `yaml:"restored"`
	By       string `yaml:"by"`
	Note     string `yaml:"note"`
}

// AIKey is one entry of ai-keys.yaml: the owner and spend limit of an AI
// provider key, workspace or project, where the provider's API does not show
// them.
type AIKey struct {
	Provider        string   `yaml:"provider"`
	KeyID           string   `yaml:"key_id"`
	Workspace       string   `yaml:"workspace"`
	Project         string   `yaml:"project"`
	Owner           string   `yaml:"owner"`
	MonthlyLimitUSD *float64 `yaml:"monthly_limit_usd"`
	Verified        string   `yaml:"verified"`
}

// Owner is one entry of owners.yaml: the team or role that answers for a
// principal no person holds, such as a GCP service account or a GitHub app.
type Owner struct {
	// Principal is a GCP service account's address, or a graph ID such as
	// github:app/123, github:deploy-key/acme/api or github:team/acme/ops.
	Principal string `yaml:"principal"`
	Owner     string `yaml:"owner"`
	Note      string `yaml:"note"`
}

// Project is everything under one .firedrill directory.
type Project struct {
	Dir     string
	Config  Config
	Waivers []Waiver
	Hosts   []Host
	// People maps a GitHub login to the email of the person who holds it.
	// Several logins may map to one email. Keys match case-insensitively.
	People   map[string]string
	Apps     []App
	Backups  []Backup
	Restores []Restore
	AIKeys   []AIKey
	Owners   []Owner
}

// PersonOf returns the email people.yaml gives a GitHub login, matching the
// login case-insensitively, or "" when there is no entry.
func (p *Project) PersonOf(login string) string {
	if e, ok := p.People[login]; ok {
		return e
	}
	for k, e := range p.People {
		if strings.EqualFold(k, login) {
			return e
		}
	}
	return ""
}

// serviceAccountLike matches a GCP service account's address.
var serviceAccountLike = regexp.MustCompile(`^[a-z0-9._-]+@[a-z0-9.-]+\.gserviceaccount\.com$`)

// principalLike matches a graph ID an owners.yaml entry may name.
var principalLike = regexp.MustCompile(`^(github|gcp):[A-Za-z0-9._/@:-]+$`)

// emailLike matches an email address. Registers name owners by handle or
// team, never by email, since every register lands in records.
var emailLike = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

func isDate(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// validateRegisters checks apps.yaml, backups.yaml, restores.yaml,
// ai-keys.yaml, owners.yaml and people.yaml.
func (p *Project) validateRegisters() error {
	owner := func(file string, i int, o string) error {
		if emailLike.MatchString(o) {
			return fmt.Errorf("%s entry %d: owner must be a handle or team name, not an email address", file, i+1)
		}
		return nil
	}
	for i, a := range p.Apps {
		if a.ClientID == "" {
			return fmt.Errorf("apps.yaml entry %d: client_id is required", i+1)
		}
		if a.Reviewed != "" && !isDate(a.Reviewed) {
			return fmt.Errorf("apps.yaml entry %d: reviewed must be YYYY-MM-DD", i+1)
		}
		if err := owner("apps.yaml", i, a.Owner); err != nil {
			return err
		}
	}
	for i, b := range p.Backups {
		if b.Database == "" || b.CopyLocation == "" || b.Verified == "" {
			return fmt.Errorf("backups.yaml entry %d: database, copy_location and verified are required", i+1)
		}
		if !isDate(b.Verified) {
			return fmt.Errorf("backups.yaml entry %d: verified must be YYYY-MM-DD", i+1)
		}
		if err := owner("backups.yaml", i, b.Owner); err != nil {
			return err
		}
	}
	for i, r := range p.Restores {
		if r.Database == "" || r.Restored == "" || r.By == "" {
			return fmt.Errorf("restores.yaml entry %d: database, restored and by are required", i+1)
		}
		if !isDate(r.Restored) {
			return fmt.Errorf("restores.yaml entry %d: restored must be YYYY-MM-DD", i+1)
		}
		if emailLike.MatchString(r.By) {
			return fmt.Errorf("restores.yaml entry %d: by must be a team or role, not an email address", i+1)
		}
		if emailLike.MatchString(r.Note) {
			return fmt.Errorf("restores.yaml entry %d: note must not hold an email address", i+1)
		}
	}
	for i, k := range p.AIKeys {
		if k.Provider != "anthropic" && k.Provider != "openai" {
			return fmt.Errorf("ai-keys.yaml entry %d: provider must be anthropic or openai", i+1)
		}
		if k.KeyID == "" && k.Workspace == "" && k.Project == "" {
			return fmt.Errorf("ai-keys.yaml entry %d: name a key_id, a workspace or a project", i+1)
		}
		if k.Verified == "" || !isDate(k.Verified) {
			return fmt.Errorf("ai-keys.yaml entry %d: verified is required, as YYYY-MM-DD", i+1)
		}
		if k.MonthlyLimitUSD != nil && *k.MonthlyLimitUSD < 0 {
			return fmt.Errorf("ai-keys.yaml entry %d: monthly_limit_usd must be 0 or more", i+1)
		}
		if err := owner("ai-keys.yaml", i, k.Owner); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for i, o := range p.Owners {
		pr := strings.ToLower(strings.TrimSpace(o.Principal))
		switch {
		case pr == "" || o.Owner == "":
			return fmt.Errorf("owners.yaml entry %d: principal and owner are required", i+1)
		case strings.Contains(pr, "@") && !serviceAccountLike.MatchString(pr):
			return fmt.Errorf("owners.yaml entry %d: principal must be a service account or a graph ID; a person's address belongs in people.yaml", i+1)
		case !strings.Contains(pr, "@") && !principalLike.MatchString(o.Principal):
			return fmt.Errorf("owners.yaml entry %d: principal must be a service account or a graph ID such as github:app/123", i+1)
		case seen[pr]:
			return fmt.Errorf("owners.yaml entry %d: %s is listed twice", i+1, o.Principal)
		}
		seen[pr] = true
		if err := owner("owners.yaml", i, o.Owner); err != nil {
			return err
		}
	}
	logins := map[string]string{}
	for login, email := range p.People {
		if !emailLike.MatchString(email) {
			return fmt.Errorf("people.yaml: %s must map to an email address", login)
		}
		l := strings.ToLower(login)
		if prev, ok := logins[l]; ok && !strings.EqualFold(prev, email) {
			return fmt.Errorf("people.yaml: %s is listed twice with different emails", login)
		}
		logins[l] = email
	}
	return nil
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
	if p.Config.ShadowWindow() < 0 || p.Config.ReviewAfter() < 0 {
		return nil, errors.New("config.yaml: shadow_days and review_after_days must be 0 or more")
	}
	if p.Config.AppReviewDays() < 0 || p.Config.MinRetentionDays() < 0 || p.Config.RestoreDays() < 0 {
		return nil, errors.New("config.yaml: google.review_days, recovery.min_retention_days and recovery.restore_days must be 0 or more")
	}
	for name, out := range map[string]any{"waivers.yaml": &p.Waivers, "hosts.yaml": &p.Hosts, "people.yaml": &p.People,
		"apps.yaml": &p.Apps, "backups.yaml": &p.Backups, "restores.yaml": &p.Restores, "ai-keys.yaml": &p.AIKeys, "owners.yaml": &p.Owners} {
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
	if err := p.validateRegisters(); err != nil {
		return nil, err
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
