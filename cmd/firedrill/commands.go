package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/sk1122/firedrill/connector"
	dnsconn "github.com/sk1122/firedrill/connectors/dns"
	githubconn "github.com/sk1122/firedrill/connectors/github"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/graph/pg"
	"github.com/sk1122/firedrill/internal/report"
	"github.com/sk1122/firedrill/internal/tag"
	"github.com/sk1122/firedrill/packs"
)

func initCmd() *cobra.Command {
	var yes bool
	var org, repos, owner string
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create .firedrill, with starter packs and the secret salt",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			cfgPath := filepath.Join(projectDir, "config.yaml")
			if _, err := os.Stat(cfgPath); err == nil {
				return fmt.Errorf("%s already exists", cfgPath)
			}
			remoteOwner, remoteRepo := gitRemote(filepath.Dir(projectDir))
			if org == "" {
				org = remoteOwner
			}
			if !yes && term.IsTerminal(int(os.Stdin.Fd())) {
				form := huh.NewForm(huh.NewGroup(
					huh.NewInput().Title("GitHub org").Value(&org),
					huh.NewInput().Title("Repos to drill, comma-separated").Value(&repos),
					huh.NewInput().Title("Default owner, such as @arjun").Description("Answers for any drill with no other owner.").Value(&owner),
				))
				if err := form.Run(); err != nil {
					return err
				}
			}
			var cfg config.Config
			cfg.GitHub.Org = org
			for r := range strings.SplitSeq(repos, ",") {
				if r = strings.TrimSpace(r); r != "" {
					cfg.GitHub.Repos = append(cfg.GitHub.Repos, r)
				}
			}
			if len(cfg.GitHub.Repos) == 0 && remoteRepo != "" && remoteRepo != "firedrill" {
				cfg.GitHub.Repos = []string{remoteRepo}
			}
			cfg.DefaultOwner = owner
			if err := os.MkdirAll(filepath.Join(projectDir, "drills"), 0o755); err != nil {
				return err
			}
			if err := writeConfig(cfgPath, cfg); err != nil {
				return err
			}
			for name, content := range map[string]string{"waivers.yaml": "[]\n", "hosts.yaml": "[]\n", "people.yaml": "{}\n", ".gitignore": "local/\nreport/\n"} {
				if err := os.WriteFile(filepath.Join(projectDir, name), []byte(content), 0o644); err != nil {
					return err
				}
			}
			n, err := copyPacks(filepath.Join(projectDir, "drills"))
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Created %s with %d starter drills.\n", projectDir, n)
			if os.Getenv("FIREDRILL_SALT") != "" {
				fmt.Fprintln(out, "Using the salt in FIREDRILL_SALT.")
			} else if _, err := os.Stat(saltPath()); err == nil {
				fmt.Fprintf(out, "Using the salt in %s.\n", saltPath())
			} else {
				salt, err := generateSalt()
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(saltPath()), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(saltPath(), []byte(salt+"\n"), 0o600); err != nil {
					return err
				}
				fmt.Fprintf(out, "Generated the secret salt in %s.\nStore it in your team's password manager and as the FIREDRILL_SALT secret in CI. Teammates set the same value.\n", saltPath())
			}
			if cfg.DefaultOwner == "" {
				fmt.Fprintln(out, "No default owner set. Add default_owner to config.yaml, so every open safeguard names one.")
			}
			fmt.Fprintln(out, "\nnext:  firedrill connect github\n       firedrill run")
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "skip questions")
	cmd.Flags().StringVar(&org, "org", "", "GitHub org")
	cmd.Flags().StringVar(&repos, "repos", "", "repos to drill, comma-separated")
	cmd.Flags().StringVar(&owner, "owner", "", "default owner")
	return cmd
}

func writeConfig(path string, c config.Config) error {
	doc := map[string]any{"github": map[string]any{"org": c.GitHub.Org, "repos": c.GitHub.Repos}, "default_owner": c.DefaultOwner, "retired": []any{}, "domains": []any{}}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func copyPacks(dest string) (int, error) {
	count := 0
	err := fs.WalkDir(packs.FS, ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".drill.yaml") {
			return err
		}
		data, err := packs.FS.ReadFile(p)
		if err != nil {
			return err
		}
		target := filepath.Join(dest, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		count++
		return os.WriteFile(target, data, 0o644)
	})
	return count, err
}

var setupNotes = map[string]string{
	"github": `GitHub needs read access: Metadata, Administration, Environments and Contents.
On a laptop the GitHub CLI's login is reused. A gh token acts as whoever is logged in.
In CI use a fine-grained token as FIREDRILL_GITHUB_TOKEN, limited to the listed repos.
With a read-only token, ruleset bypass lists come from firedrill export rulesets, or read as unknown.`,
	"google": `Google needs a service account with domain-wide delegation, approved once by a super admin.
1. Create a service account and a JSON key in Google Cloud.
2. In the Admin console, grant it the scope https://www.googleapis.com/auth/admin.directory.user.readonly.
3. Set google.domain and google.admin_email in config.yaml, the admin it acts as.
4. Set GOOGLE_APPLICATION_CREDENTIALS to the key file's path.`,
	"aws": `AWS uses the default credential chain, one profile per account under aws.accounts in config.yaml.
Attach this read policy to each:
  iam:GetAccountAuthorizationDetails, iam:GetAccessKeyLastUsed, iam:ListAccessKeys,
  iam:GenerateCredentialReport, iam:GetCredentialReport`,
	"files":   "Repo files need nothing for local checkouts: pass --path. Remote repos use the GitHub connection.",
	"hr":      "Export a CSV with the columns email,leave_date from your HR system, and set hr.leavers_csv in config.yaml.",
	"semgrep": "Run semgrep --json yourself and set semgrep.results in config.yaml. Firedrill reads the file and runs nothing.",
	"dns":     "DNS uses the system resolver. List domains in config.yaml and run firedrill verify-domain.",
	"ctlog":   "Certificate logs use the public crt.sh API, on domains verified with firedrill verify-domain.",
	"web":     "Web checks only reach hosts under domains verified with firedrill verify-domain.",
}

func connectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "connect <system>",
		Short: "Check access to a system and print the exact permissions and setup steps",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			out := cmd.OutOrStdout()
			note, ok := setupNotes[name]
			conn, found := connector.Lookup(name)
			if !ok || !found {
				names := make([]string, 0, len(setupNotes))
				for n := range setupNotes {
					names = append(names, n)
				}
				sort.Strings(names)
				return fmt.Errorf("unknown system %q. Systems: %s", name, strings.Join(names, ", "))
			}
			fmt.Fprintln(out, note)
			ctx := cmd.Context()
			rc, err := prepare(ctx, nil, false)
			if err != nil {
				return err
			}
			if name == "github" {
				_, source := githubToken(ctx)
				if source != "" {
					fmt.Fprintf(out, "\nToken found from %s.\n", source)
				}
				if source == "gh auth token" {
					fmt.Fprintln(out, "A token from gh is broad. Use a fine-grained token for CI.")
				}
			}
			avail, why := conn.Available(rc.scope)
			if !avail {
				fmt.Fprintf(out, "\nNot connected yet: %s.\n", why)
				return exitError{1}
			}
			if name == "dns" || name == "web" || name == "ctlog" || name == "files" || name == "hr" || name == "semgrep" {
				fmt.Fprintln(out, "\nReady.")
				return nil
			}
			g := graph.New()
			for _, col := range conn.Collections() {
				if err := conn.Collect(ctx, col, rc.scope, g); err != nil {
					fmt.Fprintf(out, "\nAccess check failed: %v\n", err)
					return exitError{1}
				}
			}
			fmt.Fprintf(out, "\nConnected. Read %d items.\n", len(g.Nodes("")))
			return nil
		},
	}
}

func verifyDomainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify-domain <domain>",
		Short: "Issue a DNS TXT value and confirm it, so web checks may reach that domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			salt, err := loadSalt()
			if err != nil {
				return err
			}
			h := graph.NewHasher(salt)
			domain := strings.ToLower(args[0])
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Publish this TXT record:\n  %s  TXT  %s\n", dnsconn.VerifyRecord(domain), dnsconn.VerifyValue(h, domain))
			conn, _ := connector.Lookup("dns")
			if dnsconn.IsVerified(cmd.Context(), conn.(*dnsconn.Connector).Resolver, h, domain) {
				fmt.Fprintf(out, "\nVerified. Add %s to domains in config.yaml if it is not listed.\n", domain)
				return nil
			}
			fmt.Fprintln(out, "\nNot found yet. DNS can take a few minutes. Rerun this command once it is published.")
			return exitError{1}
		},
	}
}

func exportCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "export", Short: "Export evidence a read-only token cannot see"}
	cmd.AddCommand(&cobra.Command{
		Use:   "rulesets",
		Short: "Run by a repo admin: writes the ruleset bypass lists for CI to use",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			rc, err := prepare(cmd.Context(), nil, false)
			if err != nil {
				return err
			}
			conn, _ := connector.Lookup("github")
			if ok, why := conn.Available(rc.scope); !ok {
				return errors.New(why)
			}
			path, n, err := conn.(*githubconn.Connector).ExportRulesets(cmd.Context(), rc.scope)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote %d rulesets to %s. Commit it. CI uses it for 30 days.\n", n, path)
			return nil
		},
	})
	return cmd
}

func listCmd() *cobra.Command {
	var records string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Every drill with owner, state, last verdict and waiver",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			project, err := config.Load(projectDir)
			if err != nil {
				return err
			}
			drills, _, err := drill.LoadDir(filepath.Join(projectDir, "drills"))
			if err != nil {
				return err
			}
			if records == "" {
				records = defaultRecords()
			}
			store := tag.Store{Root: records}
			keys, err := store.Keys()
			if err != nil {
				return err
			}
			byDrill := map[string][]tag.Key{}
			for _, k := range keys {
				byDrill[k.DrillID] = append(byDrill[k.DrillID], k)
			}
			type row struct {
				Drill   string `json:"drill"`
				Target  string `json:"target,omitempty"`
				Owner   string `json:"owner,omitempty"`
				State   string `json:"state"`
				Verdict string `json:"last_verdict,omitempty"`
				Waiver  string `json:"waiver,omitempty"`
				Chain   string `json:"chain,omitempty"`
			}
			var rows []row
			now := time.Now()
			waiverOf := func(id, target string) string {
				for _, w := range project.Waivers {
					if w.Drill == id && (w.Target == "" || w.Target == target) && w.Active(now) {
						return "until " + w.Expires
					}
				}
				return ""
			}
			for _, d := range drills {
				ks := byDrill[d.ID]
				if len(ks) == 0 {
					rows = append(rows, row{Drill: d.ID, Owner: firstNonEmpty(d.Owner, project.Config.DefaultOwner), State: tag.Unknown})
					continue
				}
				for _, k := range ks {
					h, err := store.History(k.DrillID, k.TargetSlug)
					if err != nil {
						return err
					}
					if len(h) == 0 {
						continue
					}
					last := h[len(h)-1].Header
					r := row{Drill: d.ID, Target: last.Target, Owner: last.Owner, State: last.State, Verdict: last.Verdict, Waiver: waiverOf(d.ID, last.Target)}
					st := tag.VerifyChain(h)
					switch {
					case !st.OK:
						r.Chain = "CHAIN BROKEN: " + strings.Join(st.Tampered, "; ")
					case st.Redacted > 0:
						r.Chain = fmt.Sprintf("%d redacted", st.Redacted)
					}
					rows = append(rows, r)
				}
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rows)
			}
			for _, r := range rows {
				line := fmt.Sprintf("%-8s %-5s %-38s %-16s %s", r.State, r.Verdict, r.Drill, r.Target, r.Owner)
				if r.Waiver != "" {
					line += "  waived " + r.Waiver
				}
				if r.Chain != "" {
					line += "  " + r.Chain
				}
				fmt.Fprintln(cmd.OutOrStdout(), strings.TrimRight(line, " "))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&records, "records", "", "where records live")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func explainCmd() *cobra.Command {
	var records string
	cmd := &cobra.Command{
		Use:   "explain <drill>",
		Short: "What the drill checks, the data it saw and why it failed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			drills, _, err := drill.LoadDir(filepath.Join(projectDir, "drills"))
			if err != nil {
				return err
			}
			var d *drill.Drill
			for _, x := range drills {
				if x.ID == args[0] {
					d = x
				}
			}
			if d == nil {
				return fmt.Errorf("no drill named %s", args[0])
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s (%s)\n%s\n", d.ID, d.Severity, d.Safeguard)
			if d.Source != "" {
				fmt.Fprintf(out, "Written in: %s\n", d.Source)
			}
			fmt.Fprintln(out, "\nIt passes when:")
			for _, c := range d.PassWhen {
				fmt.Fprintf(out, "  %s\n", strings.Join(strings.Fields(c.Expr), " "))
			}
			fmt.Fprintln(out, "\nIt reads:")
			for _, f := range d.Fetches {
				fmt.Fprintf(out, "  %s\n", f.Fact)
			}
			if records == "" {
				records = defaultRecords()
			}
			store := tag.Store{Root: records}
			keys, err := store.Keys()
			if err != nil {
				return err
			}
			any := false
			for _, k := range keys {
				if k.DrillID != d.ID {
					continue
				}
				l, err := store.Latest(k.DrillID, k.TargetSlug)
				if err != nil || l == nil {
					continue
				}
				any = true
				fmt.Fprintf(out, "\nLast run on %s, %s: %s, %s\n", firstNonEmpty(l.Header.Target, "global"), l.Header.Time.Format(time.RFC3339), l.Header.Verdict, l.Header.State)
				if l.Header.Reason != "" {
					fmt.Fprintf(out, "Reason: %s\n", l.Header.Reason)
				}
				for _, c := range l.Header.Conditions {
					if c.Result != "true" {
						fmt.Fprintf(out, "Failing: %s\n", strings.Join(strings.Fields(c.Expr), " "))
					}
				}
				b, _ := json.MarshalIndent(l.Evidence.Facts, "", "  ")
				fmt.Fprintf(out, "Evidence:\n%s\n", b)
				if l.Header.State == tag.Open && d.Fix != "" {
					fmt.Fprintf(out, "Fix: %s\n", d.Fix)
				}
			}
			if !any {
				fmt.Fprintln(out, "\nNo runs yet.")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&records, "records", "", "where records live")
	return cmd
}

func reportCmd() *cobra.Command {
	var records, outDir, summary string
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Write the HTML board",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if summary != "" {
				b, err := os.ReadFile(summary)
				if err != nil {
					return err
				}
				var j report.JSONResult
				if err := json.Unmarshal(b, &j); err != nil {
					return err
				}
				fmt.Fprint(cmd.OutOrStdout(), report.Summary(j))
				return nil
			}
			drills, _, err := drill.LoadDir(filepath.Join(projectDir, "drills"))
			if err != nil {
				return err
			}
			if records == "" {
				records = defaultRecords()
			}
			now := time.Now()
			est, err := loadEstate(cmd.Context(), records, now)
			if err != nil {
				return err
			}
			board, err := report.Build(tag.Store{Root: records}, est, drills, now)
			if err != nil {
				return err
			}
			if outDir == "" {
				outDir = filepath.Join(projectDir, "report")
			}
			path, err := report.Write(outDir, board)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Wrote", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&records, "records", "", "where records live")
	cmd.Flags().StringVar(&outDir, "out", "", "where to write the board")
	cmd.Flags().StringVar(&summary, "summary", "", "print the step summary from a --json result file")
	return cmd
}

// loadEstate reads the estate from Postgres when configured, otherwise it merges
// snapshots in memory. A database failure falls back to snapshots, the truth.
func loadEstate(ctx context.Context, records string, now time.Time) (*graph.Estate, error) {
	snaps := filepath.Join(records, "snapshots")
	if url := os.Getenv("FIREDRILL_DATABASE_URL"); url != "" {
		store, err := pg.Open(ctx, url)
		if err == nil {
			defer func() { _ = store.Close(ctx) }()
			if _, err = store.Sync(ctx, snaps, now); err == nil {
				if est, err := store.Estate(ctx); err == nil {
					return est, nil
				}
			}
		}
		fmt.Fprintln(os.Stderr, "WARN  Postgres was not usable, using snapshots")
	}
	return graph.RebuildEstate(snaps, now)
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file]",
		Short: "Check drill files against the format and the list of facts",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var issues []drill.Issue
			count := 0
			if len(args) == 1 {
				data, err := os.ReadFile(args[0])
				if err != nil {
					return err
				}
				_, issues = drill.Load(args[0], data)
				count = 1
			} else {
				drills, iss, err := drill.LoadDir(filepath.Join(projectDir, "drills"))
				if err != nil {
					return err
				}
				issues, count = iss, len(drills)
			}
			for _, i := range issues {
				fmt.Fprintln(cmd.OutOrStdout(), i)
			}
			if drill.HasErrors(issues) {
				return exitError{1}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%d drills valid, against %d facts.\n", count, len(facts.All()))
			return nil
		},
	}
}
