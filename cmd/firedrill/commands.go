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
	"github.com/sk1122/firedrill/internal/hub"
	"github.com/sk1122/firedrill/internal/report"
	"github.com/sk1122/firedrill/internal/run"
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
	lock := &hub.Lock{Hub: hub.DefaultRepo, Drills: map[string]hub.LockEntry{}}
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
		lock.Drills[strings.TrimSuffix(p, ".drill.yaml")] = hub.LockEntry{Source: "builtin", SHA256: drill.Hash(data)}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		return count, err
	}
	// The lock lets hub update tell an untouched starter drill from an edited one.
	return count, hub.WriteLock(filepath.Dir(dest), lock)
}

// guideBase is where the connector guides are published.
const guideBase = "https://github.com/sk1122/firedrill/blob/main/docs/connect/"

// guides names each system's guide.
var guides = map[string]string{
	"github": "github.md", "gcp": "gcp.md", "google": "google-workspace.md", "aws": "aws.md",
	"files": "repo-files.md", "hr": "hr.md", "semgrep": "semgrep.md",
	"dns": "domains.md", "ctlog": "domains.md", "web": "domains.md",
	"anthropic": "anthropic.md", "openai": "openai.md",
}

var setupNotes = map[string]string{
	"github": `GitHub needs read access: Metadata, Administration, Environments and Contents on the repos,
and organization Members to read who can reach them: members, teams and outside collaborators.
On a laptop the GitHub CLI's login is reused. A gh token acts as whoever is logged in.
In CI use a fine-grained token as FIREDRILL_GITHUB_TOKEN, limited to the listed repos.
With a read-only token, ruleset bypass lists come from firedrill export rulesets, or read as unknown.
Without Members, repo settings are still read and only the people facts give ERROR.`,
	"google": `Google needs a service account with domain-wide delegation, approved once by a super admin.
1. Create a service account and a JSON key in Google Cloud.
2. In the Admin console, grant it the scopes
   https://www.googleapis.com/auth/admin.directory.user.readonly,
   https://www.googleapis.com/auth/admin.directory.user.security (the OAuth grants users gave
   third-party apps; Google has no read-only scope for it, so the guard allows only GET) and
   https://www.googleapis.com/auth/admin.directory.group.readonly (the members of groups that
   hold a Google Cloud role, and of groups nested in them; no other group's members are read).
3. Set google.domain and google.admin_email in config.yaml, the admin it acts as.
4. Set GOOGLE_APPLICATION_CREDENTIALS to the key file's path.
Without the second scope, users are still read and only access/third-party-apps-reviewed gives ERROR.
Without the third, who holds a role through a group reads as unknown, and the people facts give WARN.`,
	"aws": `AWS uses the default credential chain, one profile per account under aws.accounts in config.yaml.
Attach this read policy to each:
  iam:GetAccountAuthorizationDetails, iam:GetAccessKeyLastUsed, iam:ListAccessKeys,
  iam:GenerateCredentialReport, iam:GetCredentialReport,
  rds:DescribeDBInstances, rds:DescribeDBClusters, backup:ListCopyJobs
Databases are read in each region under aws.regions, or the profile's own region.`,
	"gcp": `Google Cloud reads through a reader service account with read roles only, and no key:
1. Turn on the iam, iamcredentials, cloudresourcemanager and policyanalyzer APIs in one
   project, and create a service account, for example firedrill-reader, there.
2. On each project, grant it Viewer, Security Reviewer, Activity Analysis Viewer and Role Viewer
   (roles/viewer, roles/iam.securityReviewer, roles/policyanalyzer.activityAnalysisViewer,
   roles/iam.roleViewer; the last reads the permissions of custom roles, which stay unknown without it).
3. Grant yourself Service Account Token Creator on it, then log in as it:
   gcloud auth application-default login --impersonate-service-account=<reader email>
The IAM API needs the cloud-platform scope, so the reader's roles keep it to reads. In CI, or instead, set
FIREDRILL_GCP_CREDENTIALS to a credentials file's path.
List projects under gcp.projects in config.yaml. Owner domains come from gcp.member_domains, or google.domain.
Cloud SQL backups are read through the sqladmin API, which Viewer covers: turn on
sqladmin.googleapis.com in the reader's own project, where calls are billed.
Name production projects under production in config.yaml; with none named, every project counts.
Reads use GET, plus POST getIamPolicy on each listed project and the token calls, each by exact URL.`,

	"files":   "Repo files need nothing for local checkouts: pass --path. Remote repos use the GitHub connection.",
	"hr":      "Export a CSV with the columns email,leave_date from your HR system, and set hr.leavers_csv in config.yaml.",
	"semgrep": "Run semgrep --json yourself and set semgrep.results in config.yaml. Firedrill reads the file and runs nothing.",
	"dns":     "DNS uses the system resolver. List domains in config.yaml and run firedrill verify-domain.",
	"ctlog":   "Certificate logs use the public crt.sh API, on domains verified with firedrill verify-domain.",
	"web":     "Web checks only reach hosts under domains verified with firedrill verify-domain.",
	"anthropic": `Anthropic needs an Admin API key (sk-ant-admin...) of your Claude Console organization.
An admin key is powerful: it can create and delete keys and change members. Firedrill only ever
sends it with GET to two paths, /v1/organizations/api_keys and /v1/organizations/workspaces; the
guard refuses anything else. Set FIREDRILL_ANTHROPIC_ADMIN_KEY to it; it is never written anywhere.
The Admin API shows no spend limit, so declare each workspace's limit in .firedrill/ai-keys.yaml.`,
	"openai": `OpenAI needs an Admin key of your organization.
An admin key is powerful: it can create and delete keys and change projects. Firedrill only ever
sends it with GET to the projects list, each project's API keys and spend limit, and the
organization's spend limit; the guard refuses anything else. Set FIREDRILL_OPENAI_ADMIN_KEY to it;
it is never written anywhere.`,
}

func connectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "connect <system>",
		Short: "Check access to a system, print its setup steps, and record it as connected",
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
			if g := guides[name]; g != "" {
				fmt.Fprintf(out, "\nStep by step: %s%s\n", guideBase, g)
			}
			ctx := cmd.Context()
			rc, err := prepareConnecting(ctx, nil, false, name)
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
			// github, google, aws, gcp, anthropic and openai reach the network, so
			// they run only once connect has recorded that someone connected them
			// on purpose.
			if err := config.MarkConnected(projectDir, name); err != nil {
				return fmt.Errorf("connected, but could not record it in config.yaml: %w", err)
			}
			fmt.Fprintf(out, "\nConnected. Read %d items. Recorded %s under connected in config.yaml.\n", len(g.Nodes("")), name)
			// A collection can fail on its own, such as a missing scope, while the
			// rest worked. Its drills will give ERROR or WARN until it is fixed.
			for _, n := range g.Nodes(graph.KindScan) {
				if msg, _ := n.Attrs["error"].(string); msg != "" {
					fmt.Fprintf(out, "Not readable yet: %s\n", msg)
				} else if msg, _ := n.Attrs["partial"].(string); msg != "" {
					fmt.Fprintf(out, "Read only in part: %s\n", msg)
				}
			}
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
				if lines := sourceLines(l.Header); len(lines) > 0 {
					fmt.Fprintln(out, "Sources:")
					for _, line := range lines {
						fmt.Fprintf(out, "  %s\n", line)
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

// sourceLines lists each fetch's source with its evidence tier, then each
// inferred field read. Tags written before tiers show the source alone.
func sourceLines(h tag.Header) []string {
	var out []string
	for _, e := range report.EvidenceOf(h) {
		line := e.Alias
		if e.Source != "" {
			line += "  " + e.Source
		}
		if e.Tier != "" {
			line += "  [" + e.Tier + "]"
		}
		out = append(out, line)
	}
	return out
}

func reportCmd() *cobra.Command {
	var records, outDir, summary, issuesURL string
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
				fmt.Fprint(cmd.OutOrStdout(), report.SummaryWith(j, issuesURL))
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
			// The noise rules come from config; without one, their defaults apply.
			noise := run.RulesOf(config.Config{})
			if p, err := config.Load(projectDir); err == nil {
				noise = run.RulesOf(p.Config)
			}
			board, err := report.Build(tag.Store{Root: records}, est, drills, now, noise)
			if err != nil {
				return err
			}
			changes, err := run.LatestDiff(records)
			if err != nil {
				return err
			}
			report.AddChanges(board, changes)
			// People, Agents and the graph pages read the latest run's snapshot.
			var latest *graph.Snapshot
			if files, err := run.RunSnapshots(filepath.Join(records, "snapshots")); err != nil {
				return err
			} else if len(files) > 0 {
				s, err := graph.ReadSnapshot(files[len(files)-1])
				if err != nil {
					return err
				}
				latest = &s
			}
			report.AddViews(board, latest, changes, now)
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
	cmd.Flags().StringVar(&issuesURL, "issues-url", "", "with --summary: the repo's issues page, to link each caught change to its drill's issue")
	return cmd
}

// loadEstate reads the estate from Postgres when configured and current with
// the snapshots, otherwise it merges snapshots in memory, the truth. It only
// reads: migrations and Sync happen in syncDatabase, after a run.
func loadEstate(ctx context.Context, records string, now time.Time) (*graph.Estate, error) {
	snaps := filepath.Join(records, "snapshots")
	if url := os.Getenv("FIREDRILL_DATABASE_URL"); url != "" {
		est, why := databaseEstate(ctx, url, snaps, now)
		if est != nil {
			return est, nil
		}
		fmt.Fprintln(os.Stderr, "WARN  Postgres "+why+", using snapshots")
	}
	return graph.RebuildEstate(snaps, now)
}

// databaseEstate reads the estate from a read-only connection, only when the
// database holds exactly what the snapshots hold. Otherwise it says why not.
func databaseEstate(ctx context.Context, url, snaps string, now time.Time) (*graph.Estate, string) {
	store, err := pg.OpenReadOnly(ctx, url)
	if err != nil {
		return nil, "was not usable"
	}
	defer func() { _ = store.Close(ctx) }()
	current, err := store.Current(ctx, snaps, now)
	if err != nil {
		return nil, "was not usable"
	}
	if !current {
		return nil, "is behind the snapshots until the next firedrill run"
	}
	est, err := store.Estate(ctx)
	if err != nil {
		return nil, "was not usable"
	}
	return est, ""
}

func testCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test [folder]",
		Short: "Run each drill's fixtures and check every case gives its expected verdict",
		Long: "Runs <slug>.test.yaml beside each drill. Every drill needs a passing, a failing and a " +
			"not-applicable case. With no folder, tests .firedrill/drills.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := filepath.Join(projectDir, "drills")
			if len(args) == 1 {
				dir = args[0]
			}
			out := cmd.OutOrStdout()
			results, problems, err := run.TestDir(dir)
			if err != nil {
				return err
			}
			failed, cases := 0, 0
			for _, p := range run.SortedKeys(results) {
				for _, c := range results[p] {
					cases++
					if !c.OK() {
						failed++
						fmt.Fprintf(out, "FAIL  %s  %q: want %s, got %s (%s)\n", p, c.Name, c.Expect, c.Got, c.Reason)
					}
				}
			}
			for _, p := range run.SortedKeys(problems) {
				fmt.Fprintf(out, "FAIL  %s: %s\n", p, problems[p])
			}
			fmt.Fprintf(out, "%d drills, %d cases, %d failing, %d drills with problems.\n", len(results), cases, failed, len(problems))
			if failed > 0 || len(problems) > 0 {
				return exitError{1}
			}
			return nil
		},
	}
}

func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file or folder]",
		Short: "Check drill files against the format and the list of facts",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var issues []drill.Issue
			count := 0
			dir := filepath.Join(projectDir, "drills")
			if len(args) == 1 {
				if st, err := os.Stat(args[0]); err == nil && st.IsDir() {
					dir = args[0]
				} else {
					dir = ""
				}
			}
			if dir == "" {
				data, err := os.ReadFile(args[0])
				if err != nil {
					return err
				}
				_, issues = drill.Load(args[0], data)
				count = 1
			} else {
				drills, iss, err := drill.LoadDir(dir)
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
