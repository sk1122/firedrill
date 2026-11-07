package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/graph/pg"
	"github.com/sk1122/firedrill/internal/report"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

var (
	styleFail = lipgloss.NewStyle().Foreground(lipgloss.Color("#D3261A")).Bold(true)
	stylePass = lipgloss.NewStyle().Foreground(lipgloss.Color("#0B8A4E"))
	styleWarn = lipgloss.NewStyle().Foreground(lipgloss.Color("#E8A317"))
	styleDim  = lipgloss.NewStyle().Foreground(lipgloss.Color("#8A877C"))
	styleBold = lipgloss.NewStyle().Bold(true)
)

type runFlags struct {
	drill, pack, jsonPath, failOn, records string
	paths                                  []string
	dryRun, includeHome, publicOK          bool
}

func runCmd() *cobra.Command {
	var f runFlags
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run every drill",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			code, err := doRun(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), f)
			if err != nil {
				return err
			}
			if code != 0 {
				return exitError{code}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&f.drill, "drill", "", "run one drill")
	cmd.Flags().StringVar(&f.pack, "pack", "", "run one pack")
	cmd.Flags().StringSliceVar(&f.paths, "path", nil, "local checkouts to read")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "print every call without making any")
	cmd.Flags().StringVar(&f.jsonPath, "json", "", "write the full result to a file")
	cmd.Flags().BoolVar(&f.includeHome, "include-home", false, "also read user-level agent files")
	cmd.Flags().StringVar(&f.failOn, "fail-on", "", `exit 1 while safeguards are open: "open" for critical and high, "any" for all`)
	cmd.Flags().BoolVar(&f.publicOK, "public-ok", false, "write records even in a public repo")
	cmd.Flags().StringVar(&f.records, "records", "", "where records live (default .firedrill/local)")
	return cmd
}

func selectDrills(all []*drill.Drill, id, pack string) ([]*drill.Drill, error) {
	if id == "" && pack == "" {
		return all, nil
	}
	var out []*drill.Drill
	for _, d := range all {
		p, _, _ := strings.Cut(d.ID, "/")
		if (id != "" && d.ID == id) || (pack != "" && p == pack) {
			out = append(out, d)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no drill matches %s%s", id, pack)
	}
	return out, nil
}

func doRun(ctx context.Context, out, errOut io.Writer, f runFlags) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if f.failOn != "" && f.failOn != "open" && f.failOn != "any" {
		return 0, fmt.Errorf("--fail-on takes open or any")
	}
	rc, err := prepare(ctx, f.paths, f.includeHome)
	if err != nil {
		return 0, err
	}
	for _, w := range rc.warns {
		fmt.Fprintln(errOut, w)
	}
	drills, err := selectDrills(rc.drills, f.drill, f.pack)
	if err != nil {
		return 0, err
	}
	records := f.records
	if records == "" {
		records = defaultRecords()
	}
	stream := "local"
	if inCI() {
		stream = "ci"
	}
	allowed := recordsAllowed(ctx, rc.scope, f.publicOK)
	warnSaltMismatch(errOut, records, drills, rc.scope.Hasher)
	res, err := run.Run(ctx, run.Config{
		Project: rc.project, Drills: drills, Connectors: connector.All(), Scope: rc.scope,
		Stream: stream, RanBy: ranBy(), Records: records, WriteRecords: allowed, DryRun: f.dryRun,
	})
	if err != nil {
		return 0, err
	}
	if f.dryRun {
		fmt.Fprintln(out, "Calls this run would make. None were made.")
		for _, c := range res.Calls {
			fmt.Fprintln(out, " ", c)
		}
		return 0, nil
	}
	_ = rc.scope.Log.WriteFile(filepath.Join(projectDir, "local", "calls.jsonl"))
	if res.Fatal != "" {
		fmt.Fprintln(errOut, styleFail.Render("ERROR")+"  "+res.Fatal)
		return 2, nil
	}
	code := run.ExitCode(res.Outcomes, f.failOn)
	if f.jsonPath != "" && allowed {
		j := report.BuildJSON(res, rc.scope.Now, code)
		j.DefaultOwner = rc.project.Config.DefaultOwner
		if err := report.WriteJSON(f.jsonPath, j); err != nil {
			return 0, err
		}
	}
	if allowed {
		printRun(out, res, len(drills))
		syncDatabase(ctx, errOut, records, rc)
	} else {
		printCounts(out, res)
		fmt.Fprintln(errOut, "This repo is public, so no records were written and no evidence was printed. Move .firedrill to a private repo, or pass --public-ok.")
	}
	return code, nil
}

// syncDatabase keeps the optional Postgres estate up to date. It is a cache, so a
// failure warns and never changes a verdict.
func syncDatabase(ctx context.Context, errOut io.Writer, records string, rc *runContext) {
	url := os.Getenv("FIREDRILL_DATABASE_URL")
	if url == "" {
		return
	}
	store, err := pg.Open(ctx, url)
	if err != nil {
		fmt.Fprintln(errOut, styleWarn.Render("WARN")+"  Postgres: "+err.Error())
		return
	}
	defer func() { _ = store.Close(ctx) }()
	if _, err := store.Sync(ctx, filepath.Join(records, "snapshots"), rc.scope.Now); err != nil {
		fmt.Fprintln(errOut, styleWarn.Render("WARN")+"  Postgres: "+err.Error())
	}
}

// warnSaltMismatch warns a laptop whose salt differs from the records', since
// its hashes, and waivers written from them, would not match.
func warnSaltMismatch(errOut io.Writer, records string, drills []*drill.Drill, h graph.Hasher) {
	store := tag.Store{Root: records}
	keys, err := store.Keys()
	if err != nil {
		return
	}
	for _, k := range keys {
		l, err := store.Latest(k.DrillID, k.TargetSlug)
		if err != nil || l == nil {
			continue
		}
		if l.Header.SaltPrint != "" && l.Header.SaltPrint != h.Fingerprint() {
			fmt.Fprintln(errOut, styleWarn.Render("WARN")+"  Your salt does not match the latest record. Secret hashes and waivers will not match. Set FIREDRILL_SALT to your team's value.")
		}
		return
	}
	_ = drills
}

func styleVerdict(v string) string {
	s := fmt.Sprintf("%-5s", v)
	switch v {
	case tag.Fail:
		return styleFail.Render(s)
	case tag.Pass:
		return stylePass.Render(s)
	case tag.Warn, tag.Error:
		return styleWarn.Render(s)
	}
	return styleDim.Render(s)
}

func printRun(out io.Writer, res *run.Result, total int) {
	ran := map[string]bool{}
	for _, o := range res.Outcomes {
		if o.Verdict != tag.Skip {
			ran[o.Drill.ID] = true
		}
	}
	fmt.Fprintf(out, "%s %s   %d drills ran · %d waiting · read-only\n\n", styleBold.Render("FIREDRILL"), run.Version, len(ran), len(res.Skips))
	idWidth, targetWidth := 0, 0
	for _, o := range res.Outcomes {
		if len(o.Drill.ID) > idWidth {
			idWidth = len(o.Drill.ID)
		}
		if len(o.Target) > targetWidth {
			targetWidth = len(o.Target)
		}
	}
	for _, o := range res.Outcomes {
		line := fmt.Sprintf("%s %-*s  %-*s", styleVerdict(o.Verdict), idWidth, o.Drill.ID, targetWidth, o.Target)
		if o.Reason != "" {
			line += "  " + o.Reason
		}
		if o.Waived {
			line += "  " + styleDim.Render("waived")
		}
		if o.Unverified != "" {
			line += "  " + styleDim.Render(o.Unverified)
		}
		fmt.Fprintln(out, strings.TrimRight(line, " "))
	}
	if len(res.Skips) > 0 {
		fmt.Fprintf(out, "\n%s\n", styleDim.Render(waitingLine(res.Skips)))
	}
	a := res.Attention
	fmt.Fprintf(out, "\nNeeds attention: %d newly open, %d closed", len(a.NewlyOpen), len(a.NewlyClosed))
	if n := len(a.OpenUnverified); n > 0 {
		fmt.Fprintf(out, ", %d open and unverified", n)
	}
	if n := len(a.ClosedUnverified); n > 0 {
		fmt.Fprintf(out, ", %d closed and unverified", n)
	}
	fmt.Fprintln(out)
	if len(a.NewlyOpen) > 0 {
		fmt.Fprintf(out, "next: fix, then  firedrill verify %s\n", a.NewlyOpen[0].Drill.ID)
	}
	_ = total
}

// waitingLine says in one line what connects the waiting drills.
func waitingLine(skips []run.Skip) string {
	hints := map[string]string{
		"github": "connect github", "google": "connect google (about 10 minutes, needs a super admin)",
		"aws": "connect aws (about 2 minutes)", "hr": "an HR leavers CSV", "semgrep": "a Semgrep results file",
		"web": "verify-domain (one DNS record)", "dns": "verify-domain (one DNS record)", "ctlog": "verify-domain (one DNS record)",
		"a verified domain": "verify-domain (one DNS record)", "a target from repos": "--path, or connect github",
	}
	seen := map[string]bool{}
	var parts []string
	for _, s := range skips {
		need := strings.TrimPrefix(s.Needs, "needs ")
		h := hints[need]
		if h == "" {
			h = need
		}
		if !seen[h] {
			seen[h] = true
			parts = append(parts, h)
		}
	}
	sort.Strings(parts)
	return fmt.Sprintf("%d drills waiting: %s.", len(skips), strings.Join(parts, ", "))
}

// printCounts is all a public repo gets.
func printCounts(out io.Writer, res *run.Result) {
	c := map[string]int{}
	for _, o := range res.Outcomes {
		c[o.Verdict]++
	}
	fmt.Fprintf(out, "PASS %d  FAIL %d  WARN %d  N/A %d  SKIP %d  ERROR %d\n", c[tag.Pass], c[tag.Fail], c[tag.Warn], c[tag.NA], c[tag.Skip], c[tag.Error])
}

func verifyCmd() *cobra.Command {
	var f runFlags
	cmd := &cobra.Command{
		Use:   "verify <drill>",
		Short: "Rerun one drill and report whether its safeguard is now closed",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f.drill = args[0]
			var buf strings.Builder
			if _, err := doRun(cmd.Context(), &buf, cmd.ErrOrStderr(), f); err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), buf.String())
			records := f.records
			if records == "" {
				records = defaultRecords()
			}
			store := tag.Store{Root: records}
			keys, err := store.Keys()
			if err != nil {
				return err
			}
			open, closed := 0, 0
			for _, k := range keys {
				if k.DrillID != args[0] {
					continue
				}
				l, err := store.Latest(k.DrillID, k.TargetSlug)
				if err != nil || l == nil {
					continue
				}
				switch l.Header.State {
				case tag.Open:
					open++
				case tag.Closed:
					closed++
				}
			}
			if open > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%s  %s: %d target still open\n", styleFail.Render("OPEN"), args[0], open)
				return exitError{1}
			}
			if closed == 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "\n%s: no run has produced PASS yet, so it is not closed\n", args[0])
				return exitError{1}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\n%s  %s\n", stylePass.Render("CLOSED"), args[0])
			if !inCI() {
				fmt.Fprintln(cmd.OutOrStdout(), "This is your local record. It closes in the canonical records on the next CI run, or when someone triggers the workflow by hand.")
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&f.paths, "path", nil, "local checkouts to read")
	cmd.Flags().BoolVar(&f.includeHome, "include-home", false, "also read user-level agent files")
	cmd.Flags().StringVar(&f.records, "records", "", "where records live (default .firedrill/local)")
	return cmd
}
