package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

func diffCmd() *cobra.Command {
	var records, from, to string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Show what changed between two runs",
		Long: "Show what changed between two runs. With no flags it compares the two most recent\n" +
			"snapshots of the same stream. It reads only local records and writes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if records == "" {
				records = defaultRecords()
			}
			rec, err := loadDiff(records, from, to)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if asJSON {
				b, err := json.MarshalIndent(rec, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(out, string(b))
				return nil
			}
			printDiff(out, rec)
			return nil
		},
	}
	cmd.Flags().StringVar(&records, "records", "", "where records live")
	cmd.Flags().StringVar(&from, "from", "", "the earlier snapshot: a file, or its timestamp such as 2026-11-05T09-00-00Z")
	cmd.Flags().StringVar(&to, "to", "", "the later snapshot: a file, or its timestamp (default the latest)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the diff as JSON")
	return cmd
}

// loadDiff picks the two snapshots, then uses the diff the run stored for
// them, or works it out from the files when there is none.
func loadDiff(records, from, to string) (*run.DiffRecord, error) {
	dir := filepath.Join(records, "snapshots")
	files, err := run.RunSnapshots(dir)
	if err != nil {
		return nil, err
	}
	toPath := ""
	if to != "" {
		if toPath, err = findSnapshot(dir, files, to); err != nil {
			return nil, err
		}
	} else if len(files) > 0 {
		toPath = files[len(files)-1]
	}
	if toPath == "" {
		return nil, fmt.Errorf("no snapshots in %s yet. Run firedrill run twice to see what changed", dir)
	}
	fromPath := ""
	if from != "" {
		if fromPath, err = findSnapshot(dir, files, from); err != nil {
			return nil, err
		}
	} else {
		later, err := graph.ReadSnapshot(toPath)
		if err != nil {
			return nil, err
		}
		if fromPath, _, err = run.PreviousSnapshot(dir, later.Stream, toPath); err != nil {
			return nil, err
		}
		if fromPath == "" {
			return nil, fmt.Errorf("only one run of this stream in %s. Run firedrill run again to see what changed", dir)
		}
	}
	if stored, err := run.ReadDiff(filepath.Join(records, "diffs", run.DiffName(toPath))); err == nil && stored.FromSnapshot == filepath.Base(fromPath) {
		return stored, nil
	}
	caught, err := run.CaughtByStore(tag.Store{Root: records})
	if err != nil {
		return nil, err
	}
	return run.CompareFiles(fromPath, toPath, caught)
}

// findSnapshot accepts a path to a snapshot file or a timestamp naming one.
func findSnapshot(dir string, files []string, want string) (string, error) {
	if info, err := os.Stat(want); err == nil && !info.IsDir() {
		return want, nil
	}
	stamp := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(want), ".gz"), ".json")
	stamp = strings.ReplaceAll(stamp, ":", "-")
	if t, err := time.Parse(time.RFC3339, want); err == nil {
		stamp = strings.TrimSuffix(graph.SnapshotName(t), ".json.gz")
	}
	for _, f := range files {
		if strings.HasPrefix(filepath.Base(f), stamp) {
			return f, nil
		}
	}
	return "", fmt.Errorf("no snapshot in %s matches %s", dir, want)
}

func diffTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

func printDiff(out io.Writer, rec *run.DiffRecord) {
	if len(rec.Changes) == 0 {
		fmt.Fprintf(out, "Nothing changed since %s.\n", diffTime(rec.From))
		printSkipped(out, rec.Skipped)
		return
	}
	weak, other := rec.Counts()
	fmt.Fprintf(out, "%s  %s to %s · %d weakening, %d other\n", styleBold.Render("CHANGES"), diffTime(rec.From), diffTime(rec.To), weak, other)
	section := ""
	for _, g := range run.GroupChanges(rec.Changes) {
		title := "Other changes"
		if g.Weakening {
			title = "Weakenings"
		}
		if title != section {
			section = title
			n := other
			if g.Weakening {
				n = weak
			}
			head := fmt.Sprintf("%s (%d)", title, n)
			if g.Weakening {
				head = styleFail.Render(head)
			}
			fmt.Fprintf(out, "\n%s\n", head)
		}
		fmt.Fprintf(out, "  %s (%d)\n", styleBold.Render(g.Title), len(g.Changes))
		for _, c := range g.Changes {
			line := "    " + c.Summary
			if g.Person != "" {
				line = "    " + graph.ChangeLabel(c.Type) + ": " + c.Summary
			}
			if c.Actor != "" {
				line += "  " + styleDim.Render("by "+c.Actors()+" ("+c.ActorSource+")")
			}
			if by := caughtBy(c); by != "" {
				line += "  " + styleDim.Render(by)
			}
			fmt.Fprintln(out, line)
		}
	}
	printSkipped(out, rec.Skipped)
	printAudit(out, rec.Audit)
}

// printAudit says which audit sources could not say who made a change, so
// their changes name only the window.
func printAudit(out io.Writer, a *run.AuditNote) {
	if a == nil {
		return
	}
	for _, s := range a.NotReadable {
		fmt.Fprintln(out, styleDim.Render("Audit source not readable, so changes name only the window: "+s))
	}
	if a.NotAsked > 0 {
		fmt.Fprintln(out, styleDim.Render(fmt.Sprintf("%d audit questions not asked: the cap of %d calls per run was reached.", a.NotAsked, a.Cap)))
	}
}

func printSkipped(out io.Writer, skipped []string) {
	if len(skipped) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%s\n", styleWarn.Render(fmt.Sprintf("Not compared (%d)", len(skipped))))
	for _, s := range skipped {
		fmt.Fprintln(out, "  "+s)
	}
}

// caughtBy names the drills that also caught a change, so the story is told once.
func caughtBy(c graph.Change) string {
	if len(c.CaughtBy) == 0 {
		return ""
	}
	seen := map[string]bool{}
	var ids []string
	for _, r := range c.CaughtBy {
		if !seen[r.Drill] {
			seen[r.Drill] = true
			ids = append(ids, r.Drill)
		}
	}
	return "also caught by " + strings.Join(ids, ", ")
}

// printChangedSinceLast is the short block after a run. A public repo gets
// counts only.
func printChangedSinceLast(out io.Writer, rec *run.DiffRecord, counts bool) {
	if rec == nil {
		return
	}
	weak, other := rec.Counts()
	if counts {
		fmt.Fprintf(out, "Changed since last run: %d weakening, %d other.\n", weak, other)
		return
	}
	fmt.Fprintln(out)
	if weak+other == 0 {
		fmt.Fprintf(out, "Nothing changed since last run (%s).\n", diffTime(rec.From))
	} else {
		fmt.Fprintf(out, "Changed since last run (%s): %d weakening, %d other. Run firedrill diff to see them.\n", diffTime(rec.From), weak, other)
	}
	shown := 0
	for _, c := range rec.Changes {
		if !c.Weakening || shown == 5 {
			continue
		}
		shown++
		line := "  " + styleFail.Render("!") + " " + c.Summary
		if by := caughtBy(c); by != "" {
			line += "  " + styleDim.Render(by)
		}
		fmt.Fprintln(out, line)
	}
	if n := len(rec.Skipped); n > 0 {
		fmt.Fprintln(out, styleDim.Render(fmt.Sprintf("  %d not compared, since they were not read in both runs.", n)))
	}
}
