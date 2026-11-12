package report

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

// MaxSummaryChanges bounds the changes listed in a step summary or the weekly
// issue, so the issue body stays well under GitHub's size limit. The counts
// above the list are always whole.
const MaxSummaryChanges = 50

// DiffSummary is the snapshot diff in the JSON result: counts, each change in
// reading order (weakenings first), what was not compared, and the audit note.
// It carries change summaries, short hashed IDs and fingerprints only: no
// address, login or secret value is ever in a diff.
type DiffSummary struct {
	From      time.Time       `json:"from"`
	To        time.Time       `json:"to"`
	Weakening int             `json:"weakening"`
	Other     int             `json:"other"`
	Changes   []DiffEntry     `json:"changes"`
	Skipped   []string        `json:"skipped"`
	Audit     *run.AuditNote  `json:"audit,omitempty"`
	Record    string          `json:"record,omitempty"` // the stored diff's file name
	Groups    []DiffGroupJSON `json:"groups,omitempty"`
}

// DiffGroupJSON is one heading of the grouped diff and how many changes it holds.
type DiffGroupJSON struct {
	Title     string `json:"title"`
	Weakening bool   `json:"weakening"`
	Count     int    `json:"count"`
}

// DiffEntry is one change.
type DiffEntry struct {
	Type      string `json:"type"`
	Label     string `json:"label"`
	Summary   string `json:"summary"`
	System    string `json:"system"`
	Weakening bool   `json:"weakening"`
	// Person is the short hashed ID of the person the change's node belongs to.
	Person string `json:"person,omitempty"`
	// Actor names who made it, as short IDs or labels, when an audit source
	// said so; otherwise it happened between From and To.
	Actor       string     `json:"actor,omitempty"`
	ActorSource string     `json:"actor_source,omitempty"`
	ActedAt     *time.Time `json:"acted_at,omitempty"`
	CaughtBy    []CaughtBy `json:"caught_by,omitempty"`
}

// CaughtBy is a drill verdict that also caught a change, with the title of the
// issue the workflow keeps for it.
type CaughtBy struct {
	Drill  string `json:"drill"`
	Target string `json:"target,omitempty"`
	Issue  string `json:"issue_title"`
}

// IssueTitle is the title of the per-safeguard issue the workflow opens.
func IssueTitle(drill, target string) string {
	return "Firedrill: " + drill + " on " + targetLabel(target)
}

// DiffSummaryOf turns a stored diff into the JSON result's diff.
func DiffSummaryOf(rec *run.DiffRecord) *DiffSummary {
	if rec == nil {
		return nil
	}
	d := &DiffSummary{From: rec.From.UTC(), To: rec.To.UTC(), Skipped: rec.Skipped, Audit: rec.Audit, Changes: []DiffEntry{}}
	if d.Skipped == nil {
		d.Skipped = []string{}
	}
	if rec.ToSnapshot != "" {
		d.Record = run.DiffName(rec.ToSnapshot)
	}
	d.Weakening, d.Other = rec.Counts()
	for _, g := range run.GroupChanges(rec.Changes) {
		d.Groups = append(d.Groups, DiffGroupJSON{Title: g.Title, Weakening: g.Weakening, Count: len(g.Changes)})
		for _, c := range g.Changes {
			e := DiffEntry{Type: c.Type, Label: graph.ChangeLabel(c.Type), Summary: c.Summary, System: c.System, Weakening: c.Weakening,
				Person: c.Person, Actor: c.Actors(), ActorSource: c.ActorSource, ActedAt: c.ActedAt}
			for _, r := range c.CaughtBy {
				e.CaughtBy = append(e.CaughtBy, CaughtBy{Drill: r.Drill, Target: r.Target, Issue: IssueTitle(r.Drill, r.Target)})
			}
			d.Changes = append(d.Changes, e)
		}
	}
	return d
}

// SummaryWith renders the step summary, which is also the weekly issue's body:
// counts, open safeguards, what needs attention, and what changed since the
// last run, weakenings first. With issuesURL (the repo's issues page), each
// change a drill also caught links to that drill's issue.
func SummaryWith(j JSONResult, issuesURL string) string {
	var sb strings.Builder
	sb.WriteString(Summary(j))
	var open []Finding
	for _, r := range j.Results {
		if r.State == tag.Open {
			open = append(open, r)
		}
	}
	if len(open) > 0 {
		fmt.Fprintf(&sb, "### Open safeguards (%d)\n\n", len(open))
		for _, f := range open {
			fmt.Fprintf(&sb, "- `%s` on `%s` (%s), latest %s%s\n", f.Drill, targetLabel(f.Target), f.Severity, f.Verdict, issueLink(issuesURL, f.Drill, f.Target))
		}
		sb.WriteString("\n")
	}
	writeDiff(&sb, j.Diff, issuesURL)
	return sb.String()
}

func issueLink(issuesURL, drill, target string) string {
	if issuesURL == "" {
		return ""
	}
	q := url.QueryEscape(`is:issue in:title "` + IssueTitle(drill, target) + `"`)
	return fmt.Sprintf(" ([issue](%s?q=%s))", strings.TrimRight(issuesURL, "/"), q)
}

func writeDiff(sb *strings.Builder, d *DiffSummary, issuesURL string) {
	sb.WriteString("### What changed since the last run\n\n")
	if d == nil {
		sb.WriteString("No earlier run of this stream to compare with.\n")
		return
	}
	fmt.Fprintf(sb, "%s to %s · **%d weakening**, %d other\n\n", d.From.Format("2006-01-02 15:04 UTC"), d.To.Format("2006-01-02 15:04 UTC"), d.Weakening, d.Other)
	if len(d.Changes) == 0 {
		sb.WriteString("Nothing changed.\n")
	}
	shown := 0
	section := ""
	for _, c := range d.Changes {
		if shown == MaxSummaryChanges {
			fmt.Fprintf(sb, "\n…and %d more. Run `firedrill diff` on the records, or open the board.\n", len(d.Changes)-shown)
			break
		}
		title := "Other changes"
		if c.Weakening {
			title = "Weakenings"
		}
		if title != section {
			section = title
			fmt.Fprintf(sb, "**%s**\n\n", title)
		}
		shown++
		line := fmt.Sprintf("- %s: %s", c.Label, mdSafe(c.Summary))
		if c.Actor != "" {
			line += fmt.Sprintf(" — by %s", mdSafe(c.Actor))
			if c.ActedAt != nil {
				line += " at " + c.ActedAt.UTC().Format("2006-01-02 15:04 UTC")
			}
			line += " (" + c.ActorSource + ")"
		} else if c.Person != "" {
			line += " — person " + c.Person
		}
		for _, by := range c.CaughtBy {
			line += fmt.Sprintf(" · caught by `%s` on `%s`%s", by.Drill, targetLabel(by.Target), issueLink(issuesURL, by.Drill, by.Target))
		}
		sb.WriteString(line + "\n")
	}
	if len(d.Changes) > 0 {
		sb.WriteString("\n")
	}
	if len(d.Skipped) > 0 {
		fmt.Fprintf(sb, "**Not compared (%d)**\n\n", len(d.Skipped))
		for _, s := range d.Skipped {
			sb.WriteString("- " + mdSafe(s) + "\n")
		}
		sb.WriteString("\n")
	}
	if a := d.Audit; a != nil {
		for _, s := range a.NotReadable {
			sb.WriteString("- Audit source not readable, so its changes name only the window: " + mdSafe(s) + "\n")
		}
		if a.NotAsked > 0 {
			fmt.Fprintf(sb, "- %d audit questions not asked: the cap of %d calls per run was reached.\n", a.NotAsked, a.Cap)
		}
	}
}

// mdSafe keeps a line from opening markdown structure or mentioning anyone:
// it neutralizes @ and HTML angle brackets.
func mdSafe(s string) string {
	r := strings.NewReplacer("@", "@\u200b", "<", "&lt;", ">", "&gt;", "\n", " ", "\r", " ")
	return r.Replace(s)
}
