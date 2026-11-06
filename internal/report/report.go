// Package report writes the static HTML board, the JSON result and the step
// summary. The board needs no server, no account and no network.
package report

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

//go:embed assets
var assets embed.FS

// LastRuns is how many runs each lamp shows.
const LastRuns = 8

// Run is one past verdict on a safeguard.
type Run struct {
	Verdict string
	Class   string
	Date    string
}

// Safeguard is one drill and target on the board.
type Safeguard struct {
	DrillID    string
	Rule       string
	Target     string
	Verdict    string
	State      string
	Lamp       string
	Label      string
	Owner      string
	Reason     string
	Severity   string
	Waived     bool
	Unverified bool
	Runs       []Run
	Chain      string
	Slug       string
}

// Pack groups safeguards.
type Pack struct {
	Name       string
	Safeguards []Safeguard
}

// Item is one thing in the estate.
type Item struct {
	ID       string
	Kind     string
	Name     string
	Live     bool
	Slug     string
	Verdicts []ItemVerdict
	Seen     string
}

// ItemVerdict is one verdict that read an item.
type ItemVerdict struct {
	DrillID, Target, Verdict, Class, Date string
}

// AttentionRow is one change the board leads with.
type AttentionRow struct {
	Kind, DrillID, Target, Class string
}

// Board is everything the templates need.
type Board struct {
	Generated string
	Counts    Counts
	Attention []AttentionRow
	Packs     []Pack
	Untouched []Item
	Unowned   []Item
	Items     []Item
	Fonts     template.CSS
}

// Counts summarizes the latest verdicts and states.
type Counts struct {
	Open, Closed, Unknown, Retired, Pass, Fail, Warn, NA, Skip, Error, Total int
}

// coverageKinds are what the coverage view lists. Scan records and findings are
// not things anyone owns.
var coverageKinds = map[string]bool{
	graph.KindGitHubRepo: true, graph.KindTargetRepo: true, graph.KindEnvironment: true, graph.KindHost: true,
	graph.KindIdentityUser: true, graph.KindAWSPrincipal: true, graph.KindAgentConfig: true, graph.KindWorkflow: true,
	graph.KindTFBucket: true,
}

// Build assembles the board from tags and the estate.
func Build(store tag.Store, est *graph.Estate, drills []*drill.Drill, now time.Time) (*Board, error) {
	rules := map[string]string{}
	for _, d := range drills {
		rules[d.ID] = d.Safeguard
	}
	keys, err := store.Keys()
	if err != nil {
		return nil, err
	}
	b := &Board{Generated: now.UTC().Format("2006-01-02 15:04 UTC")}
	packs := map[string][]Safeguard{}
	reads := map[string][]ItemVerdict{}
	for _, k := range keys {
		hist, err := store.History(k.DrillID, k.TargetSlug)
		if err != nil {
			return nil, err
		}
		if len(hist) == 0 {
			continue
		}
		last := hist[len(hist)-1].Header
		sg := Safeguard{
			DrillID: k.DrillID, Rule: rules[k.DrillID], Target: last.Target, Verdict: last.Verdict, State: last.State,
			Owner: last.Owner, Reason: last.Reason, Severity: last.Severity, Waived: last.Waived,
			Slug: tag.Slug(k.DrillID + "-" + k.TargetSlug),
		}
		sg.Lamp, sg.Label = lamp(last.Verdict, last.State)
		sg.Unverified = (last.State == tag.Open && last.Verdict != tag.Fail) || (last.State == tag.Closed && last.Verdict != tag.Pass)
		start := len(hist) - LastRuns
		if start < 0 {
			start = 0
		}
		for _, t := range hist[start:] {
			sg.Runs = append(sg.Runs, Run{Verdict: t.Header.Verdict, Class: verdictClass(t.Header.Verdict), Date: t.Header.Time.Format("2006-01-02")})
		}
		st := tag.VerifyChain(hist)
		switch {
		case !st.OK:
			sg.Chain = "chain broken"
		case st.Redacted > 0:
			sg.Chain = fmt.Sprintf("%d redacted", st.Redacted)
		}
		if row, ok := attentionOf(hist, sg); ok {
			b.Attention = append(b.Attention, row)
		}
		pack, _, _ := strings.Cut(k.DrillID, "/")
		packs[pack] = append(packs[pack], sg)
		count(&b.Counts, last)
		for _, t := range hist {
			for _, id := range t.Evidence.Read {
				reads[id] = append(reads[id], ItemVerdict{
					DrillID: t.Header.DrillID, Target: t.Header.Target, Verdict: t.Header.Verdict,
					Class: verdictClass(t.Header.Verdict), Date: t.Header.Time.Format("2006-01-02"),
				})
			}
		}
	}
	names := make([]string, 0, len(packs))
	for n := range packs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		list := packs[n]
		sort.Slice(list, func(i, j int) bool {
			if a, b := list[i].State == tag.Open, list[j].State == tag.Open; a != b {
				return a
			}
			if list[i].DrillID != list[j].DrillID {
				return list[i].DrillID < list[j].DrillID
			}
			return list[i].Target < list[j].Target
		})
		b.Packs = append(b.Packs, Pack{Name: n, Safeguards: list})
	}
	sort.SliceStable(b.Attention, func(i, j int) bool {
		a, c := attentionRank[b.Attention[i].Kind], attentionRank[b.Attention[j].Kind]
		if a != c {
			return a < c
		}
		return b.Attention[i].DrillID+b.Attention[i].Target < b.Attention[j].DrillID+b.Attention[j].Target
	})
	if est != nil {
		owned := ownersOf(est)
		for _, it := range est.Sorted() {
			if !coverageKinds[it.Kind] {
				continue
			}
			item := Item{ID: string(it.ID), Kind: it.Kind, Name: displayName(it), Live: !it.Gone, Slug: tag.Slug(string(it.ID)),
				Verdicts: reads[string(it.ID)], Seen: it.LastSeen.Format("2006-01-02")}
			b.Items = append(b.Items, item)
			if it.Gone {
				continue
			}
			if len(item.Verdicts) == 0 {
				b.Untouched = append(b.Untouched, item)
			}
			if needsOwner(it) && !owned[it.ID] {
				b.Unowned = append(b.Unowned, item)
			}
		}
	}
	return b, nil
}

var attentionRank = map[string]int{"Newly open": 0, "Open, unverified": 1, "Newly closed": 2, "Closed, unverified": 3}

// attentionOf says what changed in a safeguard's latest run.
func attentionOf(hist []*tag.Tag, sg Safeguard) (AttentionRow, bool) {
	prev := ""
	if len(hist) > 1 {
		prev = hist[len(hist)-2].Header.State
	}
	row := AttentionRow{DrillID: sg.DrillID, Target: sg.Target}
	last := hist[len(hist)-1].Header
	switch {
	case sg.State == tag.Open && !last.Waived && prev != tag.Open:
		row.Kind, row.Class = "Newly open", "fail"
	case sg.State == tag.Open && sg.Unverified:
		row.Kind, row.Class = "Open, unverified", "fail"
	case sg.State == tag.Closed && prev == tag.Open:
		row.Kind, row.Class = "Newly closed", "pass"
	case sg.State == tag.Closed && sg.Unverified:
		row.Kind, row.Class = "Closed, unverified", "warn"
	default:
		return row, false
	}
	return row, true
}

func count(c *Counts, h tag.Header) {
	c.Total++
	switch h.State {
	case tag.Open:
		c.Open++
	case tag.Closed:
		c.Closed++
	case tag.Retired:
		c.Retired++
	default:
		c.Unknown++
	}
	switch h.Verdict {
	case tag.Pass:
		c.Pass++
	case tag.Fail:
		c.Fail++
	case tag.Warn:
		c.Warn++
	case tag.NA:
		c.NA++
	case tag.Skip:
		c.Skip++
	case tag.Error:
		c.Error++
	}
}

// lamp picks a safeguard's light: an open safeguard stays red under any later
// verdict except PASS.
func lamp(verdict, state string) (class, label string) {
	if state == tag.Open {
		return "fail", "OPEN"
	}
	switch verdict {
	case tag.Error:
		return "err", "ERR"
	}
	return verdictClass(verdict), verdict
}

func verdictClass(v string) string {
	switch v {
	case tag.Pass:
		return "pass"
	case tag.Fail:
		return "fail"
	case tag.Warn:
		return "warn"
	case tag.NA:
		return "na"
	case tag.Skip:
		return "skip"
	}
	return "err"
}

func needsOwner(it *graph.EstateItem) bool {
	switch it.Kind {
	case graph.KindGitHubRepo, graph.KindHost:
		return true
	case graph.KindIdentityUser, graph.KindAWSPrincipal:
		admin, _ := it.Attrs["is_admin"].(bool)
		excluded, _ := it.Attrs["excluded"].(bool)
		return admin && !excluded
	}
	return false
}

func ownersOf(est *graph.Estate) map[graph.ID]bool {
	out := map[graph.ID]bool{}
	for e := range est.Edges {
		if e.Kind == graph.EdgeOwns || e.Kind == graph.EdgeSamePerson {
			out[e.To] = true
		}
	}
	for id, it := range est.Items {
		if it.Kind == graph.KindCodeowners {
			repo := strings.TrimPrefix(string(id), "codeowners:")
			out[graph.ID("github:repo/"+repo)] = true
		}
	}
	return out
}

// displayName names an item. Items known only from history show their kind and
// a short ID, since their emails are stored as HMACs.
func displayName(it *graph.EstateItem) string {
	for _, k := range []string{"name", "host", "file"} {
		if s, ok := it.Attrs[k].(string); ok && s != "" {
			return s
		}
	}
	id := string(it.ID)
	if len(id) > 28 {
		return it.Kind + " " + id[:28] + "…"
	}
	return id
}

func fontCSS() (template.CSS, error) {
	faces := []struct{ family, file, weight string }{
		{"Big Shoulders Stencil", "stencil-700.woff2", "700"},
		{"IBM Plex Sans", "plex-sans-400.woff2", "400"},
		{"IBM Plex Sans", "plex-sans-600.woff2", "600"},
		{"IBM Plex Mono", "plex-mono-400.woff2", "400"},
	}
	var sb strings.Builder
	for _, f := range faces {
		data, err := assets.ReadFile("assets/fonts/" + f.file)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(&sb, "@font-face{font-family:%q;font-weight:%s;font-display:swap;src:url(data:font/woff2;base64,%s) format('woff2')}\n",
			f.family, f.weight, base64.StdEncoding.EncodeToString(data))
	}
	return template.CSS(sb.String()), nil // #nosec G203 -- built from embedded files only
}

// Write renders the board and one page per item into dir.
func Write(dir string, b *Board) (string, error) {
	fonts, err := fontCSS()
	if err != nil {
		return "", err
	}
	b.Fonts = fonts
	tmpl, err := template.ParseFS(assets, "assets/*.html")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Join(dir, "items"), 0o755); err != nil {
		return "", err
	}
	index := filepath.Join(dir, "index.html")
	f, err := os.Create(index)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if err := tmpl.ExecuteTemplate(f, "index.html", b); err != nil {
		return "", err
	}
	for _, it := range b.Items {
		page, err := os.Create(filepath.Join(dir, "items", it.Slug+".html"))
		if err != nil {
			return "", err
		}
		err = tmpl.ExecuteTemplate(page, "item.html", struct {
			Item  Item
			Fonts template.CSS
		}{it, fonts})
		_ = page.Close()
		if err != nil {
			return "", err
		}
	}
	return index, f.Close()
}

// Finding is an entry for scripts in the JSON result.
type Finding struct {
	Drill      string   `json:"drill"`
	Target     string   `json:"target"`
	Severity   string   `json:"severity"`
	Verdict    string   `json:"verdict"`
	State      string   `json:"state"`
	Owner      string   `json:"owner,omitempty"`
	Reason     string   `json:"reason,omitempty"`
	Waived     bool     `json:"waived,omitempty"`
	Failing    []string `json:"failing_conditions,omitempty"`
	Fix        string   `json:"fix,omitempty"`
	Unverified string   `json:"unverified,omitempty"`
	Retired    string   `json:"retired,omitempty"`
	Facts      any      `json:"facts,omitempty"`
}

// JSONResult is the full result for scripts.
type JSONResult struct {
	Time             time.Time `json:"time"`
	Stream           string    `json:"stream"`
	DefaultOwner     string    `json:"default_owner,omitempty"`
	Results          []Finding `json:"results"`
	NewlyOpen        []Finding `json:"newly_open"`
	NewlyClosed      []Finding `json:"newly_closed"`
	OpenUnverified   []Finding `json:"open_unverified"`
	ClosedUnverified []Finding `json:"closed_unverified"`
	Retired          []Finding `json:"retired"`
	Skips            []string  `json:"waiting"`
	ExitCode         int       `json:"exit_code"`
}

func findingOf(o *run.Outcome, withFacts bool) Finding {
	f := Finding{Drill: o.Drill.ID, Target: o.Target, Severity: o.Drill.Severity, Verdict: o.Verdict, State: o.State,
		Owner: o.Owner, Reason: o.Reason, Waived: o.Waived, Fix: o.Drill.Fix, Unverified: o.Unverified, Retired: o.Retired}
	for _, c := range o.Conditions {
		if c.Result == "false" {
			f.Failing = append(f.Failing, strings.Join(strings.Fields(c.Expr), " "))
		}
	}
	if withFacts {
		f.Facts = o.Facts
	}
	return f
}

func findings(list []*run.Outcome) []Finding {
	out := make([]Finding, 0, len(list))
	for _, o := range list {
		out = append(out, findingOf(o, false))
	}
	return out
}

// BuildJSON assembles the result. Lists used for issues and summaries carry no
// evidence values; only the full results list does.
func BuildJSON(res *run.Result, now time.Time, exit int) JSONResult {
	j := JSONResult{Time: now.UTC(), Stream: res.Stream, ExitCode: exit,
		NewlyOpen: findings(res.Attention.NewlyOpen), NewlyClosed: findings(res.Attention.NewlyClosed),
		OpenUnverified: findings(res.Attention.OpenUnverified), ClosedUnverified: findings(res.Attention.ClosedUnverified),
		Retired: []Finding{}, Results: []Finding{}, Skips: []string{}}
	for _, o := range res.Outcomes {
		j.Results = append(j.Results, findingOf(o, true))
		if o.Retired != "" {
			j.Retired = append(j.Retired, findingOf(o, false))
		}
	}
	for _, s := range res.Skips {
		j.Skips = append(j.Skips, s.DrillID+": "+s.Needs)
	}
	return j
}

// WriteJSON stores the result in a file, never the CI log.
func WriteJSON(path string, j JSONResult) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// Summary renders counts and what needs attention, with no evidence.
func Summary(j JSONResult) string {
	var sb strings.Builder
	counts := map[string]int{}
	states := map[string]int{}
	for _, r := range j.Results {
		counts[r.Verdict]++
		states[r.State]++
	}
	sb.WriteString("## Firedrill\n\n")
	fmt.Fprintf(&sb, "| Open | Closed | PASS | FAIL | WARN | N/A | SKIP | ERROR | Waiting |\n| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n| %d | %d | %d | %d | %d | %d | %d | %d | %d |\n\n",
		states[tag.Open], states[tag.Closed], counts[tag.Pass], counts[tag.Fail], counts[tag.Warn], counts[tag.NA], counts[tag.Skip], counts[tag.Error], len(j.Skips))
	section := func(title string, list []Finding) {
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&sb, "### %s\n\n", title)
		for _, f := range list {
			fmt.Fprintf(&sb, "- `%s` on `%s` (%s)\n", f.Drill, targetLabel(f.Target), f.Severity)
		}
		sb.WriteString("\n")
	}
	section("Newly open", j.NewlyOpen)
	section("Newly closed", j.NewlyClosed)
	section("Open, unverified this run", j.OpenUnverified)
	section("Closed, unverified", j.ClosedUnverified)
	return sb.String()
}

func targetLabel(t string) string {
	if t == "" {
		return "global"
	}
	return t
}
