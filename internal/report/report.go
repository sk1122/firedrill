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
	Evidence   []EvidenceRow
	// ShadowUntil is set while the latest run was in shadow.
	ShadowUntil string
	// OpenDays counts days of the current unwaived open stretch, -1 when the
	// safeguard is not open or is waived.
	OpenDays    int
	NeedsReview bool
}

// EvidenceRow is one fetch's source and evidence tier, or one inferred field
// a condition read, named alias.path with no source.
type EvidenceRow struct {
	Alias, Source, Tier string
}

// EvidenceOf lists a tag's sources with their tiers, each inferred field after
// its fetch. A tag written before tiers lists sources with no tier.
func EvidenceOf(h tag.Header) []EvidenceRow {
	keys := map[string]bool{}
	for k := range h.FactSources {
		keys[k] = true
	}
	for k := range h.FactTiers {
		keys[k] = true
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]EvidenceRow, 0, len(names))
	for _, k := range names {
		out = append(out, EvidenceRow{Alias: k, Source: h.FactSources[k], Tier: h.FactTiers[k]})
	}
	return out
}

// Pack groups safeguards. NotApplicable holds those whose latest verdict is N/A
// and which are not open, so the board can fold them away.
type Pack struct {
	Name          string
	Safeguards    []Safeguard
	Shown         []Safeguard
	NotApplicable []Safeguard
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

// AttentionRow is one safeguard the board leads with: a change in the latest
// run, or one still open.
type AttentionRow struct {
	Kind, DrillID, Target, Class, Severity, Reason string
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
	Changes   Changes
	Fonts     template.CSS
}

// Changes is the Changes page: the latest snapshot diff.
type Changes struct {
	Present   bool // false until two runs have been compared
	From, To  string
	Weakening int
	Other     int
	Sections  []ChangeSection
	Skipped   []string
}

// ChangeSection is weakenings or other changes.
type ChangeSection struct {
	Title     string
	Weakening bool
	Count     int
	Groups    []ChangeGroup
}

// ChangeGroup is one person's changes, or one type of change.
type ChangeGroup struct {
	Title  string
	Person bool
	Rows   []ChangeRow
}

// ChangeRow is one change, linked to its item page and to the drills that
// also caught it.
type ChangeRow struct {
	Type, Summary, System string
	Weakening             bool
	ItemHref              string
	Drills                []DrillLink
}

// DrillLink points at a safeguard card on the board.
type DrillLink struct {
	Drill, Target, Href string
}

// AddChanges puts the latest diff on the board. Call it after Build, so items
// and safeguards exist to link to. A nil diff leaves the page saying so.
func AddChanges(b *Board, rec *run.DiffRecord) {
	b.Changes = Changes{}
	if rec == nil {
		return
	}
	items := map[string]string{}
	for _, it := range b.Items {
		items[it.ID] = "items/" + it.Slug + ".html"
	}
	cards := map[string]bool{}
	for _, p := range b.Packs {
		for _, sg := range p.Safeguards {
			cards[sg.Slug] = true
		}
	}
	c := Changes{Present: true, From: rec.From.UTC().Format("2006-01-02 15:04 UTC"), To: rec.To.UTC().Format("2006-01-02 15:04 UTC"), Skipped: rec.Skipped}
	c.Weakening, c.Other = rec.Counts()
	for _, g := range run.GroupChanges(rec.Changes) {
		if len(c.Sections) == 0 || c.Sections[len(c.Sections)-1].Weakening != g.Weakening {
			sec := ChangeSection{Title: "Other changes", Count: c.Other}
			if g.Weakening {
				sec = ChangeSection{Title: "Weakenings", Weakening: true, Count: c.Weakening}
			}
			c.Sections = append(c.Sections, sec)
		}
		sec := &c.Sections[len(c.Sections)-1]
		group := ChangeGroup{Title: g.Title, Person: g.Person != ""}
		for _, ch := range g.Changes {
			row := ChangeRow{Type: graph.ChangeLabel(ch.Type), Summary: ch.Summary, System: ch.System, Weakening: ch.Weakening, ItemHref: items[string(ch.Subject)]}
			for _, ref := range ch.CaughtBy {
				href := "index.html"
				if slug := tag.Slug(ref.Drill + "-" + tag.Slug(ref.Target)); cards[slug] {
					href += "#" + slug
				}
				row.Drills = append(row.Drills, DrillLink{Drill: ref.Drill, Target: ref.Target, Href: href})
			}
			group.Rows = append(group.Rows, row)
		}
		sec.Groups = append(sec.Groups, group)
	}
	b.Changes = c
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
	graph.KindTFBucket: true, graph.KindManifest: true, graph.KindOAuthApp: true, graph.KindDatabase: true, graph.KindAIKey: true,
	graph.KindGitHubUser: true, graph.KindGitHubTeam: true, graph.KindGitHubApp: true, graph.KindDeployKey: true,
}

// Build assembles the board from tags and the estate. Shadow is judged at each
// safeguard's latest run, and days open up to now.
func Build(store tag.Store, est *graph.Estate, drills []*drill.Drill, now time.Time, noise run.Rules) (*Board, error) {
	rules := map[string]string{}
	for _, d := range drills {
		rules[d.ID] = d.Safeguard
	}
	keys, err := store.Keys()
	if err != nil {
		return nil, err
	}
	shadow, err := run.LoadShadow(store, noise.ShadowDays)
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
			Slug: tag.Slug(k.DrillID + "-" + k.TargetSlug), Evidence: EvidenceOf(last), OpenDays: -1,
		}
		if until, on := shadow.Until(k.DrillID, last.Time); on {
			sg.ShadowUntil = until.Format("2006-01-02")
		}
		if days, open := run.OpenDaysOf(hist, now); open {
			sg.OpenDays = days
			sg.NeedsReview = noise.ReviewAfterDays > 0 && days >= noise.ReviewAfterDays
		}
		sg.Lamp, sg.Label = lamp(last.Verdict, last.State)
		sg.Unverified = (last.State == tag.Open && last.Verdict != tag.Fail) || (last.State == tag.Closed && last.Verdict != tag.Pass)
		start := max(len(hist)-LastRuns, 0)
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
		pk := Pack{Name: n, Safeguards: list}
		for _, sg := range list {
			if sg.Verdict == tag.NA && sg.State != tag.Open {
				pk.NotApplicable = append(pk.NotApplicable, sg)
			} else {
				pk.Shown = append(pk.Shown, sg)
			}
		}
		b.Packs = append(b.Packs, pk)
	}
	sort.SliceStable(b.Attention, func(i, j int) bool {
		a, c := attentionRank[b.Attention[i].Kind], attentionRank[b.Attention[j].Kind]
		if a != c {
			return a < c
		}
		if a, c := severityRank[b.Attention[i].Severity], severityRank[b.Attention[j].Severity]; a != c {
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

var attentionRank = map[string]int{"Newly open": 0, "Open, unverified": 1, "Needs review": 2, "Still open": 3, "Newly closed": 4, "Closed, unverified": 5}

var severityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// attentionOf says what changed in a safeguard's latest run, or that it is
// still open, so an open safeguard never drops off the top of the board.
func attentionOf(hist []*tag.Tag, sg Safeguard) (AttentionRow, bool) {
	prev := ""
	if len(hist) > 1 {
		prev = hist[len(hist)-2].Header.State
	}
	row := AttentionRow{DrillID: sg.DrillID, Target: sg.Target, Severity: sg.Severity, Reason: sg.Reason}
	last := hist[len(hist)-1].Header
	switch {
	case sg.State == tag.Open && !last.Waived && prev != tag.Open:
		row.Kind, row.Class = "Newly open", "fail"
	case sg.NeedsReview:
		// Open this long with no fix or waiver: the safeguard is wrong or
		// nobody owns it.
		row.Kind, row.Class = "Needs review", "warn"
		row.Reason = run.ReviewAdvice(sg.OpenDays)
	case sg.State == tag.Open && sg.Unverified:
		row.Kind, row.Class = "Open, unverified", "fail"
	case sg.State == tag.Open && !last.Waived:
		row.Kind, row.Class = "Still open", "fail"
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
	id := string(it.ID)
	// A GitHub user shows by a short hashed ID: the login never reaches the
	// estate.
	if h, ok := strings.CutPrefix(id, "github:user/"); ok {
		return "GitHub user " + h[:min(8, len(h))]
	}
	if it.Kind == graph.KindGitHubTeam {
		if s, ok := it.Attrs["slug"].(string); ok && s != "" {
			return "team " + s
		}
	}
	for _, k := range []string{"name", "host", "file"} {
		if s, ok := it.Attrs[k].(string); ok && s != "" {
			return s
		}
	}
	if len(id) > 28 {
		return it.Kind + " " + id[:28] + "…"
	}
	return id
}

// FontCSS returns @font-face rules with the embedded fonts inlined, for any
// page Firedrill writes.
func FontCSS() (template.CSS, error) { return fontCSS() }

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

// Write renders the board, the Changes page and one page per item into dir.
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
	changes, err := os.Create(filepath.Join(dir, "changes.html"))
	if err != nil {
		return "", err
	}
	err = tmpl.ExecuteTemplate(changes, "changes.html", b)
	_ = changes.Close()
	if err != nil {
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
	// Shadow marks a drill new to an established install: reported, never
	// failing the run, until ShadowUntil.
	Shadow      bool              `json:"shadow,omitempty"`
	ShadowUntil string            `json:"shadow_until,omitempty"`
	NeedsReview bool              `json:"needs_review,omitempty"`
	OpenSince   string            `json:"open_since,omitempty"`
	OpenDays    int               `json:"open_days,omitempty"`
	Sources     map[string]string `json:"fact_sources,omitempty"`
	Tiers       map[string]string `json:"fact_tiers,omitempty"`
	Facts       any               `json:"facts,omitempty"`
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
	NeedsReview      []Finding `json:"needs_review"`
	Retired          []Finding `json:"retired"`
	Skips            []string  `json:"waiting"`
	ExitCode         int       `json:"exit_code"`
}

func findingOf(o *run.Outcome, withFacts bool) Finding {
	f := Finding{Drill: o.Drill.ID, Target: o.Target, Severity: o.Drill.Severity, Verdict: o.Verdict, State: o.State,
		Owner: o.Owner, Reason: o.Reason, Waived: o.Waived, Fix: o.Drill.Fix, Unverified: o.Unverified, Retired: o.Retired,
		Shadow: o.Shadow, NeedsReview: o.NeedsReview, OpenDays: o.OpenDays}
	if o.Shadow {
		f.ShadowUntil = o.ShadowUntil.Format("2006-01-02")
	}
	if !o.OpenSince.IsZero() {
		f.OpenSince = o.OpenSince.Format("2006-01-02")
	}
	for _, c := range o.Conditions {
		if c.Result == "false" {
			f.Failing = append(f.Failing, strings.Join(strings.Fields(c.Expr), " "))
		}
	}
	if withFacts {
		f.Facts = o.Facts
		if len(o.Sources) > 0 {
			f.Sources = o.Sources
		}
		if len(o.Tiers) > 0 {
			f.Tiers = o.Tiers
		}
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
		NeedsReview: findings(res.Attention.NeedsReview),
		Retired:     []Finding{}, Results: []Finding{}, Skips: []string{}}
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
			fmt.Fprintf(&sb, "- `%s` on `%s` (%s)", f.Drill, targetLabel(f.Target), f.Severity)
			if f.Shadow {
				fmt.Fprintf(&sb, ", shadow until %s", f.ShadowUntil)
			}
			if title == "Needs review" {
				fmt.Fprintf(&sb, ": %s", run.ReviewAdvice(f.OpenDays))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}
	section("Newly open", j.NewlyOpen)
	section("Newly closed", j.NewlyClosed)
	section("Open, unverified this run", j.OpenUnverified)
	section("Closed, unverified", j.ClosedUnverified)
	section("Needs review", j.NeedsReview)
	return sb.String()
}

func targetLabel(t string) string {
	if t == "" {
		return "global"
	}
	return t
}
