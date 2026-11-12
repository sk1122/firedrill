package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

func writeHeader(t *testing.T, s tag.Store, h tag.Header) {
	t.Helper()
	if _, err := s.Write(&tag.Tag{Header: h}); err != nil {
		t.Fatal(err)
	}
}

// The board shows each fetch's tier beside its source, a shadow label on a
// drill new to an established install, and days open with the review flag.
func TestBoardShowsTiersShadowAndReview(t *testing.T) {
	s := tag.Store{Root: t.TempDir()}
	// Open with no fix or waiver for 34 days.
	for _, days := range []int{-34, -20, 0} {
		writeHeader(t, s, tag.Header{DrillID: "change/old", Target: "acme/api", Verdict: tag.Fail, State: tag.Open, Severity: "high",
			Time: now.AddDate(0, 0, days), FactSources: map[string]string{"rules": "api", "files": "file"},
			FactTiers: map[string]string{"rules": "verified", "files": "declared", "files.found.env_class": "inferred"}})
	}
	// New this week on an install that is a month old.
	writeHeader(t, s, tag.Header{DrillID: "change/new", Target: "acme/api", Verdict: tag.Fail, State: tag.Open, Severity: "high",
		Time: now.AddDate(0, 0, -2), FactSources: map[string]string{"rules": "api"}})

	b, err := Build(s, nil, nil, now, run.Rules{ShadowDays: 14, ReviewAfterDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	cards := map[string]Safeguard{}
	for _, sg := range b.Packs[0].Safeguards {
		cards[sg.DrillID] = sg
	}
	old, nw := cards["change/old"], cards["change/new"]
	if !old.NeedsReview || old.OpenDays != 34 || old.ShadowUntil != "" {
		t.Fatalf("old: %+v", old)
	}
	if nw.ShadowUntil != "2026-11-19" || nw.NeedsReview || nw.OpenDays != 2 {
		t.Fatalf("new: %+v", nw)
	}
	want := []EvidenceRow{{"files", "file", "declared"}, {"files.found.env_class", "", "inferred"}, {"rules", "api", "verified"}}
	if len(old.Evidence) != len(want) {
		t.Fatalf("evidence %+v", old.Evidence)
	}
	for i, e := range want {
		if old.Evidence[i] != e {
			t.Errorf("evidence %d: %+v, want %+v", i, old.Evidence[i], e)
		}
	}
	// A tag written before tiers shows its source with no tier.
	if len(nw.Evidence) != 1 || nw.Evidence[0].Tier != "" || nw.Evidence[0].Source != "api" {
		t.Errorf("old tag evidence %+v", nw.Evidence)
	}
	review := false
	for _, a := range b.Attention {
		if a.Kind == "Needs review" && a.DrillID == "change/old" {
			review = strings.Contains(a.Reason, "open 34 days with no fix or waiver")
		}
	}
	if !review {
		t.Fatalf("attention: %+v", b.Attention)
	}

	path, err := Write(t.TempDir(), b)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(path)
	for _, want := range []string{`pill verified`, `pill declared`, `pill inferred`, "shadow until 2026-11-19", "Open 34 days with no fix or waiver: needs review", "Needs review"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("board missing %q", want)
		}
	}

	off, err := Build(s, nil, nil, now, run.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	for _, sg := range off.Packs[0].Safeguards {
		if sg.NeedsReview || sg.ShadowUntil != "" {
			t.Errorf("rules off: %+v", sg)
		}
	}
}

// The JSON result and step summary carry shadow, the review flag and tiers.
func TestJSONCarriesShadowReviewAndTiers(t *testing.T) {
	d := &drill.Drill{ID: "change/x", Severity: "high"}
	shadowed := &run.Outcome{Drill: d, Target: "acme/api", Verdict: tag.Fail, State: tag.Open, NewlyOpen: true,
		Shadow: true, ShadowUntil: time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC),
		Sources: map[string]string{"rules": "api"}, Tiers: map[string]string{"rules": "verified"}}
	stale := &run.Outcome{Drill: &drill.Drill{ID: "change/y", Severity: "high"}, Target: "acme/web", Verdict: tag.Fail, State: tag.Open,
		NeedsReview: true, OpenSince: now.AddDate(0, 0, -34), OpenDays: 34}
	all := []*run.Outcome{shadowed, stale}
	res := &run.Result{Outcomes: all, Attention: run.BuildAttention(all)}
	j := BuildJSON(res, now, run.ExitCode(all, ""))
	if j.ExitCode != 0 || !j.Results[0].Shadow || j.Results[0].ShadowUntil != "2026-11-21" || j.Results[0].Tiers["rules"] != "verified" {
		t.Fatalf("%+v", j.Results[0])
	}
	if len(j.NeedsReview) != 1 || j.NeedsReview[0].OpenSince != "2026-10-04" || j.NeedsReview[0].OpenDays != 34 {
		t.Fatalf("%+v", j.NeedsReview)
	}
	sum := Summary(j)
	for _, want := range []string{"shadow until 2026-11-21", "### Needs review", "open 34 days with no fix or waiver: fix it, waive it with an expiry, or retire the drill"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary missing %q:\n%s", want, sum)
		}
	}
}
