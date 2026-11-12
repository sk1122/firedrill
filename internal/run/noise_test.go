package run

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/tag"
)

// establish makes the records an established install: one tag of another drill,
// written a month before testNow.
func establish(t *testing.T, records string) {
	t.Helper()
	old := &tag.Tag{Header: tag.Header{DrillID: "change/older-drill", Target: "acme/api", Verdict: tag.Pass, State: tag.Closed,
		Time: testNow.AddDate(0, -1, 0)}}
	if _, err := (tag.Store{Root: records}).Write(old); err != nil {
		t.Fatal(err)
	}
}

func runAt(t *testing.T, c Config, days int, conn *fake) *Result {
	t.Helper()
	c.Connectors = []connector.Connector{conn}
	c.Scope.Now = testNow.AddDate(0, 0, days)
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func intp(n int) *int { return &n }

// A drill new to an established install reports and records as normal but
// never fails the run, until its two weeks are up. The finding it opened then
// fails CI once, on the first run after shadow ends.
func TestShadowModeForNewDrills(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d)
	establish(t, c.Records)
	failing := func() *fake { return &fake{name: "github", available: true, write: ghWriter(0)} }

	res := runAt(t, c, 0, failing())
	o := res.Outcomes[0]
	if o.Verdict != tag.Fail || o.State != tag.Open || !o.NewlyOpen || !o.Shadow {
		t.Fatalf("shadowed FAIL is decided as normal: %+v", o)
	}
	if got := o.ShadowUntil.Format("2006-01-02"); got != "2026-11-21" {
		t.Fatalf("shadow until %s", got)
	}
	if len(res.Attention.NewlyOpen) != 1 {
		t.Fatal("a shadowed outcome stays in the attention lists")
	}
	for _, failOn := range []string{"", "open", "any"} {
		if got := ExitCode(res.Outcomes, failOn); got != 0 {
			t.Fatalf("shadow never fails the run, --fail-on %q gave %d", failOn, got)
		}
	}
	h, _ := tag.Store{Root: c.Records}.History(d[0].ID, "acme/api")
	if len(h) != 1 || h[0].Header.State != tag.Open {
		t.Fatalf("a shadowed outcome is recorded: %d tags", len(h))
	}

	// A week in: still shadowed, counted from the drill's first tag.
	res = runAt(t, c, 7, failing())
	if o := res.Outcomes[0]; !o.Shadow || o.ShadowUntil.Format("2006-01-02") != "2026-11-21" || ExitCode(res.Outcomes, "open") != 0 {
		t.Fatalf("day 7: %+v", o)
	}

	// Shadow has ended: the safeguard opened in shadow counts as newly open once.
	res = runAt(t, c, 15, failing())
	o = res.Outcomes[0]
	if o.Shadow || !o.ShadowEnded || !o.NewlyOpen || ExitCode(res.Outcomes, "") != 1 {
		t.Fatalf("first run after shadow: %+v exit %d", o, ExitCode(res.Outcomes, ""))
	}

	// After that, the normal rules: still open fails only under --fail-on.
	res = runAt(t, c, 16, failing())
	o = res.Outcomes[0]
	if o.Shadow || o.ShadowEnded || o.NewlyOpen || ExitCode(res.Outcomes, "") != 0 || ExitCode(res.Outcomes, "open") != 1 {
		t.Fatalf("second run after shadow: %+v", o)
	}
}

// On a brand-new install nothing is in shadow, so a first run fails on what it
// finds.
func TestNoShadowOnANewInstall(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d)
	res := runAt(t, c, 0, &fake{name: "github", available: true, write: ghWriter(0)})
	if o := res.Outcomes[0]; o.Shadow || ExitCode(res.Outcomes, "") != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestShadowDaysZeroTurnsShadowOff(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d)
	c.Project.Config.ShadowDays = intp(0)
	establish(t, c.Records)
	res := runAt(t, c, 0, &fake{name: "github", available: true, write: ghWriter(0)})
	if o := res.Outcomes[0]; o.Shadow || ExitCode(res.Outcomes, "") != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestShadowedErrorDoesNotExit2(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "access/admins-use-mfa")}
	c := baseConfig(t, d)
	establish(t, c.Records)
	res := runAt(t, c, 0, &fake{name: "google", available: true, collect: func(connector.Scope) error { return errors.New("boom") }})
	if o := res.Outcomes[0]; o.Verdict != tag.Error || !o.Shadow || ExitCode(res.Outcomes, "") != 0 {
		t.Fatalf("%+v", o)
	}
}

// A drill whose first tag is older than the window is out of shadow, while a
// drill with no tag yet on an established install is in it.
func TestShadowUntil(t *testing.T) {
	s := Shadow{Days: 14, Oldest: testNow.AddDate(0, 0, -30), First: map[string]time.Time{
		"a/old": testNow.AddDate(0, 0, -20), "a/new": testNow.AddDate(0, 0, -3), "a/edge": testNow.AddDate(0, 0, -14),
	}}
	if _, on := s.Until("a/old", testNow); on {
		t.Error("old drill")
	}
	if u, on := s.Until("a/new", testNow); !on || !u.Equal(testNow.AddDate(0, 0, 11)) {
		t.Errorf("new drill: %v %v", u, on)
	}
	if _, on := s.Until("a/edge", testNow); on {
		t.Error("a drill first seen exactly the window ago is out of shadow")
	}
	if u, on := s.Until("a/unseen", testNow); !on || !u.Equal(testNow.AddDate(0, 0, 14)) {
		t.Errorf("unseen drill: %v %v", u, on)
	}
	young := Shadow{Days: 14, Oldest: testNow.AddDate(0, 0, -13), First: map[string]time.Time{}}
	if _, on := young.Until("a/unseen", testNow); on {
		t.Error("a young install has nothing in shadow")
	}
}

// hist builds a history from (days before testNow, state, verdict, waived).
type step struct {
	daysAgo int
	state   string
	verdict string
	waived  bool
}

func history(steps ...step) []*tag.Tag {
	var out []*tag.Tag
	for _, s := range steps {
		out = append(out, &tag.Tag{Header: tag.Header{State: s.state, Verdict: s.verdict, Waived: s.waived, Time: testNow.AddDate(0, 0, -s.daysAgo)}})
	}
	return out
}

func TestReviewFlag(t *testing.T) {
	d := loadDrill(t, "change/human-review-required")
	open := func() *Outcome { return &Outcome{Drill: d, Verdict: tag.Fail, State: tag.Open} }
	cases := []struct {
		name   string
		hist   []*tag.Tag
		waived bool
		days   int
		flag   bool
		since  int // days before testNow; -1 for none
	}{
		{"open 29 days", history(step{29, tag.Open, tag.Fail, false}), false, 30, false, 29},
		{"open 30 days", history(step{30, tag.Open, tag.Fail, false}), false, 30, true, 30},
		{"a PASS in between resets", history(step{40, tag.Open, tag.Fail, false}, step{35, tag.Closed, tag.Pass, false}, step{20, tag.Open, tag.Fail, false}), false, 30, false, 20},
		{"a waiver resets to its end", history(step{60, tag.Open, tag.Fail, false}, step{50, tag.Open, tag.Fail, true}, step{40, tag.Open, tag.Skip, true}, step{34, tag.Open, tag.Fail, false}, step{5, tag.Open, tag.Fail, false}), false, 30, true, 34},
		{"waived now", history(step{40, tag.Open, tag.Fail, false}), true, 30, false, -1},
		{"SKIP and ERROR do not reset", history(step{40, tag.Open, tag.Fail, false}, step{30, tag.Open, tag.Skip, false}, step{20, tag.Open, tag.Error, false}), false, 30, true, 40},
		{"newly open", history(step{40, tag.Closed, tag.Pass, false}), false, 30, false, 0},
		{"review_after_days 0", history(step{90, tag.Open, tag.Fail, false}), false, 0, false, 90},
	}
	for _, c := range cases {
		o := open()
		o.Waived = c.waived
		ApplyReview(o, c.hist, testNow, c.days)
		if o.NeedsReview != c.flag {
			t.Errorf("%s: flag %v, want %v", c.name, o.NeedsReview, c.flag)
		}
		if c.since < 0 {
			if !o.OpenSince.IsZero() {
				t.Errorf("%s: open since %v", c.name, o.OpenSince)
			}
			continue
		}
		if want := testNow.AddDate(0, 0, -c.since); !o.OpenSince.Equal(want) || o.OpenDays != c.since {
			t.Errorf("%s: open since %v (%d days), want %v", c.name, o.OpenSince, o.OpenDays, want)
		}
	}
	closed := &Outcome{Drill: d, Verdict: tag.Pass, State: tag.Closed}
	ApplyReview(closed, history(step{40, tag.Open, tag.Fail, false}), testNow, 30)
	if closed.NeedsReview {
		t.Error("a closed safeguard is never flagged")
	}
}

// The review flag reaches the attention lists but changes no verdict, state or
// exit code.
func TestReviewFlagInARun(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d)
	failing := func() *fake { return &fake{name: "github", available: true, write: ghWriter(0)} }
	runAt(t, c, 0, failing())
	res := runAt(t, c, 29, failing())
	if len(res.Attention.NeedsReview) != 0 {
		t.Fatal("29 days is not yet 30")
	}
	res = runAt(t, c, 30, failing())
	o := res.Outcomes[0]
	if len(res.Attention.NeedsReview) != 1 || !o.NeedsReview || o.OpenDays != 30 || !o.OpenSince.Equal(testNow) {
		t.Fatalf("%+v", o)
	}
	if o.Verdict != tag.Fail || o.State != tag.Open || ExitCode(res.Outcomes, "") != 0 || ExitCode(res.Outcomes, "open") != 1 {
		t.Fatalf("the flag changes nothing else: %+v", o)
	}
	c.Project.Config.ReviewAfterDays = intp(0)
	if res := runAt(t, c, 31, failing()); len(res.Attention.NeedsReview) != 0 {
		t.Fatal("review_after_days: 0 turns the flag off")
	}
}
