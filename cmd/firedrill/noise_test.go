package main

import (
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

// The run output marks a shadowed outcome and gives one line per safeguard to
// review.
func TestRunOutputShowsShadowAndReview(t *testing.T) {
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	all := []*run.Outcome{
		{Drill: &drill.Drill{ID: "change/new", Severity: "high"}, Target: "acme/api", Verdict: tag.Fail, State: tag.Open, NewlyOpen: true,
			Shadow: true, ShadowUntil: at.AddDate(0, 0, 14)},
		{Drill: &drill.Drill{ID: "change/old", Severity: "high"}, Target: "acme/web", Verdict: tag.Fail, State: tag.Open,
			NeedsReview: true, OpenDays: 34, OpenSince: at.AddDate(0, 0, -34)},
	}
	var out strings.Builder
	printRun(&out, &run.Result{Outcomes: all, Attention: run.BuildAttention(all)}, 2)
	s := out.String()
	for _, want := range []string{
		"shadow until 2026-11-26",
		"1 to review",
		"review: change/old acme/web  open 34 days with no fix or waiver: fix it, waive it with an expiry, or retire the drill",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q:\n%s", want, s)
		}
	}
}
