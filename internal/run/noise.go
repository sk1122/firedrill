package run

import (
	"fmt"
	"time"

	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/tag"
)

// Rules are the noise rules: how long a drill new to an established install
// runs in shadow, and how long a safeguard may stay open with no fix and no
// waiver before it is flagged for review. Zero turns a rule off.
type Rules struct {
	ShadowDays      int
	ReviewAfterDays int
}

// RulesOf reads the noise rules from config, with their defaults.
func RulesOf(c config.Config) Rules {
	return Rules{ShadowDays: c.ShadowWindow(), ReviewAfterDays: c.ReviewAfter()}
}

// Shadow is what one records directory says about new drills: when its oldest
// tag was written and when each drill was first recorded. Only this stream's
// records count.
type Shadow struct {
	Days   int
	Oldest time.Time // zero when there is no tag
	First  map[string]time.Time
}

// LoadShadow reads first-recorded times once per run, from tag file names.
func LoadShadow(store tag.Store, days int) (Shadow, error) {
	first, oldest, err := store.FirstTimes()
	if err != nil {
		return Shadow{}, err
	}
	return Shadow{Days: days, Oldest: oldest, First: first}, nil
}

// Until says whether a drill is in shadow at a time, and when its shadow ends.
// A drill is in shadow when it is new on an established install: its first tag
// is younger than the window, or it has none, and some tag of any drill is at
// least as old as the window. On a new install nothing is in shadow, so a
// first run still fails on real findings.
func (s Shadow) Until(drillID string, at time.Time) (time.Time, bool) {
	if s.Days <= 0 || s.Oldest.IsZero() {
		return time.Time{}, false
	}
	window := time.Duration(s.Days) * 24 * time.Hour
	cutoff := at.Add(-window)
	if s.Oldest.After(cutoff) {
		return time.Time{}, false
	}
	first, seen := s.First[drillID]
	if !seen {
		return at.Add(window), true
	}
	if first.After(cutoff) {
		return first.Add(window), true
	}
	return time.Time{}, false
}

// ApplyShadow marks an outcome in shadow. On the first run after shadow ends,
// a safeguard that is still open and unwaived counts as newly open once, so a
// finding that opened in shadow fails CI under the normal rule. The run after
// that compares with a tag written out of shadow, so it is raised only once.
// Call it after ApplyState.
func ApplyShadow(o *Outcome, prev *tag.Tag, s Shadow, now time.Time) {
	o.ShadowUntil, o.Shadow = s.Until(o.Drill.ID, now)
	if o.Shadow || o.NewlyOpen || o.Waived || o.State != tag.Open || prev == nil || prev.Header.State != tag.Open {
		return
	}
	if _, was := s.Until(o.Drill.ID, prev.Header.Time); was {
		o.NewlyOpen, o.ShadowEnded = true, true
	}
}

// OpenSince returns when the unwaived open stretch ending at the newest tag
// began. It walks back from the newest tag through tags whose state is OPEN; a
// CLOSED, RETIRED or UNKNOWN state or the start of history ends the stretch,
// and a waived tag resets the clock to the first unwaived tag after it. SKIP
// and ERROR runs keep the state, so they never reset it. It is false when the
// newest tag is not open and unwaived.
func OpenSince(hist []*tag.Tag) (time.Time, bool) {
	var since time.Time
	for i := len(hist) - 1; i >= 0; i-- {
		h := hist[i].Header
		if h.State != tag.Open || h.Waived {
			break
		}
		since = h.Time
	}
	return since, !since.IsZero()
}

// ApplyReview records how long an open, unwaived safeguard has been open, and
// flags it for review once that reaches the rule's days: either the safeguard
// is wrong or nobody owns it. It never changes the verdict, state or exit
// code. hist is the history before this run.
func ApplyReview(o *Outcome, hist []*tag.Tag, now time.Time, days int) {
	if o.State != tag.Open || o.Waived {
		return
	}
	since, ok := OpenSince(hist)
	if !ok {
		since = now
	}
	o.OpenSince = since
	o.OpenDays = daysBetween(since, now)
	o.NeedsReview = days > 0 && o.OpenDays >= days
}

// OpenDaysOf says how many whole days a history's newest open, unwaived
// stretch has lasted at a time, and whether there is one.
func OpenDaysOf(hist []*tag.Tag, now time.Time) (int, bool) {
	since, ok := OpenSince(hist)
	if !ok {
		return 0, false
	}
	return daysBetween(since, now), true
}

func daysBetween(from, to time.Time) int {
	if to.Before(from) {
		return 0
	}
	return int(to.Sub(from).Hours() / 24)
}

// ReviewAdvice says what to do about a safeguard flagged for review.
func ReviewAdvice(days int) string {
	return fmt.Sprintf("open %d days with no fix or waiver: fix it, waive it with an expiry, or retire the drill", days)
}
