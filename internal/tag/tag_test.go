package tag

import (
	"testing"
	"time"
)

func write(t *testing.T, s Store, verdict string, at time.Time) *Tag {
	t.Helper()
	tg := &Tag{Header: Header{DrillID: "change/x", Target: "acme/api", Verdict: verdict, Time: at},
		Evidence: Evidence{Facts: map[string]any{"email": "ravi@acme.com"}}}
	if _, err := s.Write(tg); err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestChain(t *testing.T) {
	s := Store{Root: t.TempDir()}
	base := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	write(t, s, Fail, base)
	write(t, s, Pass, base.AddDate(0, 0, 7))
	write(t, s, Pass, base.AddDate(0, 0, 14))
	h, err := s.History("change/x", "acme/api")
	if err != nil || len(h) != 3 {
		t.Fatalf("%v %d", err, len(h))
	}
	if st := VerifyChain(h); !st.OK || st.Redacted != 0 {
		t.Fatalf("clean chain: %+v", st)
	}
	if h[1].Header.Previous == "" {
		t.Fatal("tags must link")
	}

	edited, _ := s.History("change/x", "acme/api")
	edited[1].Evidence.Facts["email"] = "other@acme.com"
	if st := VerifyChain(edited); st.OK {
		t.Fatal("edited evidence must be caught")
	}

	changed, _ := s.History("change/x", "acme/api")
	changed[0].Header.Verdict = Pass
	if st := VerifyChain(changed); st.OK {
		t.Fatal("edited header must be caught")
	}

	missing, _ := s.History("change/x", "acme/api")
	if st := VerifyChain([]*Tag{missing[0], missing[2]}); st.OK {
		t.Fatal("a missing tag must be caught")
	}

	redacted, _ := s.History("change/x", "acme/api")
	Redact(redacted[1])
	st := VerifyChain(redacted)
	if !st.OK || st.Redacted != 1 || len(st.Tampered) != 0 {
		t.Fatalf("redaction must verify as redacted, never tampered: %+v", st)
	}
}

func TestLatestAndKeys(t *testing.T) {
	s := Store{Root: t.TempDir()}
	if l, err := s.Latest("change/x", "acme/api"); err != nil || l != nil {
		t.Fatal("no history gives nil")
	}
	base := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	write(t, s, Fail, base)
	l, err := s.Latest("change/x", "acme/api")
	if err != nil || l.Header.Verdict != Fail {
		t.Fatal(err, l)
	}
	k, err := s.Keys()
	if err != nil || len(k) != 1 || k[0].DrillID != "change/x" || k[0].TargetSlug != "acme-api" {
		t.Fatalf("%v %+v", err, k)
	}
}

func TestNextState(t *testing.T) {
	cases := []struct {
		prev, verdict string
		want          string
	}{
		{"", Fail, Open}, {"", Pass, Closed}, {"", Warn, Unknown}, {Open, Warn, Open}, {Open, NA, Open}, {Open, Skip, Open},
		{Open, Error, Open}, {Open, Pass, Closed}, {Closed, Fail, Open}, {Closed, NA, Closed}, {Retired, Warn, Unknown},
	}
	for _, c := range cases {
		if got := NextState(c.prev, c.verdict, false); got != c.want {
			t.Errorf("%s + %s = %s, want %s", c.prev, c.verdict, got, c.want)
		}
	}
	if NextState(Open, Fail, true) != Retired {
		t.Error("retired wins")
	}
}
