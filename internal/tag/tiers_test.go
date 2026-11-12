package tag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// oldHeader is the header as tags were written before evidence tiers.
type oldHeader struct {
	DrillID      string            `json:"drill_id"`
	DrillHash    string            `json:"drill_sha256"`
	Version      string            `json:"firedrill_version"`
	Target       string            `json:"target"`
	Stream       string            `json:"stream"`
	Verdict      string            `json:"verdict"`
	Reason       string            `json:"reason,omitempty"`
	State        string            `json:"state"`
	Waived       bool              `json:"waived,omitempty"`
	WaivedParts  int               `json:"waived_findings,omitempty"`
	Severity     string            `json:"severity"`
	Owner        string            `json:"owner,omitempty"`
	Conditions   []Condition       `json:"conditions,omitempty"`
	FactSources  map[string]string `json:"fact_sources,omitempty"`
	Time         time.Time         `json:"time"`
	RanBy        string            `json:"ran_by"`
	Attested     bool              `json:"attested"`
	SaltPrint    string            `json:"salt_fingerprint,omitempty"`
	EvidenceHash string            `json:"evidence_sha256"`
	Previous     string            `json:"previous_sha256,omitempty"`
	ScannerNotes []string          `json:"scanner_notes,omitempty"`
}

func oldHash(t *testing.T, h oldHeader) string {
	t.Helper()
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// A tag written before tiers hashes as it did then, and a chain that starts
// with such tags and goes on with tiered ones still verifies.
func TestOldTagsWithoutTiersStillVerify(t *testing.T) {
	s := Store{Root: t.TempDir()}
	base := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	ev := Evidence{Facts: map[string]any{"rules": map[string]any{"required_approvals": 0}}}
	evHash, err := EvidenceHash(ev)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(s.Root, "tags", "change", "x", "acme-api")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	prev := ""
	for i, verdict := range []string{Fail, Fail} {
		h := oldHeader{DrillID: "change/x", Target: "acme/api", Verdict: verdict, State: Open, Severity: "high",
			FactSources: map[string]string{"rules": "api"}, Time: base.AddDate(0, 0, i), RanBy: "ci",
			EvidenceHash: evHash, Previous: prev}
		raw, err := json.MarshalIndent(struct {
			Header   oldHeader `json:"header"`
			Evidence Evidence  `json:"evidence"`
		}{h, ev}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, h.Time.Format(tagTime)+".json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		prev = oldHash(t, h)
	}
	hist, err := s.History("change/x", "acme/api")
	if err != nil || len(hist) != 2 {
		t.Fatalf("%v %d", err, len(hist))
	}
	if hist[1].Header.FactTiers != nil {
		t.Fatal("an old tag reads with no tiers")
	}
	if got, _ := HeaderHash(hist[1].Header); got != prev {
		t.Fatalf("an old header must hash as it did: %s, want %s", got, prev)
	}

	next := &Tag{Header: Header{DrillID: "change/x", Target: "acme/api", Verdict: Fail, State: Open, Time: base.AddDate(0, 0, 2),
		FactSources: map[string]string{"rules": "api"}, FactTiers: map[string]string{"rules": "verified"}}, Evidence: ev}
	if _, err := s.Write(next); err != nil {
		t.Fatal(err)
	}
	hist, _ = s.History("change/x", "acme/api")
	if st := VerifyChain(hist); !st.OK || len(hist) != 3 {
		t.Fatalf("old then tiered tags must verify: %+v", st)
	}
	if hist[2].Header.FactTiers["rules"] != "verified" {
		t.Fatalf("tiers are recorded: %+v", hist[2].Header.FactTiers)
	}
	// A later tag links to this header, so editing its tiers is caught.
	if _, err := s.Write(&Tag{Header: Header{DrillID: "change/x", Target: "acme/api", Time: base.AddDate(0, 0, 3)}}); err != nil {
		t.Fatal(err)
	}
	edited, _ := s.History("change/x", "acme/api")
	edited[2].Header.FactTiers["rules"] = "inferred"
	if st := VerifyChain(edited); st.OK {
		t.Fatal("an edited tier must break the chain")
	}
}

func TestFirstTimes(t *testing.T) {
	s := Store{Root: t.TempDir()}
	first, oldest, err := s.FirstTimes()
	if err != nil || len(first) != 0 || !oldest.IsZero() {
		t.Fatalf("empty store: %v %v %v", first, oldest, err)
	}
	base := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	for _, w := range []struct {
		drill, target string
		at            time.Time
	}{
		{"change/x", "acme/api", base.AddDate(0, 0, 3)},
		{"change/x", "acme/web", base.AddDate(0, 0, 1)},
		{"change/x", "acme/web", base.AddDate(0, 0, 5)},
		{"doors/y", "", base},
	} {
		if _, err := s.Write(&Tag{Header: Header{DrillID: w.drill, Target: w.target, Time: w.at}}); err != nil {
			t.Fatal(err)
		}
	}
	first, oldest, err = s.FirstTimes()
	if err != nil {
		t.Fatal(err)
	}
	if !first["change/x"].Equal(base.AddDate(0, 0, 1)) || !first["doors/y"].Equal(base) || !oldest.Equal(base) {
		t.Fatalf("first %v oldest %v", first, oldest)
	}
}
