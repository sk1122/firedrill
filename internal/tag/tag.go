// Package tag holds the record of one drill run on one target, and the chain
// that links those records.
package tag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Verdicts for one run.
const (
	Pass  = "PASS"
	Fail  = "FAIL"
	Warn  = "WARN"
	NA    = "N/A"
	Skip  = "SKIP"
	Error = "ERROR"
)

// Safeguard states over time.
const (
	Open    = "OPEN"
	Closed  = "CLOSED"
	Unknown = "UNKNOWN"
	Retired = "RETIRED"
)

// Condition is the result of one condition.
type Condition struct {
	Expr   string `json:"expr"`
	Result string `json:"result"` // true, false or an error message
}

// Header is the part of a tag the chain covers. It holds a hash of the evidence
// rather than the evidence, so evidence about a person can be redacted without
// breaking the chain.
//
// FactTiers holds each fetch's evidence tier by alias, plus alias.path for each
// inferred field a condition read. Tags written before tiers have none, and
// omitempty keeps their header hashes as they were, so their chains verify.
type Header struct {
	DrillID     string            `json:"drill_id"`
	DrillHash   string            `json:"drill_sha256"`
	Version     string            `json:"firedrill_version"`
	Target      string            `json:"target"`
	Stream      string            `json:"stream"`
	Verdict     string            `json:"verdict"`
	Reason      string            `json:"reason,omitempty"`
	State       string            `json:"state"`
	Waived      bool              `json:"waived,omitempty"`
	WaivedParts int               `json:"waived_findings,omitempty"`
	Severity    string            `json:"severity"`
	Owner       string            `json:"owner,omitempty"`
	Conditions  []Condition       `json:"conditions,omitempty"`
	FactSources map[string]string `json:"fact_sources,omitempty"`
	FactTiers   map[string]string `json:"fact_tiers,omitempty"`
	Time        time.Time         `json:"time"`
	RanBy       string            `json:"ran_by"`
	// Attested is never set: the header is written, and hash-chained, before
	// any attestation exists. Kept so older tags hash as they were. Whether a
	// tag is attested comes from the sidecar under records/attest; see the
	// attest package.
	Attested     bool     `json:"attested"`
	SaltPrint    string   `json:"salt_fingerprint,omitempty"`
	EvidenceHash string   `json:"evidence_sha256"`
	Previous     string   `json:"previous_sha256,omitempty"`
	ScannerNotes []string `json:"scanner_notes,omitempty"`
}

// Evidence is what the verdict was decided on.
type Evidence struct {
	Facts    map[string]any `json:"facts,omitempty"`
	Read     []string       `json:"read,omitempty"`
	Redacted bool           `json:"redacted,omitempty"`
}

// Tag is one record.
type Tag struct {
	Header   Header   `json:"header"`
	Evidence Evidence `json:"evidence"`
}

func hashJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// HeaderHash returns the SHA-256 of a header.
func HeaderHash(h Header) (string, error) { return hashJSON(h) }

// EvidenceHash returns the SHA-256 of evidence.
func EvidenceHash(e Evidence) (string, error) { return hashJSON(e) }

var unsafePath = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// Slug makes a target safe to use as one path segment.
func Slug(s string) string {
	if s == "" {
		return "global"
	}
	return unsafePath.ReplaceAllString(s, "-")
}

// Store reads and writes tags under one directory.
type Store struct{ Root string }

func (s Store) dir(drillID, target string) string {
	return filepath.Join(append([]string{s.Root, "tags"}, append(strings.Split(drillID, "/"), Slug(target))...)...)
}

// Write stores a tag, filling in its evidence hash and link to the previous tag.
func (s Store) Write(t *Tag) (string, error) {
	prev, err := s.Latest(t.Header.DrillID, t.Header.Target)
	if err != nil {
		return "", err
	}
	if prev != nil {
		if t.Header.Previous, err = HeaderHash(prev.Header); err != nil {
			return "", err
		}
	}
	if t.Header.EvidenceHash, err = EvidenceHash(t.Evidence); err != nil {
		return "", err
	}
	dir := s.dir(t.Header.DrillID, t.Header.Target)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	// Two runs in one second move the later tag forward, so history stays ordered.
	path := ""
	for {
		path = filepath.Join(dir, t.Header.Time.UTC().Format(tagTime)+".json")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			break
		}
		t.Header.Time = t.Header.Time.Add(time.Second)
	}
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, b, 0o644)
}

// PathOf is the file a tag with this header was written to.
func (s Store) PathOf(h Header) string {
	return filepath.Join(s.dir(h.DrillID, h.Target), h.Time.UTC().Format(tagTime)+".json")
}

// History returns the tags of one drill and target, oldest first.
func (s Store) History(drillID, target string) ([]*Tag, error) {
	entries, err := os.ReadDir(s.dir(drillID, target))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := []string{}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := make([]*Tag, 0, len(names))
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(s.dir(drillID, target), n))
		if err != nil {
			return nil, err
		}
		var t Tag
		if err := json.Unmarshal(b, &t); err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		out = append(out, &t)
	}
	return out, nil
}

// Latest returns the newest tag of one drill and target, or nil.
func (s Store) Latest(drillID, target string) (*Tag, error) {
	h, err := s.History(drillID, target)
	if err != nil || len(h) == 0 {
		return nil, err
	}
	return h[len(h)-1], nil
}

// Key names one drill and target directory.
type Key struct{ DrillID, TargetSlug string }

// Keys lists every drill and target with tags.
func (s Store) Keys() ([]Key, error) {
	root := filepath.Join(s.Root, "tags")
	var out []Key
	err := filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if !e.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if len(parts) == 3 {
			out = append(out, Key{DrillID: parts[0] + "/" + parts[1], TargetSlug: parts[2]})
		}
		return nil
	})
	return out, err
}

// tagTime is the layout of a tag's file name.
const tagTime = "2006-01-02T15-04-05Z"

// FirstTimes returns when each drill was first recorded, on any target, and
// when the oldest tag of any drill was written, zero when there is none. It
// reads file names only, so it costs one directory listing per target.
func (s Store) FirstTimes() (map[string]time.Time, time.Time, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, time.Time{}, err
	}
	first := map[string]time.Time{}
	var oldest time.Time
	for _, k := range keys {
		t, ok, err := s.firstTime(k)
		if err != nil {
			return nil, time.Time{}, err
		}
		if !ok {
			continue
		}
		if f, seen := first[k.DrillID]; !seen || t.Before(f) {
			first[k.DrillID] = t
		}
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	return first, oldest, nil
}

// firstTime returns the time of the oldest tag of one drill and target. A file
// name that is not a time is read for its header instead.
func (s Store) firstTime(k Key) (time.Time, bool, error) {
	dir := filepath.Join(append([]string{s.Root, "tags"}, append(strings.Split(k.DrillID, "/"), k.TargetSlug)...)...)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return time.Time{}, false, err
	}
	var oldest time.Time
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		t, err := time.Parse(tagTime, name)
		if err != nil {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return time.Time{}, false, err
			}
			var tg Tag
			if err := json.Unmarshal(b, &tg); err != nil {
				return time.Time{}, false, fmt.Errorf("%s: %w", e.Name(), err)
			}
			t = tg.Header.Time
		}
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	return oldest, !oldest.IsZero(), nil
}

// ChainStatus is the result of checking one history.
type ChainStatus struct {
	OK       bool
	Tampered []string
	Redacted int
}

// VerifyChain checks that each header links to the previous one and that each
// evidence part matches its hash. Evidence replaced by a redaction marker is
// reported as redacted, never tampered.
func VerifyChain(history []*Tag) ChainStatus {
	st := ChainStatus{OK: true}
	prev := ""
	for _, t := range history {
		if t.Header.Previous != prev {
			st.OK = false
			st.Tampered = append(st.Tampered, fmt.Sprintf("%s: link to the previous tag does not match", t.Header.Time.Format(time.RFC3339)))
		}
		if t.Evidence.Redacted {
			st.Redacted++
		} else if h, err := EvidenceHash(t.Evidence); err != nil || h != t.Header.EvidenceHash {
			st.OK = false
			st.Tampered = append(st.Tampered, fmt.Sprintf("%s: evidence does not match its hash", t.Header.Time.Format(time.RFC3339)))
		}
		prev, _ = HeaderHash(t.Header)
	}
	return st
}

// Redact replaces a tag's evidence with a redaction marker. The header, and so
// the chain, stays as it was.
func Redact(t *Tag) { t.Evidence = Evidence{Redacted: true} }

// NextState applies the one rule: only FAIL opens a safeguard, and only PASS
// closes it. Every other verdict leaves the state where it was.
func NextState(prev, verdict string, retired bool) string {
	if retired {
		return Retired
	}
	switch verdict {
	case Fail:
		return Open
	case Pass:
		return Closed
	}
	if prev == "" || prev == Retired {
		return Unknown
	}
	return prev
}
