package run

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/graph"
)

// The stored diffs are chained like tags: each record names the content hash
// of the record before it, so a record that is edited, deleted from the middle
// or moved out of order breaks the link after it. The hash is over the
// record's canonical content: the JSON decoded to plain values, the sha256
// field left out, and encoded again with sorted keys and no spacing. Decoding
// first means the hash does not depend on how a file was indented, and works
// the same for a record written before a field existed.

// canonicalHash returns the SHA-256 of a stored record's canonical content.
func canonicalHash(raw []byte) (string, error) {
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return "", err
	}
	delete(m, "sha256")
	b, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// DiffRecordHash returns a record's content hash, the value its sha256 field
// holds and the next record's previous_sha256 names.
func DiffRecordHash(rec *DiffRecord) (string, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return "", err
	}
	return canonicalHash(b)
}

// diffFiles lists the stored diffs, oldest first. The name is the later
// snapshot's time, so name order is time order.
func diffFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// diffBefore returns the newest stored diff that sorts before name, or "".
func diffBefore(dir, name string) (string, error) {
	files, err := diffFiles(dir)
	if err != nil {
		return "", err
	}
	prev := ""
	for _, f := range files {
		if filepath.Base(f) < name {
			prev = f
		}
	}
	return prev, nil
}

// DiffChainStatus is the result of checking the stored diffs.
type DiffChainStatus struct {
	Records int `json:"records"`
	// Legacy counts records written before the chain, which carry no link.
	Legacy int  `json:"legacy,omitempty"`
	OK     bool `json:"ok"`
	// Problems name a record that was edited, a link that does not match
	// (a record missing or moved), or a snapshot that no longer matches its
	// recorded hash.
	Problems []string `json:"problems,omitempty"`
	// Compacted names snapshots folded into the compacted file, whose hash
	// can no longer be checked. That is expected after a year, not tampering.
	Compacted []string `json:"compacted,omitempty"`
	// Checked counts snapshot files found and matched.
	Checked int `json:"snapshots_checked"`
}

// VerifyDiffs checks the chain of stored diffs under records/diffs, and each
// snapshot a diff names against its recorded hash when the file still exists.
// It reads only local files.
func VerifyDiffs(records string) (DiffChainStatus, error) {
	st := DiffChainStatus{OK: true}
	files, err := diffFiles(filepath.Join(records, "diffs"))
	if err != nil {
		return st, err
	}
	snaps := filepath.Join(records, "snapshots")
	compactedUpTo := compactedTime(snaps)
	problem := func(format string, a ...any) {
		st.OK = false
		st.Problems = append(st.Problems, fmt.Sprintf(format, a...))
	}
	prevHash := ""
	chained := false // an earlier record carried a link or its own hash
	var prevTo time.Time
	for _, f := range files {
		name := filepath.Base(f)
		raw, err := os.ReadFile(f)
		if err != nil {
			return st, err
		}
		st.Records++
		var rec DiffRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			problem("%s: not a readable diff record: %v", name, err)
			prevHash, chained = "", true
			continue
		}
		hash, err := canonicalHash(raw)
		if err != nil {
			return st, err
		}
		legacy := rec.Previous == "" && rec.SHA256 == ""
		switch {
		case legacy && chained:
			problem("%s: has no link to the record before it, though earlier records are chained (edited, or a record was replaced)", name)
		case legacy:
			st.Legacy++
		case rec.SHA256 != "" && rec.SHA256 != hash:
			problem("%s: content does not match its sha256 (edited)", name)
		}
		if !legacy {
			switch {
			case rec.Previous != prevHash && prevHash == "":
				problem("%s: links to a record that is not here (the record before it is missing)", name)
			case rec.Previous != prevHash:
				problem("%s: link to the previous record does not match (a record was edited, deleted or moved)", name)
			}
			chained = true
		}
		if name != DiffName(rec.ToSnapshot) {
			problem("%s: names snapshot %s, which belongs to another file name (moved or renamed)", name, rec.ToSnapshot)
		}
		if !prevTo.IsZero() && rec.To.Before(prevTo) {
			problem("%s: is older than the record before it (out of order)", name)
		}
		prevTo, prevHash = rec.To, hash
		for _, s := range []struct{ file, sum string }{{rec.FromSnapshot, rec.FromSHA256}, {rec.ToSnapshot, rec.ToSHA256}} {
			if s.file == "" || s.sum == "" {
				continue
			}
			path := filepath.Join(snaps, filepath.Base(s.file))
			sum, err := FileSHA256(path)
			switch {
			case errors.Is(err, os.ErrNotExist):
				if t, ok := snapshotTime(s.file); ok && !compactedUpTo.IsZero() && !t.After(compactedUpTo) {
					if !contains(st.Compacted, s.file) {
						st.Compacted = append(st.Compacted, s.file)
					}
				} else {
					problem("%s: snapshot %s is missing and was not compacted", name, s.file)
				}
			case err != nil:
				return st, err
			case sum != s.sum:
				problem("%s: snapshot %s does not match its recorded hash (edited)", name, s.file)
			default:
				st.Checked++
			}
		}
	}
	sort.Strings(st.Compacted)
	return st, nil
}

// compactedTime is the newest snapshot time folded into the compacted file,
// or zero when there is none.
func compactedTime(dir string) time.Time {
	s, err := graph.ReadSnapshot(filepath.Join(dir, graph.CompactedName))
	if err != nil {
		return time.Time{}
	}
	return s.Time
}

// snapshotTime reads the time from a snapshot file name.
func snapshotTime(name string) (time.Time, bool) {
	t, err := time.Parse("2006-01-02T15-04-05Z", strings.TrimSuffix(filepath.Base(name), ".json.gz"))
	return t, err == nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
