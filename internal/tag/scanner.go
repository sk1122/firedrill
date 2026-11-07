package tag

import (
	"fmt"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/secrets"
)

// exemptKeys are known structured fields: graph IDs, hashes and AWS access key
// IDs. An access key ID is an identifier, never the secret.
var exemptKeys = map[string]bool{
	"id": true, "hash": true, "key_id": true, "read": true, "keys": true, "credentials": true,
	"shared_prod_staging": true, "shared_credentials": true,
}

// ScanValue replaces any string that looks like a secret with its hash, and
// returns a note for each. A hit never stops a run and never changes a verdict.
func ScanValue(v any, h graph.Hasher, where string, notes *[]string) any {
	switch val := v.(type) {
	case string:
		if secrets.LooksLikeSecret(val) {
			*notes = append(*notes, fmt.Sprintf("%s looked like a secret and was replaced with its hash", where))
			return "secret:" + h.Sum(val)
		}
		return val
	case []any:
		out := make([]any, len(val))
		for i, x := range val {
			out[i] = ScanValue(x, h, where, notes)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, x := range val {
			if exemptKeys[k] {
				out[k] = x
				continue
			}
			out[k] = ScanValue(x, h, where+"."+k, notes)
		}
		return out
	}
	return v
}

// ScanTag scans a tag's evidence in place before it is written.
func ScanTag(t *Tag, h graph.Hasher) {
	var notes []string
	for alias, v := range t.Evidence.Facts {
		t.Evidence.Facts[alias] = ScanValue(v, h, alias, &notes)
	}
	t.Header.ScannerNotes = append(t.Header.ScannerNotes, notes...)
}

// ScanSnapshot scans a snapshot's attributes before it is written, returning how
// many values it replaced.
func ScanSnapshot(s *graph.Snapshot, h graph.Hasher) int {
	var notes []string
	for i := range s.Nodes {
		if s.Nodes[i].Attrs == nil {
			continue
		}
		s.Nodes[i].Attrs, _ = ScanValue(s.Nodes[i].Attrs, h, string(s.Nodes[i].ID), &notes).(map[string]any)
	}
	return len(notes)
}
