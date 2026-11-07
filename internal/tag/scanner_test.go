package tag

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/graph"
)

func TestScanTagHashesSecretsAndLeavesStructuredFields(t *testing.T) {
	h := graph.NewHasher("salt")
	tg := &Tag{Evidence: Evidence{Facts: map[string]any{
		"doc": map[string]any{"password": "Zx8mQ2pL9vT4rW7yB1nC6dF3", "name": "plain value"},
		"secrets": map[string]any{"found": []any{map[string]any{
			"hash": "0123456789abcdef0123456789abcdef", "key_id": "AKIAIOSFODNN7ABCDEFG", "file": "scripts/domains.sh",
		}}},
	}}}
	ScanTag(tg, h)
	b, _ := json.Marshal(tg)
	s := string(b)
	if strings.Contains(s, "Zx8mQ2pL9vT4rW7yB1nC6dF3") {
		t.Fatal("a raw secret reached the record")
	}
	if !strings.Contains(s, "AKIAIOSFODNN7ABCDEFG") || !strings.Contains(s, "0123456789abcdef0123456789abcdef") {
		t.Fatalf("structured fields must pass untouched: %s", s)
	}
	if len(tg.Header.ScannerNotes) != 1 {
		t.Fatalf("want one scanner note: %v", tg.Header.ScannerNotes)
	}
}

func TestScanSnapshot(t *testing.T) {
	s := graph.Snapshot{Nodes: []graph.Node{{ID: "n", Attrs: map[string]any{"v": "sk_live_abcdefghijklmnop", "ok": "hello"}}}}
	if n := ScanSnapshot(&s, graph.NewHasher("s")); n != 1 {
		t.Fatalf("replaced %d", n)
	}
	if v := s.Nodes[0].Attrs["v"].(string); !strings.HasPrefix(v, "secret:") {
		t.Fatal(v)
	}
	if s.Nodes[0].Attrs["ok"] != "hello" {
		t.Fatal("ordinary values stay")
	}
}
