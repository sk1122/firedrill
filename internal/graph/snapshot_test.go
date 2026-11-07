package graph

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"compress/gzip"
)

func TestSnapshotDropsPrivateAttrs(t *testing.T) {
	dir := t.TempDir()
	g := New()
	now := time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)
	g.Node(Node{ID: "google:user/abc", Kind: KindIdentityUser, Attrs: map[string]any{"is_admin": true},
		Private: map[string]any{"email": "ravi@acme.com"}, SeenAt: now})
	path, err := WriteSnapshot(dir, TakeSnapshot(g, now))
	if err != nil {
		t.Fatal(err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	z, _ := gzip.NewReader(f)
	var raw any
	if err := json.NewDecoder(z).Decode(&raw); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(raw)
	if strings.Contains(string(b), "ravi@acme.com") {
		t.Fatal("snapshot must not hold a raw email")
	}
}

func TestEstateRebuiltFromSnapshotsMatchesMergedGraph(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	merged := NewEstate()
	for i := range 5 {
		at := base.AddDate(0, 0, 7*i)
		g := New()
		g.Node(Node{ID: "always", Kind: "k", Attrs: map[string]any{"run": float64(i)}, SeenAt: at})
		if i == 0 {
			g.Node(Node{ID: "leaves", Kind: "k", SeenAt: at})
			g.Edge(Edge{From: "always", To: "leaves", Kind: EdgeOwns})
		}
		s := TakeSnapshot(g, at)
		merged.Merge(s)
		if _, err := WriteSnapshot(dir, s); err != nil {
			t.Fatal(err)
		}
	}
	rebuilt, err := RebuildEstate(dir, base.AddDate(0, 2, 0))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rebuilt.Items, merged.Items) || !reflect.DeepEqual(rebuilt.Edges, merged.Edges) {
		t.Fatalf("rebuilt estate differs:\n%+v\n%+v", rebuilt.Items, merged.Items)
	}
	gone := rebuilt.Items["leaves"]
	if !gone.Gone || gone.Missed != 4 || !gone.LastSeen.Equal(base) {
		t.Fatalf("an item missing three runs is kept and marked gone: %+v", gone)
	}
	if rebuilt.Items["always"].Gone || !rebuilt.Items["always"].FirstSeen.Equal(base) {
		t.Fatalf("%+v", rebuilt.Items["always"])
	}
}

func TestRebuildSkipsSnapshotsOlderThanAYear(t *testing.T) {
	dir := t.TempDir()
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	g := New()
	g.Node(Node{ID: "old", Kind: "k", SeenAt: old})
	if _, err := WriteSnapshot(dir, TakeSnapshot(g, old)); err != nil {
		t.Fatal(err)
	}
	est, err := RebuildEstate(dir, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil || len(est.Items) != 0 {
		t.Fatalf("%v %v", err, est.Items)
	}
}

func TestCompactFoldsOldSnapshotsAndKeepsThem(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	for i, at := range []time.Time{now.AddDate(-3, 0, 0), now.AddDate(-2, 0, 0), now.AddDate(0, -1, 0)} {
		g := New()
		g.Node(Node{ID: "always", Kind: "k", Attrs: map[string]any{"run": float64(i)}, SeenAt: at})
		if i == 0 {
			g.Node(Node{ID: "oldest", Kind: "k", SeenAt: at})
		}
		if _, err := WriteSnapshot(dir, TakeSnapshot(g, at)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := Compact(dir, now)
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	files, _ := SnapshotFiles(dir)
	if len(files) != 2 || !strings.HasSuffix(files[0], CompactedName) {
		t.Fatalf("%v", files)
	}
	est, err := RebuildEstate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	if est.Items["oldest"] == nil || est.Items["always"].Attrs["run"] != float64(2) {
		t.Fatalf("compaction must keep every item: %+v", est.Items)
	}
	if n, _ := Compact(dir, now); n != 0 {
		t.Fatalf("nothing new to compact, got %d", n)
	}
}
