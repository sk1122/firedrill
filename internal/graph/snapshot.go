package graph

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Snapshot is one run's graph as stored next to its tags. Private attributes
// never reach it, so emails and raw values stay out of history.
type Snapshot struct {
	Time  time.Time `json:"time"`
	Nodes []Node    `json:"nodes"`
	Edges []Edge    `json:"edges"`
}

// TakeSnapshot captures a graph.
func TakeSnapshot(g Reader, at time.Time) Snapshot {
	return Snapshot{Time: at.UTC(), Nodes: g.Nodes(""), Edges: g.Edges("")}
}

// WriteSnapshot stores a snapshot as compressed JSON under dir.
func WriteSnapshot(dir string, s Snapshot) (string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, s.Time.Format("2006-01-02T15-04-05Z")+".json.gz")
	return path, writeSnapshotFile(path, s)
}

func writeSnapshotFile(path string, s Snapshot) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	z := gzip.NewWriter(f)
	if err := json.NewEncoder(z).Encode(s); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	return f.Close()
}

// ReadSnapshot loads one snapshot file.
func ReadSnapshot(path string) (Snapshot, error) {
	var s Snapshot
	f, err := os.Open(path)
	if err != nil {
		return s, err
	}
	defer func() { _ = f.Close() }()
	z, err := gzip.NewReader(f)
	if err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	if err := json.NewDecoder(z).Decode(&s); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// SnapshotFiles lists snapshot files under dir, oldest first.
func SnapshotFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json.gz") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// EstateItem is one thing across runs. Items missing for three runs in a row
// are marked gone and kept, so history survives.
type EstateItem struct {
	ID        ID             `json:"id"`
	Kind      string         `json:"kind"`
	Attrs     map[string]any `json:"attrs,omitempty"`
	FirstSeen time.Time      `json:"first_seen"`
	LastSeen  time.Time      `json:"last_seen"`
	Missed    int            `json:"missed"`
	Gone      bool           `json:"gone"`
}

// GoneAfter is how many runs an item may be missing before it is marked gone.
const GoneAfter = 3

// Estate is the graph across runs.
type Estate struct {
	Items map[ID]*EstateItem
	Edges map[Edge]struct{}
}

// NewEstate returns an empty estate.
func NewEstate() *Estate {
	return &Estate{Items: map[ID]*EstateItem{}, Edges: map[Edge]struct{}{}}
}

// Merge folds one snapshot in. Snapshots must be merged oldest first.
func (e *Estate) Merge(s Snapshot) {
	seen := map[ID]bool{}
	for _, n := range s.Nodes {
		seen[n.ID] = true
		it, ok := e.Items[n.ID]
		if !ok {
			it = &EstateItem{ID: n.ID, Kind: n.Kind, FirstSeen: s.Time}
			e.Items[n.ID] = it
		}
		it.Attrs, it.LastSeen, it.Missed, it.Gone = n.Attrs, s.Time, 0, false
	}
	for id, it := range e.Items {
		if !seen[id] {
			it.Missed++
			if it.Missed >= GoneAfter {
				it.Gone = true
			}
		}
	}
	for _, edge := range s.Edges {
		e.Edges[edge] = struct{}{}
	}
}

// Sorted returns items in ID order.
func (e *Estate) Sorted() []*EstateItem {
	out := make([]*EstateItem, 0, len(e.Items))
	for _, it := range e.Items {
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CompactedName holds snapshots older than a year. It sorts first, so it merges
// before anything newer.
const CompactedName = "0000-compacted.json.gz"

const yearOfSnapshots = 366 * 24 * time.Hour

// Compact folds snapshots older than a year into one, keeping the latest state
// of each item, then removes the originals. It returns how many it folded.
func Compact(dir string, now time.Time) (int, error) {
	files, err := SnapshotFiles(dir)
	if err != nil {
		return 0, err
	}
	merged := Snapshot{}
	nodes := map[ID]Node{}
	edges := map[Edge]struct{}{}
	var old []string
	for _, f := range files {
		s, err := ReadSnapshot(f)
		if err != nil {
			return 0, err
		}
		base := filepath.Base(f)
		if base != CompactedName && now.Sub(s.Time) <= yearOfSnapshots {
			continue
		}
		for _, n := range s.Nodes {
			nodes[n.ID] = n
		}
		for _, e := range s.Edges {
			edges[e] = struct{}{}
		}
		if s.Time.After(merged.Time) {
			merged.Time = s.Time
		}
		if base != CompactedName {
			old = append(old, f)
		}
	}
	if len(old) == 0 {
		return 0, nil
	}
	for _, n := range nodes {
		merged.Nodes = append(merged.Nodes, n)
	}
	sort.Slice(merged.Nodes, func(i, j int) bool { return merged.Nodes[i].ID < merged.Nodes[j].ID })
	for e := range edges {
		merged.Edges = append(merged.Edges, e)
	}
	sort.Slice(merged.Edges, func(i, j int) bool {
		a, b := merged.Edges[i], merged.Edges[j]
		return string(a.From)+string(a.To)+a.Kind < string(b.From)+string(b.To)+b.Kind
	})
	if err := writeSnapshotFile(filepath.Join(dir, CompactedName), merged); err != nil {
		return 0, err
	}
	for _, f := range old {
		if err := os.Remove(f); err != nil {
			return 0, err
		}
	}
	return len(old), nil
}

// RebuildEstate merges the compacted snapshot, then every snapshot newer than a
// year ago, oldest first.
func RebuildEstate(dir string, now time.Time) (*Estate, error) {
	files, err := SnapshotFiles(dir)
	if err != nil {
		return nil, err
	}
	est := NewEstate()
	for _, f := range files {
		s, err := ReadSnapshot(f)
		if err != nil {
			return nil, err
		}
		if filepath.Base(f) != CompactedName && now.Sub(s.Time) > yearOfSnapshots {
			continue
		}
		est.Merge(s)
	}
	return est, nil
}
