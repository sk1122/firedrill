package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// DiffRecord is a diff as stored under records/diffs, with the SHA-256 of the
// two snapshot files it compared, so it can be checked again later. It reads
// on its own: compacting the snapshots it names does not break it.
//
// Stored records form a hash chain: Previous is the content hash of the
// record before it in the diffs folder, and SHA256 is this record's own
// content hash (see DiffRecordHash). A record written before the chain has
// neither, and verifies as the start of a chain.
type DiffRecord struct {
	graph.DiffResult
	FromSnapshot string `json:"from_snapshot"`
	ToSnapshot   string `json:"to_snapshot"`
	FromSHA256   string `json:"from_sha256"`
	ToSHA256     string `json:"to_sha256,omitempty"`
	// Audit says which audit sources were asked who made each change, and
	// which could not be read. Nil when no audit source was connected.
	Audit    *AuditNote `json:"audit,omitempty"`
	Previous string     `json:"previous_sha256,omitempty"`
	SHA256   string     `json:"sha256,omitempty"`
}

// RunSnapshots lists the snapshot files of single runs, oldest first. The
// compacted file merges many runs, so it is never one side of a diff.
func RunSnapshots(dir string) ([]string, error) {
	files, err := graph.SnapshotFiles(dir)
	if err != nil {
		return nil, err
	}
	out := files[:0:0]
	for _, f := range files {
		if filepath.Base(f) != graph.CompactedName {
			out = append(out, f)
		}
	}
	return out, nil
}

// sameStream reports whether two runs may be compared. A laptop run reads
// files CI never sees. A snapshot written before streams were recorded
// matches any.
func sameStream(a, b string) bool { return a == "" || b == "" || a == b }

// PreviousSnapshot finds the newest run snapshot in dir of the same stream
// that sorts before the file named before (or the newest of all when before is
// empty). It returns "" when there is none.
func PreviousSnapshot(dir, stream, before string) (string, *graph.Snapshot, error) {
	files, err := RunSnapshots(dir)
	if err != nil {
		return "", nil, err
	}
	for i := len(files) - 1; i >= 0; i-- {
		if before != "" && filepath.Base(files[i]) >= filepath.Base(before) {
			continue
		}
		s, err := graph.ReadSnapshot(files[i])
		if err != nil {
			return "", nil, err
		}
		if sameStream(stream, s.Stream) {
			return files[i], &s, nil
		}
	}
	return "", nil, nil
}

// FileSHA256 returns the hex SHA-256 of a file.
func FileSHA256(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), nil
}

// DiffName is the diff file for a snapshot file: the same timestamp.
func DiffName(snapshot string) string {
	return strings.TrimSuffix(filepath.Base(snapshot), ".json.gz") + ".json"
}

// WriteDiff stores a diff under records/diffs, linked to the record before it.
func WriteDiff(records string, rec *DiffRecord) (string, error) {
	dir := filepath.Join(records, "diffs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := DiffName(rec.ToSnapshot)
	rec.Previous, rec.SHA256 = "", ""
	prev, err := diffBefore(dir, name)
	if err != nil {
		return "", err
	}
	if prev != "" {
		raw, err := os.ReadFile(prev)
		if err != nil {
			return "", err
		}
		if rec.Previous, err = canonicalHash(raw); err != nil {
			return "", fmt.Errorf("%s: %w", prev, err)
		}
	}
	if rec.SHA256, err = DiffRecordHash(rec); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, DiffName(rec.ToSnapshot))
	return path, os.WriteFile(path, b, 0o644)
}

// ReadDiff loads one stored diff.
func ReadDiff(path string) (*DiffRecord, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec DiffRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &rec, nil
}

// LatestDiff returns the newest stored diff, or nil when there is none.
func LatestDiff(records string) (*DiffRecord, error) {
	entries, err := os.ReadDir(filepath.Join(records, "diffs"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	sort.Strings(names)
	return ReadDiff(filepath.Join(records, "diffs", names[len(names)-1]))
}

// coverageOf records which connectors ran and which of them failed.
func coverageOf(ran []string, failures map[string]string) *graph.Coverage {
	c := &graph.Coverage{Read: []string{}}
	for _, name := range ran {
		if failures[name] == "" {
			c.Read = append(c.Read, name)
		}
	}
	for name := range failures {
		c.Failed = append(c.Failed, name)
	}
	sort.Strings(c.Read)
	sort.Strings(c.Failed)
	return c
}

// Caught maps a node ID to the drill verdicts that read it and failed.
type Caught map[graph.ID][]graph.DrillRef

func (c Caught) add(drillID, target string, read []graph.ID) {
	for _, id := range read {
		ref := graph.DrillRef{Drill: drillID, Target: target}
		dup := false
		for _, r := range c[id] {
			dup = dup || r == ref
		}
		if !dup {
			c[id] = append(c[id], ref)
		}
	}
}

// CaughtByOutcomes collects what this run's failing or open verdicts read.
func CaughtByOutcomes(outcomes []*Outcome) Caught {
	c := Caught{}
	for _, o := range outcomes {
		if o.Verdict == tag.Fail || o.State == tag.Open {
			c.add(o.Drill.ID, o.Target, o.Read)
		}
	}
	return c
}

// CaughtByStore collects what the latest failing or open tags read, for a diff
// worked out after the run that wrote them.
func CaughtByStore(store tag.Store) (Caught, error) {
	c := Caught{}
	keys, err := store.Keys()
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		t, err := store.Latest(k.DrillID, k.TargetSlug)
		if err != nil || t == nil {
			continue
		}
		if t.Header.Verdict != tag.Fail && t.Header.State != tag.Open {
			continue
		}
		read := make([]graph.ID, len(t.Evidence.Read))
		for i, id := range t.Evidence.Read {
			read[i] = graph.ID(id)
		}
		c.add(t.Header.DrillID, t.Header.Target, read)
	}
	return c, nil
}

// Annotate links each change to the drills that also caught it and to the
// person its node belongs to. It leaves the diff itself as Diff made it.
func Annotate(d *graph.DiffResult, old, new graph.Snapshot, caught Caught) {
	people := map[graph.ID]graph.ID{}
	for _, s := range []graph.Snapshot{old, new} {
		for _, e := range s.Edges {
			if e.Kind == graph.EdgeSamePerson {
				people[e.To] = e.From
			}
		}
	}
	for i := range d.Changes {
		c := &d.Changes[i]
		ids := []graph.ID{c.Subject}
		if c.Edge != nil {
			ids = append(ids, c.Edge.From, c.Edge.To)
		}
		c.CaughtBy = nil
		for _, id := range ids {
			for _, ref := range caught[id] {
				if !containsRef(c.CaughtBy, ref) {
					c.CaughtBy = append(c.CaughtBy, ref)
				}
			}
			if c.Person == "" {
				if p, ok := people[id]; ok {
					c.Person = PersonShortID(p)
				}
			}
		}
		sort.Slice(c.CaughtBy, func(a, b int) bool {
			return c.CaughtBy[a].Drill+"\x00"+c.CaughtBy[a].Target < c.CaughtBy[b].Drill+"\x00"+c.CaughtBy[b].Target
		})
	}
}

func containsRef(list []graph.DrillRef, r graph.DrillRef) bool {
	for _, x := range list {
		if x == r {
			return true
		}
	}
	return false
}

// PersonShortID is how a person is shown: the start of their hashed ID.
func PersonShortID(id graph.ID) string {
	s := strings.TrimPrefix(string(id), "person:")
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// groupKey is who a change is grouped under: the actor an audit source named,
// or else the person its node belongs to, or "" for neither. A person named as
// the actor groups with that person's own changes, by short ID.
func groupKey(c graph.Change) string {
	if c.Actor != "" {
		if rest, ok := strings.CutPrefix(c.Actor, "person:"); ok {
			return PersonShortID(graph.ID("person:" + rest))
		}
		return c.Actor
	}
	return c.Person
}

// ChangeGroup is a run of changes shown under one heading.
type ChangeGroup struct {
	Title     string
	Person    string
	Weakening bool
	Changes   []graph.Change
}

// GroupChanges orders changes for reading: weakenings first, then the rest.
// Within each, one person's changes come together under their short ID, then
// the others by type.
func GroupChanges(changes []graph.Change) []ChangeGroup {
	var out []ChangeGroup
	for _, weak := range []bool{true, false} {
		byPerson := map[string][]graph.Change{}
		byType := map[string][]graph.Change{}
		for _, c := range changes {
			if c.Weakening != weak {
				continue
			}
			if who := groupKey(c); who != "" {
				byPerson[who] = append(byPerson[who], c)
			} else {
				byType[c.Type] = append(byType[c.Type], c)
			}
		}
		people := make([]string, 0, len(byPerson))
		for p := range byPerson {
			people = append(people, p)
		}
		sort.Strings(people)
		for _, p := range people {
			title := "Person " + p
			if strings.Contains(p, " ") || strings.Contains(p, ":") {
				title = "Changed by " + graph.ActorLabel(p)
			}
			out = append(out, ChangeGroup{Title: title, Person: p, Weakening: weak, Changes: byPerson[p]})
		}
		kinds := make([]string, 0, len(byType))
		for t := range byType {
			kinds = append(kinds, t)
		}
		sort.Slice(kinds, func(i, j int) bool { return graph.ChangeRank(kinds[i]) < graph.ChangeRank(kinds[j]) })
		for _, t := range kinds {
			out = append(out, ChangeGroup{Title: graph.ChangeLabel(t), Weakening: weak, Changes: byType[t]})
		}
	}
	return out
}

// CompareFiles diffs two snapshot files, the way a run does, for a diff asked
// for later. It reads only local files.
func CompareFiles(fromPath, toPath string, caught Caught) (*DiffRecord, error) {
	old, err := graph.ReadSnapshot(fromPath)
	if err != nil {
		return nil, err
	}
	new, err := graph.ReadSnapshot(toPath)
	if err != nil {
		return nil, err
	}
	d := graph.Diff(old, new)
	Annotate(&d, old, new, caught)
	rec := &DiffRecord{DiffResult: d, FromSnapshot: filepath.Base(fromPath), ToSnapshot: filepath.Base(toPath)}
	if rec.FromSHA256, err = FileSHA256(fromPath); err != nil {
		return nil, err
	}
	if rec.ToSHA256, err = FileSHA256(toPath); err != nil {
		return nil, err
	}
	return rec, nil
}

// diffAgainst works out what changed since the previous run and, when records
// are written, stores it next to the snapshot.
func diffAgainst(ctx context.Context, prevPath string, prev *graph.Snapshot, snap graph.Snapshot, snapPath string, c Config, res *Result, h graph.Hasher) error {
	d := graph.Diff(*prev, snap)
	Annotate(&d, *prev, snap, CaughtByOutcomes(res.Outcomes))
	note := auditDiff(ctx, c, res, &d)
	tag.ScanDiff(&d, h)
	rec := &DiffRecord{DiffResult: d, FromSnapshot: filepath.Base(prevPath), ToSnapshot: graph.SnapshotName(snap.Time), Audit: note}
	var err error
	if rec.FromSHA256, err = FileSHA256(prevPath); err != nil {
		return err
	}
	res.Diff = rec
	if snapPath == "" {
		return nil
	}
	if rec.ToSHA256, err = FileSHA256(snapPath); err != nil {
		return err
	}
	res.DiffPath, err = WriteDiff(c.Records, rec)
	return err
}

// previousOf loads the snapshot a run compares itself to, before it writes
// its own.
func previousOf(c Config) (string, *graph.Snapshot) {
	if c.Records == "" {
		return "", nil
	}
	path, prev, err := PreviousSnapshot(filepath.Join(c.Records, "snapshots"), c.Stream, "")
	if err != nil || prev == nil {
		// An unreadable earlier snapshot means no diff, never a failed run.
		return "", nil
	}
	return path, prev
}
