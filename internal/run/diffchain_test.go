package run

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/attest"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
)

// chainedRuns runs n times a week apart, the setup changing each time, so
// each run after the first stores a diff. It returns the records folder.
func chainedRuns(t *testing.T, n int) (string, []string) {
	t.Helper()
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d)
	for i := range n {
		bypass := "none"
		if i%2 == 1 {
			bypass = "allowed"
		}
		c.Connectors = []connector.Connector{&fake{name: "github", available: true, write: githubWriter(int64(i%2), bypass)}}
		c.Scope.Now = testNow.AddDate(0, 0, 7*i)
		if _, err := Run(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	files, err := diffFiles(filepath.Join(c.Records, "diffs"))
	if err != nil || len(files) != n-1 {
		t.Fatalf("%d diffs, %v", len(files), err)
	}
	return c.Records, files
}

func verify(t *testing.T, records string) DiffChainStatus {
	t.Helper()
	st, err := VerifyDiffs(records)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func editJSON(t *testing.T, path string, edit func(map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiffChainIntact(t *testing.T) {
	records, files := chainedRuns(t, 4)
	st := verify(t, records)
	if !st.OK || st.Records != 3 || st.Legacy != 0 || st.Checked != 6 || len(st.Compacted) != 0 {
		t.Fatalf("%+v", st)
	}
	first, _ := ReadDiff(files[0])
	second, _ := ReadDiff(files[1])
	if first.Previous != "" || first.SHA256 == "" || second.Previous != first.SHA256 {
		t.Fatalf("the second links to the first: %q %q %q", first.Previous, first.SHA256, second.Previous)
	}
	if h, _ := DiffRecordHash(second); h != second.SHA256 {
		t.Fatal("a record's own hash is checkable")
	}
}

func TestDiffChainEditedRecord(t *testing.T) {
	records, files := chainedRuns(t, 4)
	editJSON(t, files[1], func(m map[string]any) { m["changes"] = []any{} })
	st := verify(t, records)
	if st.OK || !strings.Contains(strings.Join(st.Problems, "\n"), filepath.Base(files[1])+": content does not match its sha256") {
		t.Fatalf("%+v", st)
	}
	// Rewriting its own hash too still breaks the link from the next record.
	b, _ := os.ReadFile(files[1])
	h, _ := canonicalHash(b)
	editJSON(t, files[1], func(m map[string]any) { m["sha256"] = h })
	st = verify(t, records)
	if st.OK || !strings.Contains(strings.Join(st.Problems, "\n"), filepath.Base(files[2])+": link to the previous record does not match") {
		t.Fatalf("%+v", st)
	}
}

func TestDiffChainDeletedMiddleRecord(t *testing.T) {
	records, files := chainedRuns(t, 4)
	if err := os.Remove(files[1]); err != nil {
		t.Fatal(err)
	}
	st := verify(t, records)
	if st.OK || len(st.Problems) != 1 || !strings.Contains(st.Problems[0], filepath.Base(files[2])+": link to the previous record does not match") {
		t.Fatalf("%+v", st)
	}
	// So is a deleted first record.
	records, files = chainedRuns(t, 3)
	_ = os.Remove(files[0])
	if st := verify(t, records); st.OK || !strings.Contains(st.Problems[0], "the record before it is missing") {
		t.Fatalf("%+v", st)
	}
}

func TestDiffChainReorderedRecord(t *testing.T) {
	records, files := chainedRuns(t, 4)
	// Swap the names of two records.
	tmp := files[0] + ".tmp"
	_ = os.Rename(files[0], tmp)
	_ = os.Rename(files[1], files[0])
	_ = os.Rename(tmp, files[1])
	st := verify(t, records)
	if st.OK || !strings.Contains(strings.Join(st.Problems, "\n"), "moved") {
		t.Fatalf("%+v", st)
	}
}

func TestDiffChainEditedSnapshot(t *testing.T) {
	records, files := chainedRuns(t, 3)
	rec, _ := ReadDiff(files[0])
	snap := filepath.Join(records, "snapshots", rec.FromSnapshot)
	if err := os.WriteFile(snap, []byte("not the snapshot"), 0o644); err != nil {
		t.Fatal(err)
	}
	st := verify(t, records)
	if st.OK || !strings.Contains(strings.Join(st.Problems, "\n"), "snapshot "+rec.FromSnapshot+" does not match its recorded hash") {
		t.Fatalf("%+v", st)
	}
}

func TestDiffChainCompactedSnapshotIsNotTampering(t *testing.T) {
	records, files := chainedRuns(t, 3)
	rec, _ := ReadDiff(files[0])
	// A year later every snapshot of these runs is folded away.
	if n, err := graph.Compact(filepath.Join(records, "snapshots"), testNow.AddDate(2, 0, 0)); err != nil || n != 3 {
		t.Fatalf("compacted %d: %v", n, err)
	}
	st := verify(t, records)
	if !st.OK || len(st.Compacted) != 3 || st.Checked != 0 || st.Compacted[0] != rec.FromSnapshot {
		t.Fatalf("%+v", st)
	}
	// A snapshot deleted with no compaction is reported.
	records, files = chainedRuns(t, 3)
	rec, _ = ReadDiff(files[1])
	_ = os.Remove(filepath.Join(records, "snapshots", rec.ToSnapshot))
	if st := verify(t, records); st.OK || !strings.Contains(strings.Join(st.Problems, "\n"), "is missing and was not compacted") {
		t.Fatalf("%+v", st)
	}
}

func TestDiffChainLegacyRecord(t *testing.T) {
	records, files := chainedRuns(t, 4)
	// A record written before the chain has neither field. As the first
	// record it starts the chain.
	editJSON(t, files[0], func(m map[string]any) { delete(m, "sha256"); delete(m, "previous_sha256") })
	if st := verify(t, records); !st.OK || st.Legacy != 1 {
		t.Fatalf("%+v", st)
	}
	// After a chained record, a record with no link is a problem.
	editJSON(t, files[2], func(m map[string]any) { delete(m, "sha256"); delete(m, "previous_sha256") })
	if st := verify(t, records); st.OK || !strings.Contains(strings.Join(st.Problems, "\n"), "has no link") {
		t.Fatalf("%+v", st)
	}
	// Records written entirely before the chain verify too.
	records, files = chainedRuns(t, 3)
	for _, f := range files {
		editJSON(t, f, func(m map[string]any) { delete(m, "sha256"); delete(m, "previous_sha256") })
	}
	if st := verify(t, records); !st.OK || st.Legacy != 2 {
		t.Fatalf("%+v", st)
	}
	// And the next run links to the last legacy record.
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: githubWriter(3, "none")})
	c.Records, c.Scope.Now = records, testNow.AddDate(0, 0, 30)
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if st := verify(t, records); !st.OK || st.Legacy != 2 || st.Records != 3 {
		t.Fatalf("%+v", st)
	}
}

func TestCIRunWritesChecksumsForAttestation(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: githubWriter(1, "none")})
	res, err := Run(context.Background(), c)
	if err != nil || res.ChecksumsPath != "" {
		t.Fatalf("a laptop run writes no checksums: %q %v", res.ChecksumsPath, err)
	}
	c.Attest = true
	c.Scope.Now = testNow.Add(time.Hour)
	c.Connectors = []connector.Connector{&fake{name: "github", available: true, write: githubWriter(0, "allowed")}}
	res, err = Run(context.Background(), c)
	if err != nil || res.ChecksumsPath == "" {
		t.Fatal(res, err)
	}
	if filepath.Dir(res.ChecksumsPath) != filepath.Join(c.Records, attest.Dir) || !strings.HasSuffix(res.ChecksumsPath, ".sha256") {
		t.Fatal(res.ChecksumsPath)
	}
	list, err := attest.ReadChecksums(res.ChecksumsPath)
	if err != nil {
		t.Fatal(err)
	}
	// Every tag this run wrote, and its diff, each with its current hash.
	if len(list) != len(res.TagPaths)+1 || len(res.TagPaths) != 1 {
		t.Fatalf("%v for %v", list, res.TagPaths)
	}
	for _, p := range append(append([]string{}, res.TagPaths...), res.DiffPath) {
		rel, _ := filepath.Rel(c.Records, p)
		sum, _ := FileSHA256(p)
		if list[filepath.ToSlash(rel)] != sum {
			t.Fatalf("%s: %q, want %q", rel, list[filepath.ToSlash(rel)], sum)
		}
	}
	raw, _ := os.ReadFile(res.ChecksumsPath)
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		sum, path, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || strings.HasPrefix(path, "/") || !strings.HasPrefix(path, "tags/") && !strings.HasPrefix(path, "diffs/") {
			t.Fatalf("not a sha256sum line: %q", line)
		}
	}
}
