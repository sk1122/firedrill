package pg

import (
	"context"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/sk1122/firedrill/internal/graph"
)

func startPostgres(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("firedrill"), postgres.WithUsername("firedrill"), postgres.WithPassword("firedrill"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90*time.Second)))
	if err != nil {
		t.Skipf("Docker with Postgres is not available: %v", err)
	}
	t.Cleanup(func() { _ = c.Terminate(ctx) })
	url, err := c.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	return url
}

func writeRuns(t *testing.T, dir string, base time.Time, n int) {
	t.Helper()
	for i := range n {
		at := base.AddDate(0, 0, 7*i)
		g := graph.New()
		g.Node(graph.Node{ID: "always", Kind: "k", Attrs: map[string]any{"run": float64(i)}, SeenAt: at})
		if i == 0 {
			g.Node(graph.Node{ID: "leaves", Kind: "k", SeenAt: at})
			g.Edge(graph.Edge{From: "always", To: "leaves", Kind: graph.EdgeOwns, Source: "x"})
		}
		if _, err := graph.WriteSnapshot(dir, graph.TakeSnapshot(g, at)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEstateInPostgresMatchesMemoryAndRebuilds(t *testing.T) {
	url := startPostgres(t)
	ctx := context.Background()
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	if _, err := Open(ctx, url); err != nil {
		t.Fatalf("migrations must be repeatable: %v", err)
	}

	dir := t.TempDir()
	base := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	now := base.AddDate(0, 3, 0)
	writeRuns(t, dir, base, 5)
	n, err := s.Sync(ctx, dir, now)
	if err != nil || n != 5 {
		t.Fatalf("merged %d: %v", n, err)
	}
	if n, err := s.Sync(ctx, dir, now); err != nil || n != 0 {
		t.Fatalf("second sync merged %d: %v", n, err)
	}
	want, err := graph.RebuildEstate(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Estate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalize(got), normalize(want)) {
		t.Fatalf("Postgres estate differs from memory:\n%+v\n%+v", normalize(got), normalize(want))
	}
	if !got.Items["leaves"].Gone {
		t.Fatal("an item missing three runs must be gone")
	}

	if err := s.Reset(ctx); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Sync(ctx, dir, now); err != nil || n != 5 {
		t.Fatalf("rebuild after wipe merged %d: %v", n, err)
	}
	got, _ = s.Estate(ctx)
	if !reflect.DeepEqual(normalize(got), normalize(want)) {
		t.Fatal("rebuilt estate differs")
	}
}

type flatItem struct {
	Kind        string
	Run         any
	First, Last time.Time
	Missed      int
	Gone        bool
}

func normalize(e *graph.Estate) map[graph.ID]flatItem {
	out := map[graph.ID]flatItem{}
	for id, it := range e.Items {
		out[id] = flatItem{it.Kind, it.Attrs["run"], it.FirstSeen, it.LastSeen, it.Missed, it.Gone}
	}
	return out
}

func TestReadOnlyOpenNeverWritesAndKnowsWhenItIsCurrent(t *testing.T) {
	url := startPostgres(t)
	ctx := context.Background()
	dir := t.TempDir()
	base := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	now := base.AddDate(0, 3, 0)
	writeRuns(t, dir, base, 3)

	// A fresh database: reading neither migrates nor syncs.
	ro, err := OpenReadOnly(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close(ctx)
	if cur, err := ro.Current(ctx, dir, now); err != nil || cur {
		t.Fatalf("an empty database is not current: %v %v", cur, err)
	}
	var table *string
	if err := ro.conn.QueryRow(ctx, `SELECT to_regclass('estate_migrations')::text`).Scan(&table); err != nil || table != nil {
		t.Fatalf("a read-only open must not migrate: %v %v", table, err)
	}
	if _, err := ro.conn.Exec(ctx, `CREATE TABLE acme_probe (x int)`); err == nil {
		t.Fatal("the read-only session must refuse writes")
	}

	// The write path brings it up to date.
	rw, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close(ctx)
	if _, err := rw.Sync(ctx, dir, now); err != nil {
		t.Fatal(err)
	}
	if cur, err := ro.Current(ctx, dir, now); err != nil || !cur {
		t.Fatalf("synced database is current: %v %v", cur, err)
	}
	want, _ := graph.RebuildEstate(dir, now)
	got, err := ro.Estate(ctx)
	if err != nil || !reflect.DeepEqual(normalize(got), normalize(want)) {
		t.Fatalf("read-only estate differs from memory: %v", err)
	}
	if err := ro.Reset(ctx); err == nil {
		t.Fatal("the read-only session must refuse a wipe")
	}

	// A new snapshot not yet merged makes it stale, and reading does not merge it.
	writeRuns(t, dir, base.AddDate(0, 0, 21), 1)
	if cur, _ := ro.Current(ctx, dir, now.AddDate(0, 0, 21)); cur {
		t.Fatal("an unmerged snapshot means stale")
	}
	var n int
	if err := ro.conn.QueryRow(ctx, `SELECT count(*) FROM estate_snapshots`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("reading merged something: %d %v", n, err)
	}
	if _, err := rw.Sync(ctx, dir, now.AddDate(0, 0, 21)); err != nil {
		t.Fatal(err)
	}
	if cur, _ := ro.Current(ctx, dir, now.AddDate(0, 0, 21)); !cur {
		t.Fatal("current again after the write path syncs")
	}

	// A merged snapshot that left the folder, or aged out of the year a rebuild
	// reads, makes it stale too.
	files, _ := graph.SnapshotFiles(dir)
	if cur, _ := ro.Current(ctx, dir, base.AddDate(1, 1, 0)); cur {
		t.Fatal("a merged snapshot older than a year means stale")
	}
	if err := os.Remove(files[0]); err != nil {
		t.Fatal(err)
	}
	if cur, _ := ro.Current(ctx, dir, now.AddDate(0, 0, 21)); cur {
		t.Fatal("a merged snapshot gone from the folder means stale")
	}
}
