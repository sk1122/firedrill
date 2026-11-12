package main

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/graph/pg"
)

func TestLoadEstateFallsBackToSnapshots(t *testing.T) {
	records := t.TempDir()
	snaps := filepath.Join(records, "snapshots")
	at := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	g := graph.New()
	g.Node(graph.Node{ID: "acme-api", Kind: "k", SeenAt: at})
	if _, err := graph.WriteSnapshot(snaps, graph.TakeSnapshot(g, at)); err != nil {
		t.Fatal(err)
	}
	want, err := graph.RebuildEstate(snaps, at)
	if err != nil {
		t.Fatal(err)
	}
	for name, url := range map[string]string{
		"no database":          "",
		"unreachable database": "postgres://acme:acme@127.0.0.1:1/acme?connect_timeout=2",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("FIREDRILL_DATABASE_URL", url)
			got, err := loadEstate(context.Background(), records, at)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) || got.Items["acme-api"] == nil {
				t.Fatalf("got %+v, want the snapshot estate %+v", got, want)
			}
		})
	}
}

func TestLoadEstateNeverWritesAndSkipsAStaleDatabase(t *testing.T) {
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
	t.Setenv("FIREDRILL_DATABASE_URL", url)

	records := t.TempDir()
	snaps := filepath.Join(records, "snapshots")
	first := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	snap := func(id graph.ID, at time.Time) {
		g := graph.New()
		g.Node(graph.Node{ID: id, Kind: "k", SeenAt: at})
		if _, err := graph.WriteSnapshot(snaps, graph.TakeSnapshot(g, at)); err != nil {
			t.Fatal(err)
		}
	}
	snap("acme-api", first)

	// Before any run has synced, report falls back without touching the database.
	if _, err := loadEstate(ctx, records, first); err != nil {
		t.Fatal(err)
	}
	rw, err := pg.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close(ctx)
	if _, err := rw.Sync(ctx, snaps, first); err != nil {
		t.Fatal(err)
	}

	// A newer snapshot the database has not merged: report uses snapshots and
	// leaves the database as it was.
	second := first.AddDate(0, 0, 7)
	snap("acme-web", second)
	got, err := loadEstate(ctx, records, second)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := graph.RebuildEstate(snaps, second)
	if !reflect.DeepEqual(got, want) || got.Items["acme-web"] == nil {
		t.Fatalf("a stale database must give way to snapshots: %+v", got)
	}
	if n, err := rw.Sync(ctx, snaps, second); err != nil || n != 1 {
		t.Fatalf("report must not have synced: the write path merged %d (%v)", n, err)
	}
	// Current now: the estate comes from the database and matches.
	if got, err := loadEstate(ctx, records, second); err != nil || len(got.Items) != len(want.Items) {
		t.Fatalf("%v %+v", err, got)
	}
}
