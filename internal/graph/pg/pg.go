// Package pg keeps the estate in Postgres for fast queries. Snapshots stay the
// source of truth, so the database can always be wiped and rebuilt, and it holds
// exactly what snapshots hold: emails and secrets as HMACs.
package pg

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/sk1122/firedrill/internal/graph"
)

//go:embed migrations/*.sql
var migrations embed.FS

// Store is an open estate database.
type Store struct{ conn *pgx.Conn }

// Open connects and applies any migration not yet applied. It is for the write
// path, after a run; readers use OpenReadOnly.
func Open(ctx context.Context, url string) (*Store, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("connect to Postgres: %w", redact(err))
	}
	s := &Store{conn: conn}
	if err := s.migrate(ctx); err != nil {
		_ = conn.Close(ctx)
		return nil, err
	}
	return s, nil
}

// OpenReadOnly connects for reading only: it applies no migration and the
// session refuses writes, so a read command can never change the database.
func OpenReadOnly(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("connect to Postgres: %w", redact(err))
	}
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = map[string]string{}
	}
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to Postgres: %w", redact(err))
	}
	return &Store{conn: conn}, nil
}

// Current says whether the estate in the database is exactly what
// graph.RebuildEstate(dir, now) gives: every migration applied, every snapshot
// in dir that a rebuild would merge already merged, and nothing merged that a
// rebuild would leave out, such as a snapshot since compacted, deleted or aged
// past a year. It only reads.
func (s *Store) Current(ctx context.Context, dir string, now time.Time) (bool, error) {
	var table *string
	if err := s.conn.QueryRow(ctx, `SELECT to_regclass('estate_migrations')::text`).Scan(&table); err != nil {
		return false, err
	}
	if table == nil {
		return false, nil
	}
	applied, err := s.names(ctx, `SELECT name FROM estate_migrations`)
	if err != nil {
		return false, err
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if _, ok := applied[e.Name()]; !ok {
			return false, nil
		}
	}
	merged := map[string]time.Time{}
	rows, err := s.conn.Query(ctx, `SELECT name, taken_at FROM estate_snapshots`)
	if err != nil {
		return false, err
	}
	for rows.Next() {
		var name string
		var at time.Time
		if err := rows.Scan(&name, &at); err != nil {
			rows.Close()
			return false, err
		}
		merged[name] = at
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	files, err := graph.SnapshotFiles(dir)
	if err != nil {
		return false, err
	}
	onDisk := map[string]bool{}
	for _, f := range files {
		name := filepath.Base(f)
		onDisk[name] = true
		if _, ok := merged[name]; ok {
			continue
		}
		if name == graph.CompactedName {
			return false, nil
		}
		snap, err := graph.ReadSnapshot(f)
		if err != nil {
			return false, err
		}
		if now.Sub(snap.Time) <= yearOfSnapshots {
			return false, nil
		}
	}
	for name, at := range merged {
		if !onDisk[name] || (name != graph.CompactedName && now.Sub(at) > yearOfSnapshots) {
			return false, nil
		}
	}
	return true, nil
}

// yearOfSnapshots is the window graph.RebuildEstate and Sync merge.
const yearOfSnapshots = 366 * 24 * time.Hour

func (s *Store) names(ctx context.Context, query string) (map[string]struct{}, error) {
	rows, err := s.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]struct{}{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out[n] = struct{}{}
	}
	return out, rows.Err()
}

// redact keeps a connection error from echoing a password in the URL.
func redact(err error) error {
	if _, ok := errors.AsType[*pgconn.ParseConfigError](err); ok {
		return errors.New("FIREDRILL_DATABASE_URL could not be parsed")
	}
	return err
}

// Close ends the connection.
func (s *Store) Close(ctx context.Context) error { return s.conn.Close(ctx) }

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS estate_migrations (name text PRIMARY KEY)`); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	entries, err := migrations.ReadDir("migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, n := range names {
		var done bool
		if err := s.conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM estate_migrations WHERE name = $1)`, n).Scan(&done); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		if done {
			continue
		}
		sql, err := migrations.ReadFile("migrations/" + n)
		if err != nil {
			return err
		}
		tx, err := s.conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migrate %s: %w", n, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO estate_migrations (name) VALUES ($1)`, n); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("migrate %s: %w", n, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Sync merges every snapshot under dir that the database has not seen, oldest
// first, skipping those older than a year. It returns how many it merged. If an
// older snapshot appears after a newer one was merged, the estate is wiped and
// rebuilt, since merges must run in order.
func (s *Store) Sync(ctx context.Context, dir string, now time.Time) (int, error) {
	files, err := graph.SnapshotFiles(dir)
	if err != nil {
		return 0, err
	}
	var newest *time.Time
	if err := s.conn.QueryRow(ctx, `SELECT max(taken_at) FROM estate_snapshots`).Scan(&newest); err != nil {
		return 0, err
	}
	merged := 0
	for _, f := range files {
		name := filepath.Base(f)
		var seen bool
		if err := s.conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM estate_snapshots WHERE name = $1)`, name).Scan(&seen); err != nil {
			return merged, err
		}
		if seen {
			continue
		}
		snap, err := graph.ReadSnapshot(f)
		if err != nil {
			return merged, err
		}
		if name != graph.CompactedName && now.Sub(snap.Time) > yearOfSnapshots {
			continue
		}
		if newest != nil && snap.Time.Before(*newest) {
			if err := s.Reset(ctx); err != nil {
				return merged, err
			}
			return s.Sync(ctx, dir, now)
		}
		if err := s.merge(ctx, name, snap); err != nil {
			return merged, err
		}
		t := snap.Time
		newest = &t
		merged++
	}
	return merged, nil
}

// Reset wipes the estate. Sync rebuilds it from snapshots.
func (s *Store) Reset(ctx context.Context) error {
	_, err := s.conn.Exec(ctx, `TRUNCATE estate_snapshots, estate_items, estate_edges`)
	return err
}

func (s *Store) merge(ctx context.Context, name string, snap graph.Snapshot) error {
	tx, err := s.conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, n := range snap.Nodes {
		attrs, err := json.Marshal(n.Attrs)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO estate_items (id, kind, attrs, first_seen, last_seen, missed, gone)
			VALUES ($1, $2, $3, $4, $4, 0, false)
			ON CONFLICT (id) DO UPDATE SET kind = $2, attrs = $3, last_seen = $4, missed = 0, gone = false`,
			string(n.ID), n.Kind, string(attrs), snap.Time)
		if err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `UPDATE estate_items SET missed = missed + 1, gone = (missed + 1 >= $1) WHERE last_seen < $2`,
		graph.GoneAfter, snap.Time)
	if err != nil {
		return err
	}
	for _, e := range snap.Edges {
		_, err = tx.Exec(ctx, `INSERT INTO estate_edges (from_id, to_id, kind, source) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			string(e.From), string(e.To), e.Kind, e.Source)
		if err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO estate_snapshots (name, taken_at) VALUES ($1, $2)`, name, snap.Time); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Estate loads the estate.
func (s *Store) Estate(ctx context.Context) (*graph.Estate, error) {
	est := graph.NewEstate()
	rows, err := s.conn.Query(ctx, `SELECT id, kind, attrs, first_seen, last_seen, missed, gone FROM estate_items`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var (
			id, kind string
			attrs    []byte
			it       graph.EstateItem
		)
		if err := rows.Scan(&id, &kind, &attrs, &it.FirstSeen, &it.LastSeen, &it.Missed, &it.Gone); err != nil {
			rows.Close()
			return nil, err
		}
		it.ID, it.Kind = graph.ID(id), kind
		if len(attrs) > 0 {
			if err := json.Unmarshal(attrs, &it.Attrs); err != nil {
				rows.Close()
				return nil, err
			}
		}
		it.FirstSeen, it.LastSeen = it.FirstSeen.UTC(), it.LastSeen.UTC()
		est.Items[it.ID] = &it
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	edges, err := s.conn.Query(ctx, `SELECT from_id, to_id, kind, source FROM estate_edges`)
	if err != nil {
		return nil, err
	}
	defer edges.Close()
	for edges.Next() {
		var from, to, kind, source string
		if err := edges.Scan(&from, &to, &kind, &source); err != nil {
			return nil, err
		}
		est.Edges[graph.Edge{From: graph.ID(from), To: graph.ID(to), Kind: kind, Source: source}] = struct{}{}
	}
	return est, edges.Err()
}
