CREATE TABLE IF NOT EXISTS estate_snapshots (
  name text PRIMARY KEY,
  taken_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS estate_items (
  id text PRIMARY KEY,
  kind text NOT NULL,
  attrs jsonb,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  missed integer NOT NULL DEFAULT 0,
  gone boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS estate_items_kind ON estate_items (kind);

CREATE TABLE IF NOT EXISTS estate_edges (
  from_id text NOT NULL,
  to_id text NOT NULL,
  kind text NOT NULL,
  source text NOT NULL DEFAULT '',
  PRIMARY KEY (from_id, to_id, kind, source)
);
