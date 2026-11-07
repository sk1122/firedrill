# Postgres (optional)

Firedrill needs no database. Its records and snapshots, on the `firedrill-tags` branch or in `.firedrill/local`, are the source of truth. Postgres only makes board builds over a long history faster.

## 1. Run a server

Firedrill is tested with Postgres 16. To try it locally:

```bash
docker run -d --name firedrill-db -e POSTGRES_PASSWORD=change-me -e POSTGRES_DB=firedrill -p 5432:5432 postgres:16-alpine
```

## 2. Set its URL in the environment

```bash
export FIREDRILL_DATABASE_URL="postgres://postgres:change-me@localhost:5432/firedrill?sslmode=disable"
```

Never put it in `config.yaml`. Firedrill creates its own tables on first use.

The database holds the same data as the snapshots, with emails and secrets as hashes. You can wipe it at any time; it's rebuilt from the snapshots.
