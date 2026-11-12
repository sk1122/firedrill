# HR leavers

`access/leavers-gone-everywhere` checks that everyone who has left the company holds no active Google Workspace account, no GCP role and no GitHub org membership or repo access. It judges whichever of Google Workspace, GCP and GitHub are connected, and needs at least one of them and a list of leavers from your HR system. It supersedes `access/leavers-locked-out`, which checked Google Workspace only.

## 1. Export the leavers

A CSV with these two columns, in any order:

```csv
email,leave_date
ravi@acme.com,2026-10-31
mei@acme.com,2026-11-14
```

`leave_date` is `YYYY-MM-DD`. An account is due to be locked once its leave date has passed, so future dates are fine to include.

## 2. Point Firedrill at it

```yaml
hr:
  leavers_csv: /secure/hr/leavers.csv
```

A relative path is read from your Firedrill repo's root folder, the one that holds `.firedrill`.

The file holds personal data. Keep it outside the repo if you can. Firedrill stores the emails only as hashes.

## 3. Check it

```bash
firedrill connect hr
```

If the file is missing, the drill gives SKIP, the same as an unconnected system.
