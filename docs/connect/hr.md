# HR leavers

`access/leavers-locked-out` checks that everyone who has left the company has no active Google Workspace account. It needs [Workspace connected](google-workspace.md) and a list of leavers from your HR system.

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
