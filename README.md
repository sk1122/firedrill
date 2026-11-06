# Firedrill

Your rules, drilled weekly, with proof.

A safeguard is a rule your company believes it follows: nobody ships to production alone, admins use MFA, ex-employees lose access on their last day, AI agents cannot reach production credentials. Firedrill turns each one into a drill, runs it against the real systems, and returns PASS or FAIL with the evidence attached. It only reads. It sends no telemetry, uses no model, and your credentials stay on the machine that runs it.

Design: [docs/SPEC.md](docs/SPEC.md). Decisions: [DECISIONS.md](DECISIONS.md).

## Install

```bash
brew install sk1122/tap/firedrill
```

```bash
go install github.com/sk1122/firedrill/cmd/firedrill@latest
```

Or download a release binary. Every release lists checksums and an SBOM. Homebrew installs on macOS.

## Five minutes to the first failure

Keep Firedrill in its own private repo, `<org>/firedrill`, because records hold emails, account names and failing settings.

```bash
firedrill init --org acme --repos api,web,infra --owner @arjun
```

```bash
firedrill connect github
```

```bash
firedrill run
```

If the GitHub CLI is logged in, `connect github` reuses its token. With GitHub alone, 11 of the 20 drills run. The rest are listed with what connects them.

No GitHub yet? Point it at a checkout:

```bash
firedrill run --path ../api
```

Fix what failed, then prove it:

```bash
firedrill verify change/no-solo-ship
```

## How a result works

| Verdict | Meaning |
| --- | --- |
| PASS | Every condition held |
| FAIL | At least one condition failed |
| WARN | A warning matched, or Firedrill could read only part of what it needed |
| N/A | The drill does not apply here, or had nothing to check |
| SKIP | The drill needs a system that is not connected |
| ERROR | A fetch failed, or a condition named a field that does not exist |

One rule decides state over time: **only FAIL opens a safeguard, and only PASS closes it.** Every other verdict leaves it where it was, so a failure cannot disappear by disconnecting a system.

Exit codes: `0` by default. `1` when an unwaived critical or high safeguard turned open in this run. `2` on any ERROR, which wins over 1. `--fail-on open` also exits 1 while a critical or high safeguard stays open, and `--fail-on any` while any does.

## Commands

| Command | What it does |
| --- | --- |
| `firedrill init` | Creates `.firedrill/`, the salt and the starter packs |
| `firedrill connect <system>` | Checks access and prints the exact permissions |
| `firedrill run` | Runs every drill |
| `firedrill verify <drill>` | Reruns one drill and reports whether it closed |
| `firedrill verify-domain <domain>` | Proves you own a domain, so web checks may reach it |
| `firedrill export rulesets` | Run by a repo admin: saves bypass lists for CI |
| `firedrill list` | Every drill with owner, state, last verdict and waiver |
| `firedrill explain <drill>` | What it checks, what it saw and why it failed |
| `firedrill report` | Writes the HTML board |
| `firedrill validate [file]` | Checks drill files |

## Weekly in CI

Copy [docs/firedrill-workflow.yml](docs/firedrill-workflow.yml) to `.github/workflows/firedrill.yml` in your Firedrill repo, and add two repository secrets:

- `FIREDRILL_GITHUB_TOKEN`: a fine-grained read token for the listed repos, with Metadata, Administration, Environments and Contents.
- `FIREDRILL_SALT`: the value `init` generated. Keep it in your password manager too.

Each Monday it runs the drills, pushes records to the `firedrill-tags` branch, writes a step summary, and opens one issue per newly open safeguard, assigned to its owner. Protect `firedrill-tags` against force pushes and deletion, and require a reviewer on `main`, so changes to drills and waivers get reviewed. Owners need read access to the repo to be assigned.

CI sees committed files only, and its results say so. Run on a laptop with `--path` and `--include-home` to also read `.env*` files and user-level agent settings.

## Accepting a risk

Add to `.firedrill/waivers.yaml`:

```yaml
- drill: agent/no-prod-secrets-in-agent-reach
  target: acme/api
  finding: { file: scripts/seed-demo.sh, hash: "secret:3f9a2c" }  # optional: one finding only
  reason: "Demo key with no access, rotated monthly"
  approved_by: "@arjun"
  expires: 2027-01-31
```

A waived FAIL still prints as FAIL, stays out of the exit code and issues, and returns to normal the day it expires. A waiver on one finding never hides a real one found later in the same repo.

## Optional Postgres

Firedrill needs no database. To keep history in Postgres for fast board builds, run a server yourself and set the URL in the environment. Never put it in config.

```bash
docker run -d --name firedrill-db -e POSTGRES_PASSWORD=firedrill -e POSTGRES_DB=firedrill -p 5432:5432 postgres:16-alpine
```

```bash
export FIREDRILL_DATABASE_URL="postgres://postgres:firedrill@localhost:5432/firedrill?sslmode=disable"
```

Snapshots on the records branch stay the source of truth. The database holds the same data, with emails and secrets as HMACs, and can always be wiped and rebuilt.

## Safety model

- **Read scopes are the real control.** Every connector asks for read access only, and `connect` prints the permissions first.
- **A guard backs it up.** GitHub and Google calls may only GET and HEAD, plus Google's token exchange and GitHub's tarball redirect, each by exact host. AWS calls are checked by action against a fixed list. Anything else stops the run with ERROR.
- **Every call is logged** to `.firedrill/local/calls.jsonl`, with no query strings. `--dry-run` prints the calls and makes none.
- **Secrets are never stored.** A found secret becomes an HMAC keyed by your org's salt. Every record is scanned before it is written, and anything that looks like a secret is replaced with its hash.
- **Records stay private.** In a public repo Firedrill writes no record files and prints only counts, unless you pass `--public-ok`.
- **Drills cannot run code.** They are YAML with named facts and CEL conditions with a cost limit.
- **Network calls** go only to the connected systems, public DNS, crt.sh, hosts under domains you verified, and the Postgres you configured.

What it does not do yet: AWS checks read policy documents and take no account of Deny statements, permission boundaries or SCPs, so they can overstate access. Policy simulation is planned. IAM Identity Center arrives in v0.1.

## Build from source

```bash
make check
```

Tests that use Postgres start it through Docker and skip if Docker is not running.

## License

Apache-2.0. Embedded fonts are under the SIL Open Font License. See `internal/report/assets/fonts`.
