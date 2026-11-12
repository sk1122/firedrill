<p align="center">
  <img src="docs/assets/logo.svg" alt="Firedrill" width="120">
</p>

<h1 align="center">Firedrill</h1>

<p align="center"><strong>Your rules, drilled weekly, with proof.</strong></p>

<p align="center">
  <a href="https://github.com/sk1122/firedrill/actions/workflows/ci.yml"><img src="https://github.com/sk1122/firedrill/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-16161A" alt="License: Apache-2.0"></a>
  <a href="go.mod"><img src="https://img.shields.io/badge/go-1.27-16161A" alt="Go 1.27"></a>
  <a href="https://github.com/sk1122/firedrill-drills"><img src="https://img.shields.io/badge/drill%20hub-34%20drills-D3261A" alt="Drill hub"></a>
</p>

<p align="center"><img src="docs/assets/hazard.svg" alt="" width="100%" height="12"></p>

A fire drill doesn't ask whether the building is safe. It pulls the alarm and watches what happens.

Firedrill does that for the rules your company believes it follows: nobody ships to production alone, admins use MFA, ex-employees lose access on their last day, AI agents can't reach production credentials. Each rule becomes a **drill**. Firedrill runs it against the real systems and returns PASS or FAIL with the evidence attached, every week, and keeps the record.

- **It only reads.** Every connector asks for read access, and a guard refuses anything else.
- **It stays with you.** No telemetry, no model, no server. Credentials stay on the machine or CI that runs it.
- **It keeps proof.** Every result is a hash-chained record with the evidence that decided it. A failure stays open until a run passes.

## Why

AI made claims nearly free: code, approvals, "done" statuses, compliance answers. Proof stayed expensive. In April 2026 a coding agent working on a staging task [used a cloud token it found in an unrelated file](https://zenity.io/blog/current-events/ai-agent-database-deletion-pocketos) and deleted a company's production database, with its backups, in seconds. `agent/no-prod-secrets-in-agent-reach` is the drill that catches a token like that before an agent does.

Existing tools check pieces. OpenSSF Scorecard and legitify score GitHub settings, and Prowler and Steampipe query cloud configuration. Firedrill starts from your own rules, keeps a record of each one over time, and checks what AI agents can reach.

## Install

```bash
brew install sk1122/tap/firedrill
```

```bash
go install github.com/sk1122/firedrill/cmd/firedrill@latest
```

Or download a binary from [Releases](https://github.com/sk1122/firedrill/releases). Every release lists checksums and an SBOM. Builds for macOS, Linux and Windows, on amd64 and arm64.

## Five minutes to the first failure

Keep Firedrill in its own private repo, such as `<org>/firedrill`, because records hold account names and failing settings.

```bash
firedrill init --org acme --repos api,web,infra --owner @arjun
```

```bash
firedrill connect github
```

```bash
firedrill run
```

If the GitHub CLI is logged in, `connect github` reuses its login. With GitHub alone, 18 of the 34 starter drills run. The rest are listed with what connects them.

No GitHub connection yet? Point it at a checkout:

```bash
firedrill run --path ../api
```

Fix what failed, then prove it:

```bash
firedrill verify change/no-solo-ship
```

## What it drills

34 starter drills in ten packs, plus more in the [drill hub](https://github.com/sk1122/firedrill-drills):

| Pack | Examples |
| --- | --- |
| **Change** | Nobody merges and deploys to production alone. History on main can't be rewritten. Actions are pinned to a commit. CI reaches the cloud through OIDC, never a stored key. |
| **Access** | Every admin has MFA enforced. People who left hold nothing in Google Workspace, GCP or GitHub. Every admin is a current person or has a named owner. No admin sits unused for 90 days. No third-party app holds Gmail, Drive or admin access without an owner and a current review. |
| **Agent** | No production credential sits in a file a coding agent can read. Destructive agent commands need approval. Every MCP server points at a known host and runs a pinned package. An agent never works through a human's token or bypass. |
| **Paths** | No one person can both skip review on a repo that deploys to production and delete production data. |
| **Supply** | Every JavaScript project commits its lockfile and CI installs from it unchanged. No dependency quietly gains an install script. |
| **Doors** | No DNS record points at a deleted host. No API docs or source maps are public. Every host has an owner. |
| **GCP** | No public buckets. Only your own domains hold Owner. No service account key is older than 90 days. |
| **Recovery** | Every production database keeps automated backups long enough, with a copy in a different account or project. |
| **Keys** | Every Anthropic and OpenAI API key has an owner and sits under a hard spend limit. |
| **Code** | Your own Semgrep rules report nothing at error level. |

A drill is a short YAML file: the facts it reads, and the conditions that must hold, written in [CEL](https://cel.dev).

```yaml
firedrill: v0
id: change/no-force-push-main
safeguard: "History on main cannot be rewritten or deleted, by anyone."
severity: high
for_each: github.repos
fetch:
  rules: { fact: github.branch_rules, args: { branch: default } }
applies_when: target.protection_available
na_reason: "the plan has no branch protection on private repos"
pass_when:
  - rules.force_push_allowed == false
  - rules.deletion_allowed == false
  - rules.bypass != "allowed"
warn_when:
  - rules.bypass == "unknown"
fix: "Block force pushes and deletion on main, and remove bypass."
maps_to: [SOC2:CC8.1]
```

## Connectors

| System | How it connects | Access |
| --- | --- | --- |
| GitHub | Your `gh` login, or a fine-grained token in CI | Read: Metadata, Administration, Environments, Contents on the repos; Members on the org, for who can reach each repo |
| Google Workspace | A service account with domain-wide delegation | `admin.directory.user.readonly`, `admin.directory.user.security` (GET only) |
| Google Cloud | A keyless reader service account, through gcloud | Viewer, Security Reviewer |
| AWS | Your credential profiles | A read policy `connect aws` prints |
| Anthropic, OpenAI | An admin key in `FIREDRILL_ANTHROPIC_ADMIN_KEY` or `FIREDRILL_OPENAI_ADMIN_KEY` | Admin keys have no read-only scope; the guard sends them only with GET, to the admin read paths it names |
| Repo files | Local checkouts, or tarballs through GitHub | None beyond GitHub's |
| DNS, certificate logs, web | Public DNS, crt.sh, and domains you verify | None |
| HR leavers, Semgrep | A CSV export, a results file | None |

`firedrill connect <system>` prints the exact permissions and setup steps before anything is granted. Step-by-step guides for each system are in [docs/connect](docs/connect/README.md).

Nothing calls GitHub, Google, AWS, Google Cloud, Anthropic or OpenAI until `firedrill connect <system>` has passed its access check and recorded the system under `connected:` in `.firedrill/config.yaml`; credentials already on the machine are never enough on their own. Projects set up before this list existed run `firedrill connect <system>` once per system and commit the change, so CI picks it up.

## How a result works

| Verdict | Meaning |
| --- | --- |
| PASS | Every condition held |
| FAIL | At least one condition failed |
| WARN | A warning matched, or only part of what was needed could be read |
| N/A | The drill doesn't apply here, or had nothing to check |
| SKIP | The drill needs a system that isn't connected |
| ERROR | A fetch failed, or a condition named a field that doesn't exist |

**Only FAIL opens a safeguard, and only PASS closes it.** Every other verdict leaves it where it was, so a failure can't disappear by disconnecting a system.

Exit codes: `0` by default. `1` when an unwaived critical or high safeguard turned open in this run. `2` on any ERROR, which wins over 1. `--fail-on open` also exits 1 while a critical or high safeguard stays open, and `--fail-on any` while any does.

`firedrill report` writes a static HTML board: every open safeguard first, then each pack with its run history. A People page shows what each person can do across GitHub, GCP and Google Workspace, by short hashed ID and never ranked; an Agents page shows what each agent config can reach; and graph pages each draw one question, such as who can reach production data alone. `access/leavers-gone-everywhere` supersedes `access/leavers-locked-out`, and `access/every-admin-is-someone` supersedes `gcp/no-editor-service-accounts`; an existing install keeps its own copies until it removes them.

Each run also compares itself with the previous run and stores the result in `diffs/` next to its snapshot. `firedrill run` ends with a count of what changed; `firedrill diff` shows each change, weakenings first, and the board has a Changes page. Only settings are compared, never timestamps, and a system not read in both runs is left out and named, so an outage never reads as everything removed.

## The drill hub

[sk1122/firedrill-drills](https://github.com/sk1122/firedrill-drills) is a public repo of drills, each with passing, failing and not-applicable test cases.

```bash
firedrill hub search mfa
```

```bash
firedrill hub add access/all-users-use-mfa
```

`hub add` copies the drill into `.firedrill/drills` as a file you review and commit, and records where it came from in `.firedrill/hub.lock`. `hub update` shows each change as a diff and asks first, leaves drills you edited alone, and offers new official drills. Write your own and contribute it back: see the hub's CONTRIBUTING.

## Weekly in CI

Copy [docs/firedrill-workflow.yml](docs/firedrill-workflow.yml) to `.github/workflows/firedrill.yml` in your Firedrill repo, and add two repository secrets:

- `FIREDRILL_GITHUB_TOKEN`: a fine-grained read token for the listed repos, with Metadata, Administration, Environments and Contents.
- `FIREDRILL_SALT`: the value `init` generated. Keep it in your password manager too.

Each Monday it runs the drills, pushes records to the `firedrill-tags` branch, writes a step summary, and opens one issue per newly open safeguard, assigned to its owner. It closes the issue when a run passes. Protect `firedrill-tags` against force pushes and deletion, and require a reviewer on `main`, so changes to drills and waivers get reviewed.

CI sees committed files only, and its results say so. Run on a laptop with `--path` and `--include-home` to also read `.env*` files and user-level agent settings.

## Commands

| Command | What it does |
| --- | --- |
| `firedrill init` | Creates `.firedrill/`, the salt and the starter drills |
| `firedrill connect <system>` | Checks access and prints the exact permissions |
| `firedrill run` | Runs every drill |
| `firedrill verify <drill>` | Reruns one drill and reports whether it closed |
| `firedrill verify-domain <domain>` | Proves you own a domain, so web checks may reach it |
| `firedrill export rulesets` | Run by a repo admin: saves bypass lists for CI |
| `firedrill list` | Every drill with owner, state, last verdict and waiver |
| `firedrill explain <drill>` | What it checks, what it saw and why it failed |
| `firedrill report` | Writes the HTML board, with Changes, People, Agents and graph pages |
| `firedrill diff` | Shows what changed since the previous run |
| `firedrill validate [file or folder]` | Checks drill files |
| `firedrill test [folder]` | Runs each drill's test cases |
| `firedrill hub search`, `add`, `update` | Finds and installs drills from the drill hub |

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

## Safety model

- **Read scopes are the real control.** Every connector asks for read access only, and `connect` prints the permissions first.
- **A guard backs it up.** GitHub, Google and Google Cloud calls may only GET and HEAD, plus a few read calls allowed by exact URL: Google's token exchange, GitHub's tarball redirect, and Google Cloud's `getIamPolicy` on each listed project. AWS calls are checked by action against a fixed list. Anything else stops the run with ERROR.
- **Every call is logged** to `.firedrill/local/calls.jsonl`, with no query strings. `--dry-run` prints the calls and makes none.
- **Secrets are never stored.** A found secret becomes an HMAC keyed by your org's salt. Every record is scanned before it's written, and anything that looks like a secret is replaced with its hash.
- **Records stay private.** In a public repo Firedrill writes no record files and prints only counts, unless you pass `--public-ok`.
- **Drills can't run code.** They're YAML with named facts and CEL conditions with a cost limit.

What it doesn't do yet: AWS checks read policy documents and take no account of Deny statements, permission boundaries or SCPs, so they can overstate access.

## Optional Postgres

Firedrill needs no database. To keep history in Postgres for faster board builds, run a server yourself and set its URL in the environment, never in config:

```bash
export FIREDRILL_DATABASE_URL="postgres://user:pass@localhost:5432/firedrill?sslmode=disable"
```

Snapshots on the records branch stay the source of truth, and the database can always be wiped and rebuilt from them.

## Contributing

Drills are the easiest way in: write one in the [drill hub](https://github.com/sk1122/firedrill-drills). For the tool itself, see [CONTRIBUTING.md](CONTRIBUTING.md). Run `make check` before opening a pull request. The design is in [docs/SPEC.md](docs/SPEC.md).

Found a security problem? See [SECURITY.md](SECURITY.md) and report it privately.

## License

Apache-2.0. Embedded fonts are under the SIL Open Font License; see `internal/report/assets/fonts`.
