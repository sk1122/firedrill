# Firedrill decisions

Every decision below was confirmed before code was written. New decisions found during the build get added here and asked before going further.

"Rec" is Claude's recommendation only. It is not a decision until the Answer column is filled in.

## Already decided in the spec (S2 changed by you, the rest confirmed)

| # | Decision | Spec's answer |
| --- | --- | --- |
| S1 | Language | Go, `CGO_ENABLED=0` |
| S2 | Database | CHANGED by you: local Postgres or a database URL. Details in section E |
| S3 | Model in v0 | None |
| S4 | Conditions language | CEL (`cel-go`) |
| S5 | YAML, Terraform, rate limit libraries | `yaml.v3`, `hashicorp/hcl/v2`, `golang.org/x/time/rate` |
| S6 | API clients | `go-github`, Google Admin SDK, `aws-sdk-go-v2` |
| S7 | Where records live | `firedrill-tags` branch of one private `<org>/firedrill` repo. Reconfirmed by you |
| S8 | Secret storage | HMAC with one org-wide salt; raw values never stored |
| S9 | Certificate logs source | crt.sh |
| S10 | Platforms | macOS, Linux, Windows on arm64 and amd64 |

## A. Project setup

| # | Decision | Options | Rec | Answer |
| --- | --- | --- | --- | --- |
| A1 | GitHub owner (sets module path) | Personal account / an org, and its name | None, yours to pick | Personal account `sk1122`, module `github.com/sk1122/firedrill` |
| A2 | Repo visibility until launch | Private / public | Private | Private |
| A3 | License | Apache-2.0 / MIT / AGPL | Apache-2.0 | Apache-2.0 |
| A4 | Contributor sign-off | DCO / CLA / none | DCO | DCO |
| A5 | Claude's git permissions | Commit, push and open PRs on milestone branches, you merge / ask each time / local commits only | First | Local commits only. You push and open PRs |
| A6 | Review stops | After milestones 1 and 4 / after every milestone / only at the end | After every milestone | Only at the end, but new decisions are still asked when they come up |
| A7 | Spec in the repo | Technical sections only | Technical sections only | Technical sections only |
| A8 | If the name "firedrill" is taken | Decide after the check / pick a backup name now | Decide after the check | Keep "firedrill", no recheck. Checked Nov 2026: free on Homebrew and under sk1122; FourCoreLabs/firedrill exists; AttackIQ mark cancelled |
| A9 | Minimum Go version | 1.25 / 1.24 | 1.25 | Go 1.25 |
| A10 | Project CI | GitHub Actions / other | GitHub Actions | GitHub Actions |
| A11 | Install `gh` with Homebrew | Yes / you install it / no | Yes, you log in | Not now. Ask at milestone 5 |
| A12 | How milestones close with local commits only (the spec says checks pass in CI) | Same checks run locally, CI workflow written and first runs when you push / you push at each milestone | Run locally | Same checks run locally; workflow first runs when you push |
| A13 | This file in git | Committed, business and account notes kept outside the repo | Same | Same |
| A14 | Spec copy in the repo | Update `docs/SPEC.md` from decisions / leave spec / you edit | Update | Update `docs/SPEC.md`; your upload stays unchanged |
| A15 | Local commit layout | One branch per milestone / all on main | Per milestone | One branch per milestone |
| A16 | Check command | `make check` / Go script | `make check` | `make check` |
| A17 | Dev tools | golangci-lint now, GoReleaser at milestone 8 / both now / you install | First | golangci-lint now, GoReleaser at milestone 8 with notice |
| A18 | Commit trailers | Co-Authored-By: Claude / none | None asked | No Co-Authored-By line |
| A19 | DCO Signed-off-by on Claude's commits | Sign off in your name / leave for you to add | Sign off | Sign off in your name |

## B. Libraries and tools the spec does not name

| # | Decision | Options | Rec | Answer |
| --- | --- | --- | --- | --- |
| B1 | CLI framework | Cobra / urfave/cli / standard library `flag` | Cobra | Cobra |
| B2 | `init` questions | Plain stdin prompts / `huh` | Plain prompts | `huh` |
| B3 | Terminal colors | Plain ANSI, off when piped or `NO_COLOR` / `lipgloss` | Plain ANSI | `lipgloss` |
| B4 | Test helpers | Standard `testing` / `testify` | Standard `testing` | Standard `testing` |
| B5 | Linting | `golangci-lint` / `go vet` and `staticcheck` only | `golangci-lint` | `golangci-lint` |
| B6 | Board fonts | Embed in the HTML / system fonts only | Embed, because a static report should make no network calls | Embed in the HTML |
| B7 | Board scripting | No JavaScript / small inline script | Small inline script only if a view needs it | No JavaScript unless a view needs it, and tell you which |
| B8 | Board templates | `html/template` with `go:embed` / a template library | `html/template` | `html/template` with `go:embed` |
| B9 | Release tool | GoReleaser / own script | GoReleaser | GoReleaser |
| B10 | SBOM tool and format | Syft / cyclonedx-gomod | cyclonedx-gomod | cyclonedx-gomod |
| B11 | Sign releases | Checksums only, as the spec says / add cosign | Checksums only for v0 | Checksums only for v0 |
| B12 | Where starter drills live in the tool repo | `packs/`, embedded with `go:embed` / another path | `packs/` | `packs/`, embedded with `go:embed` |

## C. Behavior the spec leaves open

| # | Decision | Options | Rec | Answer |
| --- | --- | --- | --- | --- |
| C1 | Targets for file drills | New `repos` list from config plus `--path` / keep `github.repos` and require GitHub | New `repos` list | New `repos` list from config plus `--path` |
| C2 | Targets for Doors drills | Add `config.domains` / no `for_each`, read all domains | Add `config.domains` | Add `config.domains` |
| C3 | One finding waived, another not | Unwaived FAIL / whole drill waived | Unwaived FAIL | Unwaived FAIL, with the waived finding marked |
| C4 | Destructive commands | List to be reviewed at milestone 1 (`rm -rf`, `git push --force`, `DROP`, `terraform destroy` and so on), config can extend / fixed list | Reviewed list, config can extend | Approved (list below), config can extend |
| C5 | AWS `destructive_actions` | `Delete*`, `Terminate*`, `Drop*`, `Destroy*`, `Purge*`, plus wildcards / curated list of actions | Patterns plus wildcards | `Delete*`, `Terminate*`, `Drop*`, `Destroy*`, `Purge*`, plus wildcards covering them |
| C6 | AWS `is_admin` | `AdministratorAccess` or `*` on `*` / also `iam:*` and privilege escalation paths | First, and `iam:*` | `AdministratorAccess`, `*` on `*`, or `iam:*` |
| C7 | Secret entropy rule | Shannon entropy at least 3.5 and at least 20 characters, tuned on fixtures / borrow gitleaks' thresholds | First | Entropy at least 3.5 and at least 20 characters, tuned on fixtures; report any change |
| C8 | Paths marked prod or staging | Path or file name contains `prod`, `production`, or `staging`, `stage`, config can extend / only exact `.env.production` style names | First | Whole-word match in path for prod/production, staging/stage; config can extend |
| C9 | API doc paths checked | `/swagger.json`, `/swagger-ui/`, `/openapi.json`, `/api-docs`, `/v3/api-docs`, `/config.json`, `/env.js`, reviewed list / shorter list | Reviewed list | Approved (list below) |
| C10 | Which hosts count as production for Doors | All hosts under verified domains unless excluded / only listed in `hosts.yaml` | All, with excludes | All hosts under verified domains unless excluded |
| C11 | Web checks over the 20 request limit | WARN naming what was unchecked / rotate hosts across weeks | WARN | WARN naming what was unchecked |
| C12 | Leaver timing | Active account on or after the leave date is FAIL / allow a grace period | No grace, as your example says "on their last day" | Active after the leave date is FAIL, no grace, compared by UTC date |
| C13 | Future leave dates in the CSV | Ignore until the date / flag | Ignore until the date | Ignore until the date |
| C14 | Dormant admin threshold | 90 days fixed in the drill, editable there / config value | In the drill | 90 days, in the drill file |
| C15 | Admins who never logged in | FAIL / WARN | FAIL | FAIL, unless created within the last 90 days |
| C16 | Which snapshots are "recent" for the estate | Last 12 runs / all under a year | All under a year | All under a year |
| C17 | Call log | JSON Lines in `.firedrill/local/calls.jsonl` and a CI artifact / plain text | JSON Lines | JSON Lines in `.firedrill/local/calls.jsonl` and a CI artifact |
| C18 | Rate limits | Each API's published limit, conservative default / a fixed number | Published limit | Below each published limit, obey retry headers; values listed for you when written |
| C19 | Google admin to impersonate | New `google.admin_email` config field / environment variable | Config field | `google.admin_email` config field |
| C20 | Google key location | Path in `GOOGLE_APPLICATION_CREDENTIALS` / Firedrill's own variable | Standard variable | `GOOGLE_APPLICATION_CREDENTIALS` |
| C21 | Salt format | 32 random bytes as hex, HMAC-SHA-256 / other | As stated | 32 random bytes as hex, HMAC-SHA-256 |
| C22 | Severity of each drill | Proposed with the 19 drills at milestone 1 / set now | Milestone 1 | Claude proposes, you review at the end |
| C23 | YAML for the other 19 drills | Claude drafts, you approve each before `validate` is final / you write them | Claude drafts | Claude drafts, you review at the end |
| C24 | Web request limit: 13 API doc paths use up the 20 requests per drill on two hosts, so most domains would WARN every run | 20 per host per drill with a total cap / keep 20 per drill / configurable | 20 per host, total cap | 20 per host per drill, total cap 500 per drill |

## E. Postgres (from your change to S2)

| # | Decision | Options | Rec | Answer |
| --- | --- | --- | --- | --- |
| E1 | Is Postgres required to run? | Optional, in-memory without it / required always / required in CI only | Optional | Optional; in-memory from snapshots without it |
| E2 | What "local Postgres" means | You run your own and pass a URL / Firedrill starts Docker / embedded download | Your own, URL only | You run it; `FIREDRILL_DATABASE_URL`, environment only, never in config; README shows a Docker command |
| E3 | Source of truth | Snapshots on the branch, Postgres rebuildable / Postgres is the truth | Snapshots | Snapshots on the branch are truth; Postgres is rebuildable, same privacy rules |
| E4 | Driver and migrations | `pgx` with embedded SQL migrations / `pgx` with goose / golang-migrate | `pgx`, embedded SQL | `pgx`, embedded plain SQL migrations with a small runner |
| E5 | Tests needing Postgres | testcontainers (Docker) / local server / both | Decide after checking tools | testcontainers through Docker, test-only |

## N. Made overnight while you slept: please review

You asked me to implement everything while you slept, so I could not ask. Each choice below is the conservative option and easy to change, and it's listed here so none is silent.

| # | Decision | What I chose | Why |
| --- | --- | --- | --- |
| N1 | Reason text for N/A | Optional drill field `na_reason` | The spec's sample N/A messages can't be produced from a CEL condition alone |
| N2 | CEL library path | `cel.dev/cel-go`, not `github.com/google/cel-go` | The project moved. The old path no longer installs |
| N3 | Dependency versions | Held at what Go 1.25 allows (A9), so some are not the newest: testcontainers, `google.golang.org/api`, `golang.org/x/*`, `go-github` v76 | Newer ones need Go 1.26 |
| N4 | Extra fact fields | `days_since_login`, `days_since_created`, `days_since_used`, `unguarded_destructive`, `shared_credentials`, `shared_prod_staging`, `unknown_account`, `inspected` | CEL has no easy date maths or joins here, and 90 days stays in the drill file (C14) |
| N5 | Only the default branch is read | `github.branch_rules` collects `branch: default`. Any other value gives ERROR | All library drills use it. Other branches can come later |
| N6 | Fact interface | Returns a `Result` struct, not the four values in the spec's sketch | It also needs to carry partial reads and the source |
| N7 | Extra flag `run --records <dir>` | Where records live, default `.firedrill/local` | CI needs to point at the checked-out `firedrill-tags` branch |
| N8 | Extra flag `report --summary <file>` | Prints the step summary from a `--json` file | The binary never writes to GitHub, so the workflow pipes it |
| N9 | Verify-domain record | TXT at `_firedrill.<domain>`, value derived from the salt | No stored state, and it matches on every machine holding the salt |
| N10 | DNS CNAME lookups | Direct UDP query with `golang.org/x/net/dns/dnsmessage`, falling back to 1.1.1.1 where there is no resolv.conf, as on Windows | Go's standard lookup fails on a CNAME whose target is gone, which is exactly the case to find |
| N11 | Web redirects | Not followed | A verified host redirecting off-domain would otherwise trip the guard and stop the whole run |
| N12 | Hosts that do not answer | Not counted as a partial read | Old certificates name dead hosts, which would hold drills on WARN forever |
| N13 | HTML catch-all sites | A 200 HTML reply to a doc path is not an exposed file, except the Swagger UI and Redoc pages, which match on content | Single-page apps answer every path with their home page |
| N14 | Terraform files that fail to parse | Skipped, and counted as inspected | A template is not a reason to stop a run. A bucket in one would be missed |
| N15 | Broken agent settings file | ERROR | Treating it as absent would hide what it says |
| N16 | Unknown GitHub plan | Protection assumed available, required reviewers assumed not | Never N/A on a guess, and asks only for fixes every plan has |
| N17 | Workflow permission rule | `read` if top-level is read, or every job declares its own | Matches the spec's "unless a job needs more" |
| N18 | Skipped or removed targets | A target with history stays listed and open, and writes a tag with SKIP or N/A | Spec's rule that a failure cannot disappear |
| N19 | Homebrew packaging | Cask, not formula | GoReleaser deprecated formulas. A cask covers macOS, so Linux users use the binary or `go install` |
| N20 | SBOM scope | Module level, so it lists test-only dependencies such as testcontainers | Overstates rather than misses |
| N21 | Tag file names | Time to the second, moved forward a second on a clash | Keeps two runs in one second ordered |
| N22 | Secret-looking evidence fields left alone | Exempt: `id`, `hash`, `key_id`, `read`, `keys`, `credentials`, and the two shared lists | Spec's structured fields |
| N23 | Local demo preview config | `.claude/launch.json`, excluded from git through `.git/info/exclude` | Only for checking the board |
| N24 | When the estate is built | At `report` and when syncing Postgres, not at the start of each run as the spec's step 1 says | No v0 drill reads history, so a run doesn't need it. Path drills in v0.1 may change this |
| N25 | Where JSON comes from | `run --json <file>` only. `report` writes just the board | Spec lists JSON under both. The result only exists at run time |

## Questions for you

| # | Question | Rec | Answer |
| --- | --- | --- | --- |
| Q1 | Dogfooding on this repo flagged 19 fake keys in Go test files. Add `*_test.*`, `test/` and `tests/` to the `example` paths? Your list has only `testdata/`, `fixtures/`, `__tests__/`, `*.example`, `*.sample`, `*.template` | Yes, and config can still narrow it | OPEN |
| Q2 | Should a laptop-only run with no GitHub connection trust that records stay local, as it does now? They go to a gitignored folder | Yes | OPEN |

## Approved lists (C4 and C9)

**Destructive commands:** `rm -rf`, `git push --force` and `-f`, `git reset --hard`, `git clean -f`, `DROP TABLE`, `DROP DATABASE`, `TRUNCATE`, `terraform destroy`, `kubectl delete`, `helm uninstall`, `aws * delete-*`, `aws s3 rm`.

**API doc and config paths:** `/swagger.json`, `/swagger-ui/`, `/swagger-ui.html`, `/openapi.json`, `/openapi.yaml`, `/api-docs`, `/v2/api-docs`, `/v3/api-docs`, `/redoc`, `/config.json`, `/env.js`, `/env.json`, `/.env`.
