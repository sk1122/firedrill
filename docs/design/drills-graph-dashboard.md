# Firedrill: drills, graph and dashboard

Nov 9, 2026 · @Satyam · revised Nov 11, 2026 after a check against the code

## What Firedrill is

Firedrill reads a company's setup across GitHub, the clouds, Google Workspace, DNS, the public web and its repos, builds one graph of who and what can reach what, and runs drills that check the safeguards still hold. Every result is kept in a hash chain, so a broken safeguard can't quietly disappear. Signing each result is planned (see Build order, step 4).

It is read-only. It never holds a credential it finds, never writes to a system, and never sits in the path of anything a company or its agents do.

It is not a findings feed. A drill names one safeguard, says PASS or FAIL with the evidence, and says what to change. The graph exists to answer questions no single console can: who alone can get from code to production data, which key an agent can read and what that key can delete, which leaver still holds something somewhere.

## The incidents that set the catalog

Most drills below trace to something that happened in 2026, where the failure was a setup fact visible from outside before the incident. Four drills trace to a recurring audit finding instead, and say so.

| When | Incident | What a drill would have seen |
| --- | --- | --- |
| Nov 2026 | [Claude Code "don't ask again" leak](https://thehackernews.com/2026/11/claude-codes-dont-ask-again-file.html): 1,122 public copies of `.claude/settings.local.json` holding a secret; 2,539 secrets in 1,994 repos once `settings.json`, older versions and chat logs are counted | Secrets in `.claude/settings.local.json`, file not gitignored |
| Aug 2026 | [Karakun](https://dev.karakun.com/2026/08/28/coding-agent-pushed-deletion-to-main.html): an agent pushed a commit deleting 723 files to main in one repo and 151 in another; two weeks later, a separate force-push | Unprotected main; the agent used the human's credentials |
| Aug 2026 | [Mini Shai-Hulud via keyv](https://labs.cloudsecurityalliance.org/research/csa-research-note-supply-chain-single-points-of-failure-2026/): 400+ npm packages in about 24 hours | Installs not held to the lockfile, long-lived cloud keys and npm tokens on dev machines and CI; persistence in `.claude` and `.vscode` |
| Jul 2026 | [Adform](https://labs.cloudsecurityalliance.org/research/csa-research-note-supply-chain-single-points-of-failure-2026/): one CDN script swapped; Adform has about 1,800 advertisers and hasn't said how many sites served it | Third-party script with no integrity hash |
| Jul 2026 | [UK AISI](https://www.lumenova.ai/blog/agentic-ai-security-incidents/): agents acted on the live internet out of scope (secondary source) | No egress boundary outside the agent |
| Apr 2026 | [PocketOS](https://www.fastcompany.com/91533544/cursor-claude-ai-agent-deleted-software-company-pocket-os-database-jer-crane): prod DB and backups deleted in 9 seconds | A destructive API token in a file the agent could read; backups in the same volume |
| Apr 2026 | [Vercel via Context.ai](https://www.lumenova.ai/blog/agentic-ai-security-incidents/): breached through an OAuth grant (secondary source) | Third-party app with Google account access, unreviewed |
| 2026 | [$6,000 overnight /loop](https://x.com/om_patel5/status/2050433423970300156): 46 runs on Opus, unattended | Provider key with no spend cap and no owner |
| Oct 2026 | [MCP SDK CVE](https://dev.to/devomnitools/fixing-the-mcp-bearer-auth-flaw-cve-2026-111771-why-cross-service-tokens-were-accepted-1944): bearer middleware didn't check the token audience, so tokens issued for other services were accepted | Unknown, unpinned MCP servers in agent configs |
| Apr 2026 | [Claude Code GitHub Action PR-title attack](https://www.orcarouter.ai/blog/2026-04-01-claude-code-github-action): a PR title reached the prompt and exposed the workflow's secrets | `pull_request_target` handing secrets to a run an outsider can steer |
| Oct 2026 | Manchester Airports, 8.7M records (source needed) | A live key in page JavaScript |
| Oct 2026 | Binance, $6.3B (source needed) | One laptop could reach the money |

Not yet checked against a source: the PocketOS and $6,000 loop pages wouldn't load, and the Manchester Airports and Binance rows have no link.

## Drill catalog

16 new drills in three tiers: 8 on existing connectors, 4 cross-system drills that read `people.powers`, and 4 that need new connectors. Effort: S is a day on a fact we have, M is a few days for a new fact or field on an existing connector, L is a week or more for a new connector or a cross-system join.

### Tier 1: incident-proven, on existing connectors

| Drill | Safeguard | Proven by | Facts | Effort |
| --- | --- | --- | --- | --- |
| `change/no-pr-target-with-secrets` | A workflow an outside pull request can trigger never runs with secrets or more than a read-only token | PR-title attack | `files.workflows` with new `triggers` and `secrets` fields | S |
| `agent/no-secrets-in-agent-config` | No secret in any `.claude/`, `.cursor/`, `.gemini/` or `.mcp.json` file, and those paths are gitignored | Claude Code leak | `files.secrets` extended to all agent dirs (`.gemini/` isn't read today), plus a new gitignored flag per file | M |
| `agent/mcp-servers-known` | Every MCP server in an agent config points at an owned or allowlisted host, and any package it runs is pinned to an exact version | MCP CVE | `files.agent_configs.mcp_servers` extended with `transport`, `host`, `host_known`, `command`, `package`, `version`, `pinned` and `package_known`; owned means a verified domain, `hosts.yaml` or `agents.mcp_hosts`, and `agents.mcp_packages` allows packages | M |
| `supply/installs-from-lockfile` | Every JavaScript project (npm, pnpm, yarn or bun) commits its lockfile and CI installs from it without changing it; no dependency gained an install script since the last run | Shai-Hulud | new `files.manifests`, whose `new_install_scripts` the run works out against the previous snapshot; `files.workflows` with new `unfrozen_installs` | M |
| `change/ci-uses-oidc-not-keys` | CI reaches the cloud through short-lived OIDC credentials, never a long-lived cloud key stored as a secret | Shai-Hulud harvest | `files.workflows` with new `cloud_key_secrets` and `uses_oidc`; `aws.principals` gains `github_oidc` and `github_oidc_unscoped` from the trust policy, not yet judged by any drill | M |
| `keys/ai-keys-capped` | Every Anthropic and OpenAI key sits under a hard spend limit and has a named owner | $6,000 loop | new Anthropic and OpenAI admin connectors, GET only on named paths; `anthropic.keys`, `openai.keys`, and `keys.ai`, which needs either provider. OpenAI's org and project hard limits are read; Anthropic shows none, so its limits come from `ai-keys.yaml` and read as WARN until declared | M |
| `access/third-party-apps-reviewed` | No third-party OAuth app holds Gmail, Drive or admin scopes without an owner and a review date | Vercel | new `identity.oauth_apps` on the Google connector, from `tokens.list` per user with the extra `admin.directory.user.security` scope; owner and review date come from `apps.yaml` | M |
| `recovery/backups-separate-and-retained` | Production databases have automated backups with retention, copied to a different account or project | PocketOS | new `aws.backups` (RDS, plus AWS Backup copy jobs to another account), `gcp.backups` (Cloud SQL; a copy in another project is never visible, so unknown unless declared in `backups.yaml`), and `recovery.databases`, which needs either cloud; production named by one `production` list in config | M |

Two things to settle before building:

- **`keys/ai-keys-capped`**: settled from the documentation. OpenAI's Administration API reads a hard spend limit on the organization (`GET /v1/organization/spend_limit`) and on each project (`GET /v1/organization/projects/{id}/spend_limit`), not per key, so a key is capped when its project or the organization is. Anthropic's Admin API lists keys and workspaces but shows no spend limit for a Claude Console organization, workspace or key (its Spend Limits API covers Claude Enterprise members only), so Anthropic limits are declared in `ai-keys.yaml` and read as WARN until they are. Neither provider offers a read-only admin key, so Firedrill holds its most privileged credential here; the guard limits each to GET on the exact admin read paths used.
- **PocketOS is already covered.** The existing `agent/no-destructive-tokens` and `agent/no-prod-secrets-in-agent-reach` are the PocketOS drills. No new drill is added for it. See Example drills.

### Tier 2: cross-system, the ones no console shows

All four read `people.powers`: it walks `same_person` from each person to every account they hold and sums what those accounts can do. That fact has prerequisites of its own, listed under The graph. Effort below is for the drill once `people.powers` exists.

| Drill | Safeguard | Proven by | Effort |
| --- | --- | --- | --- |
| `paths/no-single-person-code-to-prod-data` | Nobody can bypass review on a repo that deploys to production and also destroy data in a production GCP project. Built; AWS production accounts not built (out of scope for now) | Binance | L |
| `access/leavers-gone-everywhere` | A leaver holds nothing in Google Workspace, GCP or GitHub. Built; AWS not built (out of scope for now) | Recurring audit finding | M |
| `access/every-admin-is-someone` | Every admin principal in GitHub, GCP and Google Workspace maps to a current person or a named owner. Built; AWS not built (out of scope for now) | Recurring audit finding | M |
| `agent/agent-has-own-identity` | No personal GitHub token (`ghp_`, `github_pat_`, `gho_`, `ghu_`) in a file an agent reads, and no human can bypass review on a repo with an agent config. Built from repo files and bypass actors, with no new call | Karakun | L |

### Tier 3: needs new connectors

| Drill | Safeguard | Proven by | Effort |
| --- | --- | --- | --- |
| `doors/no-live-key-in-public-bundle` | No key ID in a public JavaScript bundle matches a key in the cloud inventory | Manchester Airports | L |
| `doors/third-party-scripts-pinned` | External scripts on owned hosts carry an integrity hash or come from an owned domain | Adform | L |
| `agent/egress-allowlisted` | Agent configs and sandboxes restrict outbound hosts to an allowlist | UK AISI | M for config, L for runtime |
| `recovery/restore-exercised` | A restore of each production database succeeded in the last 90 days | Recurring audit finding | L |

Notes:

- **`no-live-key-in-public-bundle`** never tests a key. It matches the key ID against keys Firedrill has already read from the cloud. A secret with no readable ID (a Stripe key, say) shows as WARN.
- **`restore-exercised`** has no API that reports a successful restore. Evidence is either a restore event in the cloud audit log or a dated record the team commits, which is declared evidence.

## Example drills

Four drills in the format the engine runs. All four ship.

PocketOS, as the drill that already ships (`packs/agent/no-destructive-tokens.drill.yaml`):

```yaml
firedrill: v0
id: agent/no-destructive-tokens
safeguard: "AWS keys within an agent's reach cannot delete or run as admin."
severity: critical
fetch:
  keys: { fact: aws.agent_keys }
applies_when: keys.size() > 0
na_reason: "no AWS access key was found in an agent-readable file"
pass_when:
  - keys.filter(k, k.is_admin || k.destructive_actions.size() > 0).size() == 0
warn_when:
  - keys.exists(k, k.unknown_account)
fix: "Rotate the key, remove it from the file, and give the agent a role limited to read actions."
```

It has no `for_each`, because `aws.agent_keys` covers every repo at once. It only sees AWS keys. A token for any other provider in an agent-readable file is caught by `agent/no-prod-secrets-in-agent-reach`, which can't say what the token can delete.

The PR-title attack, as the drill that now ships (`packs/change/no-pr-target-with-secrets.drill.yaml`). It reads the `triggers` and `secrets` fields on `files.workflows`; `secrets` holds the names of the secrets a workflow references, never their values, and `inherit` when a job passes every secret on:

```yaml
firedrill: v0
id: change/no-pr-target-with-secrets
safeguard: "A workflow an outside pull request can trigger never runs with secrets or more than a read-only token."
severity: high
for_each: repos
fetch:
  workflows: { fact: files.workflows }
pass_when:
  - >-
    workflows.found.filter(w, "pull_request_target" in w.triggers
    && (w.permissions != "read" || w.secrets.size() > 0)).size() == 0
fix: "Use pull_request, not pull_request_target. If the trigger must stay, declare read-only permissions and pass no secrets to it."
maps_to: [SOC2:CC8.1]
```

It checks one thing. Bot approval, the production gate and bypass stay with `change/no-solo-ship` and `change/prod-deploy-gated`, so one misconfiguration gives one FAIL.

Binance, as the drill that now ships (`packs/paths/no-single-person-code-to-prod-data.drill.yaml`). It reads `people.powers` and the top-level `production` list, which names GCP projects; AWS production accounts and AWS power are not built (out of scope for now):

```yaml
firedrill: v0
id: paths/no-single-person-code-to-prod-data
safeguard: "No one person can bypass review on a repo that deploys to production and also destroy production data."
severity: critical
for_each: github.repos
fetch:
  env:      { fact: github.environment, args: { name: production } }
  rules:    { fact: github.branch_rules, args: { branch: default } }
  projects: { fact: gcp.projects }
  people:   { fact: people.powers }
applies_when: env.exists && projects.size() > 0
na_reason: "the repo has no production environment in GitHub, or no GCP project was read to hold production data"
pass_when:
  - people.found.filter(p, target.name in p.github_bypass && p.prod_destructive.size() > 0).size() == 0
warn_when:
  - "!rules.bypass_actors_known"
  - target.name in people.unlinked.bypass_repos
  - people.found.exists(p, target.name in p.github_bypass && !p.gcp_power_known)
fix: "Remove this person's bypass on the default branch, or move their production role that can delete data to one that needs a second person to grant, such as a just-in-time grant with approval. List production projects under production in config.yaml so only they count."
```

`prod_destructive` lists projects where the person holds a role that can delete data, in production projects only. Counting any delete permission anywhere would fail nearly everyone at a small company. When nothing is named production every project counts, and `production_basis` says so. Fetching `gcp.projects` makes the drill wait (SKIP) until GCP is connected, so a GitHub-only install never reads "no cloud power" as good news. An unlinked GitHub account that can bypass, or a bypassing person whose GCP power is unknown, gives WARN.

Leavers, everywhere, as the drill that now ships (`packs/access/leavers-gone-everywhere.drill.yaml`). AWS keys are not built (out of scope for now):

```yaml
firedrill: v0
id: access/leavers-gone-everywhere
safeguard: "People who left hold no account, role or repo access in Google Workspace, GCP or GitHub."
severity: critical
fetch:
  leavers: { fact: hr.leavers }
  people:  { fact: people.powers }
applies_when: leavers.size() > 0 && people.systems_read.size() > 0
na_reason: "no leave dates have passed in the HR file"
pass_when:
  - >-
    people.found.filter(p, leavers.exists(l, l.id == p.id)
    && (p.google_active || p.gcp_roles.size() > 0 || p.github_repos.size() > 0
    || p.github_org_role in ["admin", "member"])).size() == 0
warn_when:
  - people.unlinked.github > 0
fix: "Suspend the leaver's Google account, remove their GCP roles and group memberships, and remove them from the GitHub org and every repo, then rerun. Map every GitHub login in people.yaml, so no leaver hides behind an unlinked account."
```

People are matched by `id`, the hashed person ID that `hr.leavers` now carries, never by email, so no address reaches a verdict's evidence. `google_active` is false for a person with no Google account, so a missing account never reads as an active one. The drill judges whichever systems were read and records them; a system read only in part, or a GitHub login that maps to nobody, gives WARN.

Each drill ships with a `.test.yaml` holding at least one PASS case and one FAIL case built from the incident it names.

## The graph

The graph is one store of every person, agent, credential and production system Firedrill has read, with typed edges between them. Drills query it; the diff compares two copies of it; the graph view draws a slice of it.

&#91;embedded content: the graph · four zones, read left to right\]

Every worry in this doc is a path that runs left to right through these four zones in few hops. The Binance laptop is person, then credential, then production. PocketOS is agent config, then secret, then a key with delete rights.

### Edges

| Edge | From → to | Written by | Today |
| --- | --- | --- | --- |
| `same_person` | person → each account they hold | link step, by email | Google users (and aliases), GCP bindings naming a user, and GitHub users through `people.yaml`; GCP roles held through a Google group are `via_group` edges. AWS: not built |
| `holds` | AWS principal → access key | AWS connector | Yes, IAM users |
| `found_in` | secret fingerprint → file it was seen in | files connector | Yes |
| `owns` | GCP project → its resources; config host → host | GCP connector, config | Yes |
| `points_to` | host → CNAME target | DNS connector | Yes |
| `deploys_to` | repo → environment | GitHub connector | Yes |
| `admin_of`, `member_of` | account → org or group | GitHub, Google | GitHub: yes, users to the org and teams, and `admin_of` from users and teams to repos. Google: not yet |
| `writes_to` | GitHub user or team → repo | GitHub connector | Yes, push or maintain permission |
| `can_bypass` | GitHub user, app or deploy key → repo | GitHub connector | Yes, teams and roles expanded to users |

### New facts this needs

**`people.powers`**: built. One row per person, summing what every account they hold can do, from the same rows as `people.accounts`: GitHub org role, repos with write or admin, and repos whose review they can bypass; GCP roles, admin and delete-capable projects, the production subset, and whether that power is known; Google presence, whether the account is active, and admin. AWS destructive actions and active keys: not built (out of scope for now). The four Tier 2 drills read it, or `people.admins`. Its prerequisites:

- **GitHub people.** Built. The GitHub connector's people collection reads org members by role, outside collaborators, teams with their members, and each repo's collaborators and teams, and writes `member_of`, `admin_of` and `writes_to`. The login stays out of snapshots; `github.people` gives one row per human.
- **Bypass actors.** Built. Branch rules keep bypass as allowed, none or unknown, and add `bypass_actors_known` and the resolved list; `github.bypass_actors` lists the people, teams and apps per repo, and each writes a `can_bypass` edge. Classic protection's allowances and `enforce_admins` are read by any token with Administration: read. Ruleset bypass lists come from the API, or from the existing admin export, which already carried each ruleset's actor list as GitHub returns it (type, ID, mode) and needed no change. Unreadable, the list is unknown, never empty.
- **AWS people.** Not built (out of scope for now, by the owner's decision). The AWS connector reads IAM users and roles. People who sign in through IAM Identity Center are invisible; reading them means new actions on the AWS allowlist.
- **Principal linking.** Built for Google, GCP and GitHub: the link step joins Google users by email and alias, GCP `user:` members by email, GitHub users through `people.yaml`, and GCP `group:` members through the group's members, which a new Google collection reads for bound groups only (`admin.directory.group.readonly`, nested groups included). `.firedrill/owners.yaml` owns service accounts, apps and deploy keys. `people.accounts`, `people.unlinked` and `people.admins` expose it. AWS principal linking (by tag or owners file): not built (out of scope for now).
- **Production accounts.** Built for GCP: the top-level `production` list marks each project and binding, and a GCP custom role is read with `roles.get` so its power is known. AWS accounts in the same list already mark AWS databases; AWS principal power by production account: not built (out of scope for now).

**`identity.oauth_apps`**, **`files.manifests`**, **`aws.backups`**, **`gcp.backups`**, **provider admin keys**: one each for the Tier 1 drills.

**Previous-snapshot facts**: a fact can read only the current run's graph. "No new install scripts since the last run" needs a fact that can also read the last snapshot.

### Patterns to spot

Drills catch what someone thought to ask. These shapes catch what nobody did. Each is cheap to compute and is shown on Home when it appears.

| Pattern | How to compute it | What it means |
| --- | --- | --- |
| Fan-in | Nodes sorted by incoming `found_in` or `points_to` edges | One secret in five repos, or one CNAME target behind twenty hosts: one change hits everything |
| Cut-point person | Remove each person and check whether code still reaches production with a second human in the path | That person is a single point of failure |
| Short path from outside | Paths of three hops or fewer from the Outside zone to the Production zone | Exposure, whatever the drills say |
| Orphaned power | Keys, principals and hosts with power and no `same_person` or `owns` edge | Nobody owns it, so nobody notices it change |
| Dormant power | High privilege and long unused | A key whose owner won't notice it's gone |
| New edge | Present in this snapshot, absent in the last | Every weakening starts here; see the snapshot diff |

Fan-in, dormant power and new edge work on today's graph. Cut-point person and orphaned power are built from `people.powers`, `people.admins` and `people.unlinked`, and shown on the People and Graph screens: a cut point is a person who can bypass review on a repo that deploys to production, or the only person with admin over a GCP project, the GitHub org or Workspace; orphaned power is an admin or delete-capable principal with no person and no owner.

## Snapshot diff

Every weakening of a company's setup shows up as a new or changed edge in the graph. Listing what appeared since the last run catches the weakenings no drill was written for. It's the first thing anyone should read after a run, and it needs no drill. Every run already writes a full snapshot, so the diff compares two files that exist.

What it reports, newest first:

| Change | Edge or attribute | Why it matters | Data today |
| --- | --- | --- | --- |
| New admin | `is_admin` turned true | Power grew | Yes |
| New key held | `holds` from a principal to a key | A credential exists that didn't | Yes |
| Secret seen in a new place | `found_in` | A secret spread | Yes |
| Bypass turned on | branch rule `bypass` changed to allowed | Review can be skipped | Yes; each new actor is also its own "new bypass actor" row, from a new `can_bypass` edge |
| New deploy path | `deploys_to` | Code reaches production another way | Yes |
| New MCP server | `agent_config.mcp_servers` | An agent talks to something new | By name; host needs the parser change |
| New public thing | bucket public grant, host resolving, source map served | Exposure grew | Yes |
| New OAuth grant | `identity.oauth_apps` scope added | An outside app reached in | Needs the fact |
| New dependency | `files.manifests` direct dependency added | Something new is trusted | Needs the fact |
| Gone | any edge removed | Usually good; worth a glance when a backup or a protection disappears | Yes |

Rules:

- **Only stable attributes are compared.** The diff reads a fixed list of attributes per node kind. Timestamps such as `last_used`, `last_login` and `seen_at` are left out, or every run reports a change.
- **Only what both runs read is compared.** A connector that failed or wasn't connected in either run is skipped and named, so an outage never reads as everything removed and then added.
- **Only runs of the same stream are compared.** A laptop run reads home-directory files and local environment that CI never sees.
- **A secret is identified by fingerprint and file, not line.** Today the occurrence ID includes the line number, so an edit above a secret would read as one gone and one new.
- A diff entry names the window between the two snapshots. Naming the actor is planned: it needs audit sources (GitHub audit log, which is Enterprise only; CloudTrail; Google Admin reports), each a new read on the allowlist.
- Entries are grouped by person when `same_person` links them, so one person's new admin, new key and new bypass read as one story. Until principal linking exists this covers Google accounts only.
- A diff entry that a drill also catches links to that drill's verdict instead of repeating it.
- The diff is stored with the snapshot and covered by the run's hash chain, so "what changed last Tuesday" can be answered months later.

## Dashboard

The dashboard answers three questions in order: what broke, what changed, and who can do what. It's read after a run, usually weekly, and on a PR when a drill fails. It is not a place to live. It is a static site built from the records, as the report is today.

### Screens

| Screen | Answers | What's on it |
| --- | --- | --- |
| Home | What needs me this week? | Open FAILs by severity, the snapshot diff since last run, any pattern that appeared, drills that couldn't run and why. Nothing else. |
| Drills | Which safeguards hold? | Every drill with its state (OPEN, CLOSED, UNKNOWN, RETIRED), last verdict per target, days open, linked incident. Filter by tier, system, severity. |
| Drill | Why is this one failing? | The safeguard sentence, each failing target, the evidence rows with their source and evidence tier, the fix, the history of verdicts as a strip, and the waiver if any. |
| Changes | What changed since last run? | The snapshot diff, grouped by person, newest first, each entry linked to the drill it broke if any. |
| People | Who can do what, everywhere? | One row per person from `people.powers`: GitHub repos and bypass, GCP power, Google admin, leaver status, and a link to what they can do. Sorted by short hashed ID, since names are not stored; filter by system with plain links. Below: cut points, power nobody owns, and accounts no person answers for. AWS power and keys held: not built. |
| Agents | What can each agent reach? | One row per agent config: tool, repo, file, MCP servers, secrets readable by fingerprint, unguarded destructive commands, and whether people can bypass review on the repo. The keys behind those secrets and what they can delete: not built. |
| Graph | How does it connect? | The graph view, opened on a question, never on the whole graph. Built as static pages: who can reach production data alone, what one person can do, what one agent config can touch, and what changed. Not built: what is reachable from outside, what one secret opens. |
| Report | What do I hand an auditor? | The export: drills, verdicts, evidence and a coverage manifest of what was and wasn't read. |

### How it behaves

- **Opens on Home, and Home can be empty.** A week with no new FAIL and no diff shows one line: "Nothing broke, nothing changed". That's the best possible screen.
- **Every number is a link to its rows.** "3 open" opens those 3. No number without its evidence one click away.
- **Evidence shows its tier.** Declared (read from a config file), inferred (worked out from naming or heuristics) and verified (read from a live API) are visually distinct. A FAIL resting only on inferred evidence shows as WARN. All three tiers are recorded in each tag, but no shipped fact field is marked inferred yet.
- **Secrets are never shown.** A secret appears as its HMAC fingerprint and the places it was seen. No screen can reveal a value because no value is stored.
- **People are shown by short ID.** Emails are hashed and never reach a snapshot, so a person appears as a short ID. Showing names is an open question (see Build order).
- **No per-person score.** People and Changes show what a person can do or changed, never a total or a ranking. Weakenings are things to vouch for, not blame.
- **A failing drill offers three actions only:** open the fix, copy a waiver entry with an owner and an expiry to add to the config by pull request, or open the evidence in the source system. The dashboard writes nothing, to a source system or to the repo.
- **It works on a phone.** Home and Drill are readable at 390 px wide; Graph and People scroll inside a box.

### The graph view

The whole graph is never drawn: past a few hundred nodes it's a hairball nobody reads. The view always opens on a question, and draws only the subgraph that answers it.

| Question | Starts from | Draws |
| --- | --- | --- |
| Who can reach production data alone? | The production environment and data stores | Every person path that reaches them, cut points highlighted |
| What can this person do? | One person | Their accounts, and what each account can reach |
| What can this agent touch? | One agent config | Secrets it can read, the keys behind them, what those keys can do |
| What's reachable from outside? | Public buckets, hosts, source maps, outside OAuth apps | Paths of three hops or fewer to production |
| What does this secret open? | One secret fingerprint | Every place it was seen and every system that accepts it |
| What changed? | The snapshot diff | New edges in an accent colour over the old ones in grey |

Nodes are coloured by system (GitHub, AWS, GCP, Google, web, files). Edges carry their kind as a label on hover. A node with a failing drill carries the drill's severity as a ring. Clicking a node opens its row in People, Agents or Drill. Layout is left to right: outside on the left, people and agents in the middle, production on the right.

## Behaviour rules

These hold for every drill, every connector and every screen. A change that breaks one is a bug. A rule marked planned isn't enforced by the code yet and has a place in the build order.

### Verdicts

| Verdict | Meaning |
| --- | --- |
| PASS | The safeguard holds for this target, on evidence read this run |
| FAIL | It doesn't, and the evidence says so |
| WARN | Something is wrong but the evidence is partial or only inferred |
| N/A | The safeguard doesn't apply here, with the reason |
| SKIP | The system it needs isn't connected |
| ERROR | The system was connected and couldn't be read |

A permission error is never read as a PASS. A 403 from GitHub on bypass settings is ERROR or WARN, never "no bypass". Missing evidence is never good news.

### Read-only

- Every outbound call is checked against an allowlist: GET and HEAD, plus exact POST URLs that only read (GCP `getIamPolicy`, token exchange). Anything else is refused before it leaves.
- No network call before the user has connected that system on purpose.
- A secret found in a file is hashed with the company's salt and the value dropped. It's never used, logged or shown.

### State and history

- Every verdict is a hash-chained tag on the `firedrill-tags` branch. A FAIL can't disappear by disconnecting a system or removing a target: the last known verdict carries forward until the drill runs again.
- The chain catches edits and missing tags. It can't stop someone who can rewrite the branch; that comes from branch protection and, planned, an attestation on every CI tag.
- A drill's state is OPEN after a FAIL and CLOSED after a PASS. Any other verdict leaves the state where it was, shown as unverified. It is UNKNOWN only when it has never passed or failed, and RETIRED when removed on purpose.

### Noise

- Drills check existence and membership, which don't flap. Thresholds (dormant days, retention days, key age) live in the pack, not in drill code, so one change fixes every install.
- A new drill runs in shadow for two weeks: it reports, but it doesn't fail a PR.
- A drill that has fired with no fix and no waiver for 30 days gets flagged for review. Either the safeguard is wrong or nobody owns it.

### Waivers

- A waiver names the drill, the target, the reason, the person who approved it and an expiry. No expiry, no waiver.
- A waived FAIL shows as waived, not as PASS, and returns to FAIL the day the waiver expires.

### Where it runs

| Mode | Trigger | Fails what |
| --- | --- | --- |
| Local | `firedrill run` on a laptop | Nothing; prints |
| PR | GitHub Action on every pull request | The PR, for drills scoped to that repo |
| Weekly | Scheduled Action on the org | Nothing; opens or updates one issue with the diff and open FAILs |

## The existing 24 drills

19 stay as they are, 3 get replaced by broader versions, and 2 are retired.

| Drill | Decision | Why |
| --- | --- | --- |
| `change/human-review-required` | Keep | Core, Karakun |
| `change/no-solo-ship` | Keep | Core, Binance shape inside one repo |
| `change/no-force-push-main` | Keep | Karakun's later force-push |
| `change/prod-deploy-gated` | Keep |  |
| `change/workflow-tokens-read-only` | Keep | `no-pr-target-with-secrets` adds the trigger check beside it |
| `change/actions-pinned` | Keep | Supply chain |
| `agent/destructive-commands-gated` | Keep |  |
| `agent/no-destructive-tokens` | Keep | The PocketOS drill for AWS keys |
| `agent/no-shared-agent-keys` | Keep |  |
| `agent/no-prod-secrets-in-agent-reach` | Keep | The PocketOS drill for every other token |
| `access/admins-use-mfa` | Keep |  |
| `access/no-dormant-admins` | Keep |  |
| `access/no-shared-prod-keys` | Keep |  |
| `doors/no-public-source-maps` | Keep | Feeds `no-live-key-in-public-bundle` |
| `doors/every-host-owned` | Keep |  |
| `doors/no-public-buckets-in-terraform` | Keep |  |
| `doors/no-dangling-dns` | Keep | Subdomain takeover |
| `gcp/no-public-buckets` | Keep |  |
| `gcp/no-outside-owners` | Keep |  |
| `access/leavers-locked-out` | Replace (done) | By `access/leavers-gone-everywhere`, removed from the packs in step 8 |
| `gcp/sa-keys-short-lived` | Replace | Folded into `change/ci-uses-oidc-not-keys` plus a key-age check in the pack |
| `gcp/no-editor-service-accounts` | Replace (done) | Folded into `access/every-admin-is-someone`, removed from the packs in step 8 |
| `doors/no-public-api-docs` | Retire | Public API docs are a choice, not a weakness |
| `code/rules-clean` | Retire | A lint, not a safeguard; Semgrep results stay available as a fact |

## Build order

Trust first, then the cheap incident-proven drills, then the diff, then the rules the doc promises, then the cross-system work. Each step is done when the condition next to it holds.

1. **Fix the seven known bugs.** Done when the record scanner can't emit a secret value, a GitHub 403 reads as ERROR, waivers don't flap, Postgres writes are gone from the read path, no call leaves before consent, CI pins its install, and test paths aren't marked as examples. Five are confirmed in the code as of Nov 11; waiver flapping and the consent bug weren't rechecked.
2. **Tier 1, first two drills:** `no-pr-target-with-secrets`, then `no-secrets-in-agent-config`. Done when each has a PASS and a FAIL fixture built from its incident, and runs green on our own repos or fails for a real reason. Both are built, with fixtures from their incidents.
3. **Snapshot diff** on the CLI and the Changes screen, with the four noise rules, and previous-snapshot facts. Done when two runs a week apart produce a diff you'd actually read, and a run with a failed connector reports no false removals. Built: `graph.Diff` with the four noise rules (a fixed attribute list per node kind; coverage recorded in each snapshot and worked out for older ones, per repo, project and domain; runs compared only within one stream; secret occurrences keyed by fingerprint and file), `firedrill diff`, the count after `firedrill run`, `diffs/<time>.json` with the SHA-256 of both snapshots, links to drills that also caught a change, grouping by person, the Changes page, and `Args.Previous` for facts. Not built: naming the actor from audit logs, the weekly issue, covering the diff by the hash chain or an attestation, and any fact that reads `Args.Previous`.
4. **The planned rules:** shadow mode for new drills, the 30-day review flag, evidence tiers with the inferred-means-WARN rule, and an attestation on every CI tag. Done when each rule in Behaviour rules loses its "planned" mark. Built: shadow mode (`shadow_days`, default 14), the review flag (`review_after_days`, default 30), and evidence tiers recorded per fact in each tag with the inferred-means-WARN rule, though no shipped fact field is marked inferred yet. Not built: the attestation on every CI tag.
5. **Tier 1, the rest**, starting with `mcp-servers-known`, then the Anthropic and OpenAI admin connectors for `keys/ai-keys-capped`, then OAuth apps, manifests, OIDC and backups. Done per drill as in step 2. Built: `agent/mcp-servers-known`, `supply/installs-from-lockfile` and `change/ci-uses-oidc-not-keys`, each with fixtures from its incident, reading repo files only. Also built: `keys/ai-keys-capped`, `access/third-party-apps-reviewed` and `recovery/backups-separate-and-retained`, with their new read calls on the allowlist and fixtures from their incidents. All Tier 1 drills are built. Each new connector call was checked only against the providers' documentation and fake servers; live verification against real Google Workspace, AWS, Google Cloud, Anthropic and OpenAI accounts is still needed.
6. **GitHub people:** org members, collaborators, teams and bypass actors, writing `member_of` and `admin_of`. Done when the graph shows who can bypass review on each repo. Built: the people collection, `writes_to` and `can_bypass` edges, `github.people`, `github.bypass_actors` and `bypass_actors_known` on `github.branch_rules`, with diff rows for new admins, new bypass actors and outside collaborators with write. Verified against fake servers only, not a live org.
7. **Principal linking:** AWS and GCP principals joined to a person, AWS Identity Center read, production accounts named in config. Done when every admin principal either links to a person or shows as unowned. Built for Google, GCP and GitHub: the link step with `same_person`, `via_group` and `bound_to` edges, the Google groups collection, GCP role classification with custom roles read by `roles.get`, `production` on GCP projects and bindings, `owners.yaml`, and `people.accounts`, `people.unlinked` and `people.admins`, with a run-level test of the done condition over a mixed estate; diff rows for new GCP power through a link or a group, group members outside the domain and a principal losing its owner. Verified against Google's documentation and fake servers only. Not built (out of scope for now, by the owner's decision): AWS IAM Identity Center, AWS principal linking, AWS tags to a person.
8. **`people.powers`**, then the four Tier 2 drills, then the People and Graph screens. Done when one person's power across GitHub, AWS, GCP and Google shows on one row. Built for GitHub, GCP and Google Workspace: `people.powers`, `id` on `hr.leavers`, `members_known` and `departed` on `people.admins`, GitHub token kinds for fine-grained, OAuth and user-to-server tokens, and the four Tier 2 drills (`paths/no-single-person-code-to-prod-data`, `access/leavers-gone-everywhere`, `access/every-admin-is-someone`, `agent/agent-has-own-identity`), each with fixtures from its incident or audit finding and a run-level test over a mixed estate that no address, login or token reaches a tag, snapshot or diff. They replace `access/leavers-locked-out` and `gcp/no-editor-service-accounts`. Also built: the cut-point person and orphaned power patterns, a subgraph extractor, and the People, Agents and graph pages (production, per person, per agent config, what changed) as server-side SVG. Verified against fakes only. Not built: AWS power in `people.powers` (out of scope for now, by the owner's decision), the graph pages for what is reachable from outside and what one secret opens, and names on the People page.
9. **Tier 3** as connectors allow.

Open questions:

- **Before step 5:** do the Anthropic and OpenAI admin APIs expose a hard spend limit, and at what level? Answered: OpenAI does, per organization and per project, never per key. Anthropic's Admin API does not for Claude Console organizations, so those limits are declared.
- **Before step 7:** how AWS principals get linked to a person. Email works for Google and GCP users; AWS IAM users need a tag or an owners file. Answered for GitHub (a login maps to an email in `people.yaml`, never guessed) and GCP (by email, and through Google groups). AWS is still open.
- **Before step 8:** whether the People screen may show names. Emails are hashed and kept out of snapshots today; showing a name means either storing it or resolving it at view time from a file the viewer holds.
