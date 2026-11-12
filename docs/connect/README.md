# Connecting Firedrill

Firedrill only reads, and every system it reads needs your permission first. These guides walk through each one: what to create, what to click, and how to check it worked.

Start with GitHub; with it alone, 19 of the 38 starter drills run. Add the rest when you need their drills. `firedrill run` lists every drill that is waiting, and what connects it.

| System | Guide | Drills it unlocks | Time |
| --- | --- | --- | --- |
| GitHub | [github.md](github.md) | Change pack, remote repo files | 1 minute |
| Repo files | [repo-files.md](repo-files.md) | Agent pack (including agent egress), secrets, workflows, lockfiles, Terraform | None |
| Google Cloud | [gcp.md](gcp.md) | GCP pack, Cloud SQL backups and restores, who can delete production data (Paths pack), live keys in public JavaScript | 15 minutes |
| Google Workspace | [google-workspace.md](google-workspace.md) | MFA, leavers, dormant admins, third-party apps | 10 minutes, needs a super admin |
| AWS | [aws.md](aws.md) | Dormant admins, destructive tokens, unused keys, database backups | 5 minutes per account |
| Anthropic | [anthropic.md](anthropic.md) | AI keys capped and owned | 5 minutes, needs an admin key |
| OpenAI | [openai.md](openai.md) | AI keys capped and owned | 5 minutes, needs an admin key |
| Domains | [domains.md](domains.md) | Doors pack: DNS, certificate logs, web, credentials in public JavaScript, unpinned third-party scripts | 5 minutes, needs DNS access |
| HR leavers | [hr.md](hr.md) | Leavers gone everywhere | One export |
| Semgrep | [semgrep.md](semgrep.md) | Your own Semgrep rules | One scan |
| Postgres (optional) | [postgres.md](postgres.md) | None; faster board builds | 2 minutes |
| Weekly CI | [ci.md](ci.md) | Everything above, every Monday | 10 minutes |

## Checking a connection

```bash
firedrill connect <system>
```

It prints the exact permissions the system needs, then reads it once and reports `Connected. Read N items`, or what is missing. Nothing is written anywhere.

```bash
firedrill run --dry-run
```

It lists every call a run would make, without making any.

## Where credentials live

Never in `config.yaml`, and never in the repo. Firedrill reads them from your environment, your `gh` and `gcloud` logins, or your AWS profiles, and keeps them in memory only. Anthropic and OpenAI admin keys come from `FIREDRILL_ANTHROPIC_ADMIN_KEY` and `FIREDRILL_OPENAI_ADMIN_KEY` and are only ever sent with GET.

## Registers you keep

Some evidence no API shows. Files under `.firedrill/` hold it. Each entry names an owner or the team that did the work (a handle or team, never an email), and most a date someone checked it:

| File | What it declares | Read by |
| --- | --- | --- |
| `apps.yaml` | Owner and last review of each third-party OAuth app | `access/third-party-apps-reviewed` |
| `backups.yaml` | A copy of a database in another account or project | `recovery/backups-separate-and-retained` |
| `restores.yaml` | A restore of a database the API cannot show: `database`, `restored` (YYYY-MM-DD), `by` (a team or role) and an optional `note` | `recovery/restore-exercised` |
| `ai-keys.yaml` | Owner and monthly spend limit of an AI key, workspace or project | `keys/ai-keys-capped` |
| `owners.yaml` | The team that owns a principal no person holds: a GCP service account's address, or a graph ID such as `github:app/123456` or `github:deploy-key/acme/api`, with `principal`, `owner` and an optional `note` | `people.admins`, `people.unlinked` |
| `people.yaml` | A flat map of GitHub login to the email of the person who holds it, such as `ana-acme: ana@acme.example`. Logins match case-insensitively, and several may name one person. A login with no entry stays unlinked; it is never guessed. This file holds emails and never reaches a record | `people.accounts`, `people.admins`, `people.unlinked` |

Declared evidence is shown as declared in each result.
