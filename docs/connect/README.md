# Connecting Firedrill

Firedrill only reads, and every system it reads needs your permission first. These guides walk through each one: what to create, what to click, and how to check it worked.

Start with GitHub; with it alone, 11 of the 24 starter drills run. Add the rest when you need their drills. `firedrill run` lists every drill that is waiting, and what connects it.

| System | Guide | Drills it unlocks | Time |
| --- | --- | --- | --- |
| GitHub | [github.md](github.md) | Change pack, remote repo files | 1 minute |
| Repo files | [repo-files.md](repo-files.md) | Agent pack, secrets, workflows, Terraform | None |
| Google Cloud | [gcp.md](gcp.md) | GCP pack | 15 minutes |
| Google Workspace | [google-workspace.md](google-workspace.md) | MFA, leavers, dormant admins | 10 minutes, needs a super admin |
| AWS | [aws.md](aws.md) | Dormant admins, destructive tokens, unused keys | 5 minutes per account |
| Domains | [domains.md](domains.md) | Doors pack: DNS, certificate logs, web | 5 minutes, needs DNS access |
| HR leavers | [hr.md](hr.md) | Leavers locked out | One export |
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

Never in `config.yaml`, and never in the repo. Firedrill reads them from your environment, your `gh` and `gcloud` logins, or your AWS profiles, and keeps them in memory only.
