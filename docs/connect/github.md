# Connect GitHub

GitHub unlocks the Change pack (branch protection, rulesets, production environments, Actions settings), shows who can reach each repo (org members, teams, collaborators and who can bypass review), and lets Firedrill read remote repos for the file drills.

## On your laptop

1. Install the [GitHub CLI](https://cli.github.com) and log in:

   ```bash
   gh auth login
   ```

   Choose GitHub.com and log in with a web browser. HTTPS or SSH doesn't matter; Firedrill uses the API token the login creates.

2. List the org and repos in `.firedrill/config.yaml`:

   ```yaml
   github:
     org: acme
     repos: [api, web, infra]
   ```

3. Check it:

   ```bash
   firedrill connect github
   ```

   You should see `Token found from gh auth token.` and `Connected. Read N items`.

A `gh` login acts as you, with all your access. Firedrill's guard still allows only reads, but in CI use a narrow token instead.

## In CI, or for a narrower token

Create a fine-grained token at [github.com/settings/personal-access-tokens/new](https://github.com/settings/personal-access-tokens/new):

| Setting | Value |
| --- | --- |
| Resource owner | Your org |
| Repository access | Only select repositories: the repos in `github.repos` |
| Repository permissions → Administration | Read-only |
| Repository permissions → Contents | Read-only |
| Repository permissions → Environments | Read-only |
| Repository permissions → Metadata | Read-only (added automatically) |
| Organization permissions → Members | Read-only |

A token made before this list had Members only needs that one permission added: edit the token, open **Organization permissions**, and set **Members** to Read-only. If your org approves tokens, the change needs approval again.

If your org requires approval for fine-grained tokens, an org owner approves it under the org's **Settings → Personal access tokens → Pending requests**.

Firedrill reads it from `FIREDRILL_GITHUB_TOKEN`, then `GH_TOKEN`, then your `gh` login.

## Ruleset bypass lists

GitHub shows who may bypass a ruleset only to people with write access to it, so a read-only token sees bypass as `unknown`, and drills give WARN instead of PASS. A repo admin can export the lists once:

```bash
firedrill export rulesets
```

It writes `.firedrill/evidence/rulesets.json`. Commit it; CI uses it for 30 days, and records say which commit it came from. The file holds each ruleset's bypass list as GitHub returns it: actor type, actor ID and bypass mode, with team and app IDs but no logins.

## Which repos deploy to production

`change/prod-deploy-gated`, `change/no-solo-ship` and `paths/no-single-person-code-to-prod-data` judge repos that deploy to production. A repo does when it has a GitHub environment named `production`, `prod` or `live`, in any case. Add other names your team uses:

```yaml
github:
  production_environments: [release, prd]
```

With several production environments, each gate is judged by the least protected of them. A repo that deploys from somewhere else, such as Vercel or Argo CD, with no production environment in GitHub, goes under the top-level `production` list as `org/repo`, next to the AWS accounts and GCP projects there:

```yaml
production: [acme/api, acme-prod]
```

Such a repo fails `change/prod-deploy-gated`, since nothing in GitHub gates its deploys, and warns on `change/no-solo-ship` while main is protected, since how its deploys are approved cannot be read. A repo with neither is N/A on all three, and the reason names both settings.

## Who can reach your repos

Firedrill reads, for `github.org` and each repo in `github.repos`:

| Call | What it reads | Permission |
| --- | --- | --- |
| `GET /orgs/{org}/members?role=admin` and `?role=member` | Org owners and members | Organization Members: read |
| `GET /orgs/{org}/outside_collaborators` | Outside collaborators | Organization Members: read |
| `GET /orgs/{org}/teams`, then `GET /orgs/{org}/teams/{team}/members?role=maintainer` and `?role=member` for each team | Teams, their parent team, and members (GitHub includes child teams' members) | Organization Members: read |
| `GET /repos/{repo}/collaborators?affiliation=all` | Everyone with access to the repo and their permission: admin, maintain, push, triage or pull | Repository Metadata: read |
| `GET /repos/{repo}/teams` | Teams with access to the repo and their permission | Repository Metadata: read |

Each list is read 100 at a time. Team members are read once per team, and no user profile is fetched, so a large org costs a few calls per team and per repo.

Logins are used during the run and in drill results only. Snapshots keep a hashed ID per person, never the login.

Who can bypass review on each repo's default branch comes from branch protection (users, teams and apps allowed to bypass pull requests, and every repo admin when admins are not included) and from rulesets' bypass lists (teams, repository roles, org admins, apps and deploy keys). Teams and roles are expanded to people; apps and deploy keys are listed as they are. A ruleset's bypass list needs the export below when the token can't see it. Until then Firedrill says it does not know who can bypass, never that nobody can.

Without Members: read, `firedrill connect github` prints `Not readable yet:` with what to add. Repo settings are still read, and only the facts about people give ERROR. A repo whose collaborators can't be read prints `Read only in part:`, and drills reading people there give WARN.

If `github.org` is a user account rather than an org, there are no members or teams; repo collaborators are still read.

## Who made a change (optional)

After each run's diff, Firedrill asks GitHub's [organization audit log](https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization) who changed a ruleset, branch protection, repo access or an org role, for the window between the two runs only: `GET /orgs/{org}/audit-log` with a search phrase of one action or category, the repo and `created:<from>..<to>`, one page of 100, at most 50 audit calls a run across every source. The login it returns is hashed at once and never stored; a change shows the person's short ID, or the account's.

The audit log needs GitHub Enterprise Cloud and a token of an organization owner with `read:audit_log` (a classic token or OAuth app; GitHub's reference names no fine-grained permission for it). With any other plan or token the call returns 403 or 404, the diff says `github_audit: not readable`, and each change keeps the window. Nothing else is affected.

## What your plan allows

GitHub Free has no branch protection on private repos, and only Enterprise has environment reviewers on private repos. Firedrill reads your plan, and drills that ask for something your plan can't offer give N/A with the reason, never a FAIL you can't fix. If the token can't see your plan, GitHub's own "upgrade to enable" reply is used instead.
