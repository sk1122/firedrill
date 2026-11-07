# Connect GitHub

GitHub unlocks the Change pack (branch protection, rulesets, production environments, Actions settings) and lets Firedrill read remote repos for the file drills.

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
| Administration | Read-only |
| Contents | Read-only |
| Environments | Read-only |
| Metadata | Read-only (added automatically) |

If your org requires approval for fine-grained tokens, an org owner approves it under the org's **Settings → Personal access tokens → Pending requests**.

Firedrill reads it from `FIREDRILL_GITHUB_TOKEN`, then `GH_TOKEN`, then your `gh` login.

## Ruleset bypass lists

GitHub shows who may bypass a ruleset only to people with write access to it, so a read-only token sees bypass as `unknown`, and drills give WARN instead of PASS. A repo admin can export the lists once:

```bash
firedrill export rulesets
```

It writes `.firedrill/evidence/rulesets.json`. Commit it; CI uses it for 30 days, and records say which commit it came from.

## What your plan allows

GitHub Free has no branch protection on private repos, and only Enterprise has environment reviewers on private repos. Firedrill reads your plan, and drills that ask for something your plan can't offer give N/A with the reason, never a FAIL you can't fix. If the token can't see your plan, GitHub's own "upgrade to enable" reply is used instead.
