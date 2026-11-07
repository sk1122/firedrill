# Weekly in CI

The workflow runs every drill each Monday, keeps the records in your Firedrill repo, and opens an issue for each safeguard that turns open, assigned to its owner. It closes the issue when a run passes.

Keep Firedrill in its own **private** repo, such as `acme/firedrill`, because records hold account names and failing settings.

## 1. Add the workflow

Copy [docs/firedrill-workflow.yml](../firedrill-workflow.yml) to `.github/workflows/firedrill.yml` in your Firedrill repo, and commit it with your `.firedrill/` folder.

## 2. Add two repository secrets

| Secret | Value |
| --- | --- |
| `FIREDRILL_GITHUB_TOKEN` | A fine-grained read token for the repos in `github.repos`; see [github.md](github.md) |
| `FIREDRILL_SALT` | The salt `init` generated, from `~/.config/firedrill/salt` |

```bash
gh secret set FIREDRILL_GITHUB_TOKEN --repo acme/firedrill
```

```bash
gh secret set FIREDRILL_SALT --repo acme/firedrill < ~/.config/firedrill/salt
```

Keep the salt in your password manager too. Every machine and CI must use the same one, or hashes and waivers won't match. A CI run without it stops with ERROR.

For other systems, add their credentials the same way; see each guide's "In CI" section.

## 3. Protect the repo

- Protect `firedrill-tags`, the records branch, against force pushes and deletion.
- Require a pull request with a reviewer on `main`, so changes to drills and waivers are reviewed.
- Give each drill owner read access to the repo, so issues can be assigned to them. An owner without access is named in the issue and the default owner is assigned.

## 4. Run it once

```bash
gh workflow run firedrill.yml --repo acme/firedrill
```

Check the run's summary page, the new `firedrill-tags` branch, and the issues it opened. The board is attached to each run as an artifact.

## What CI can't see

CI reads committed files only, and its results say so. Run on a laptop with `--path` and `--include-home` to read `.env*` files and user-level agent settings too.
