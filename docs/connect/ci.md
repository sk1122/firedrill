# Weekly in CI

The workflow runs every drill each Monday, keeps the records in your Firedrill repo, attests the tags each run writes, opens an issue for each safeguard that turns open, assigned to its owner, and keeps one standing issue, "Firedrill weekly: what changed", whose body is the diff since the last run (weakenings first) and the open safeguards. It closes a safeguard's issue when a run passes.

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

## Attestation

After `firedrill run`, the workflow attests the tags it wrote with a [GitHub artifact attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds):

1. `firedrill run` writes `records/attest/<time>.sha256`, one `sha256  path` line per tag and diff it wrote, and sets the step output `checksums`.
2. [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance), pinned by commit, attests that file in one attestation with `subject-checksums`. The job needs `id-token: write` and `attestations: write`, which the workflow grants to that job only.
3. `firedrill attest record` writes `records/attest/<time>.json` with the checksums file's hash and the attestation's ID and URL, and keeps the bundle beside it.
4. The records are pushed.

`firedrill verify --records records` then reports each tag `attested`, `unattested` or `checksums mismatch`, with no network call; `--online` prints the `gh attestation verify` commands to check each signature yourself. Laptop runs are never attested.

GitHub offers attestations in public repos on every current plan, and in private or internal repos only on GitHub Enterprise Cloud. A private Firedrill repo on another plan gets an error from the attest step, which is allowed to fail, and its tags stay unattested; nothing else changes. These steps were built to GitHub's documentation and have not yet been exercised in a real Actions run.

## 4. Run it once

```bash
gh workflow run firedrill.yml --repo acme/firedrill
```

Check the run's summary page, the new `firedrill-tags` branch, the issues it opened and the "Firedrill weekly: what changed" issue (label `firedrill-weekly`), which later runs edit rather than open again. The board is attached to each run as an artifact.

## What CI can't see

CI reads committed files only, and its results say so. Run on a laptop with `--path` and `--include-home` to read `.env*` files and user-level agent settings too.
