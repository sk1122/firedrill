# Repo files

The file drills read your repos' committed files: secrets, coding agent settings, GitHub Actions workflows and Terraform. They need no account and no key.

## Remote repos

With [GitHub connected](github.md), Firedrill downloads each repo in `github.repos` as one tarball per run and reads it in memory. Nothing is written back.

## Local checkouts

```bash
firedrill run --path ../api --path ../web
```

A checkout whose folder name matches a repo in config replaces the download for that repo. On a laptop, Firedrill also reads `.env*` files and `.claude/settings.local.json` even when `.gitignore` excludes them, because that's where real secrets sit.

## Your own agent settings

```bash
firedrill run --path ../api --include-home
```

`--include-home` also reads user-level agent settings in your home folder, `~/.claude/settings.json`, `~/.cursor/mcp.json` and `~/.vscode/mcp.json`. CI never sees these, and its results say "committed files only".

## Tuning the secret scan

Firedrill decides each secret's environment from its path: `prod`, `staging`, `example` or `unknown`. Example paths are out of scope. You can extend the defaults in `.firedrill/config.yaml`:

```yaml
secrets:
  example_paths: ["samples/", "*.dist"]   # added to testdata/, fixtures/, test/, tests/, *_test.*, *.example …
  prod_words: ["live"]                     # added to prod, production
  staging_words: ["preprod"]               # added to staging, stage
agents:
  destructive_commands: ["kubectl delete"] # added to rm -rf, git push --force, DROP, terraform destroy …
```

To accept one known fake secret without hiding real ones, waive that single finding; see the README.
