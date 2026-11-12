# Repo files

The file drills read your repos' committed files: secrets, coding agent settings and the MCP servers they name, GitHub Actions workflows, JavaScript manifests and lockfiles, and Terraform. They need no account and no key.

## Remote repos

With [GitHub connected](github.md), Firedrill downloads each repo in `github.repos` as one tarball per run and reads it in memory. Nothing is written back.

## Local checkouts

```bash
firedrill run --path ../api --path ../web
```

A checkout whose folder name matches a repo in config replaces the download for that repo. On a laptop, Firedrill also reads `.env*` files and agent config files (`.claude/`, `.cursor/`, `.gemini/`, `.mcp.json`, `.vscode/mcp.json`) even when `.gitignore` excludes them, because that's where real secrets sit. JavaScript lockfiles are read even when gitignored too, so a lockfile left out of git is reported rather than missed.

## Your own agent settings

```bash
firedrill run --path ../api --include-home
```

`--include-home` also reads user-level agent settings in your home folder, `~/.claude/settings.json`, `~/.cursor/mcp.json` and `~/.vscode/mcp.json`. CI never sees these, and its results say "committed files only".

## Tuning the secret scan

Firedrill decides each secret's environment from its path: `prod`, `staging`, `example` or `unknown`. Example paths are out of scope. By default only `*.example`, `*.sample` and `*.template` files are examples; test folders and test files are not, so a real key committed under `test/` is still found. If a folder holds only fakes, add it under `example_paths`. You can extend the defaults in `.firedrill/config.yaml`:

```yaml
secrets:
  example_paths: ["samples/", "*.dist"]   # added to *.example, *.sample, *.template
  prod_words: ["live"]                     # added to prod, production
  staging_words: ["preprod"]               # added to staging, stage
agents:
  destructive_commands: ["kubectl delete"] # added to rm -rf, git push --force, DROP, terraform destroy …
```

## Allowing MCP servers

`agent/mcp-servers-known` fails an MCP server whose URL points at a host you don't own, or whose package isn't pinned to an exact version. A host counts as owned when it is under a domain verified with `firedrill verify-domain`, listed in `.firedrill/hosts.yaml`, or `localhost`. After reviewing a vendor's server or package, allow it in `.firedrill/config.yaml`:

```yaml
agents:
  mcp_hosts: ["mcp.vendor.example"]        # hosts or domains; subdomains count
  mcp_packages: ["@acme/mcp-fs", "ghcr.io/acme/mcp"]  # exact npm, PyPI or image names
```

A pinned package that isn't on `mcp_packages` gives WARN, not FAIL. Firedrill keeps only a URL's hostname and a command's base name and package: never the path, query or arguments, which can carry tokens.

## JavaScript lockfiles

`supply/installs-from-lockfile` judges npm, pnpm, yarn and bun projects only; a repo with no `package.json` is N/A. It reads which dependencies the lockfile marks as running install scripts (`hasInstallScript` in `package-lock.json` v2 and v3, `requiresBuild` in `pnpm-lock.yaml` before pnpm 9) and compares them with the previous run, so the first run sets the baseline. yarn and bun lockfiles don't record install scripts, so for them only the lockfile and CI checks apply. A new install script stays a finding until it leaves the lockfile; to accept one after review, waive it by file:

```yaml
# .firedrill/waivers.yaml
- drill: supply/installs-from-lockfile
  finding: { file: package.json }
  reason: "esbuild's postinstall fetches its binary; reviewed"
  approved_by: "@arjun"
  expires: 2027-02-01
```

To accept one known fake secret without hiding real ones, waive that single finding; see the README.
