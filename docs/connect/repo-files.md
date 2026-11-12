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

`--include-home` also reads user-level agent settings in your home folder, `~/.claude/settings.json`, `~/.cursor/mcp.json`, `~/.cursor/sandbox.json`, `~/.vscode/mcp.json` and `~/.gemini/settings.json`. CI never sees these, and its results say "committed files only".

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

## Limiting where agents can reach

`agent/egress-allowlisted` fails when a coding agent's committed settings leave outbound network access open, or allow every host, and warns when only tool-level rules exist or the tool has no such setting. It passes when a real boundary limits access to listed hosts. What counts, per tool:

- **Claude Code**, in `.claude/settings.json` (merged with `settings.local.json`, and your user file with `--include-home`):

  ```json
  {
    "sandbox": {
      "enabled": true,
      "allowUnsandboxedCommands": false,
      "network": { "allowedDomains": ["github.com", "*.npmjs.org"] }
    },
    "permissions": { "allow": ["WebFetch(domain:docs.acme.com)"] }
  }
  ```

  The sandbox limits Bash and what it starts; WebFetch follows its own permission rules, so a bare `WebFetch` allow rule, `sandbox.excludedCommands`, or leaving the unsandboxed retry on makes it partial. Without the sandbox, deny rules on `WebFetch`, `WebSearch`, `curl` or `wget` are partial: a program reached another way is not stopped. A host outside the list still prompts unless `sandbox.network.strictAllowlist` is set in user or managed settings, which Firedrill does not read.
- **Cursor**: commit `.cursor/sandbox.json` with `"networkPolicy": {"default": "deny", "allow": [...]}`. The network mode chosen in Cursor's own settings (such as Allow All) is not in the file and is not checked.
- **VS Code**: in `.vscode/mcp.json`, run each local server with `"sandboxEnabled": true` and `"sandbox": {"network": {"allowedDomains": [...]}}`. VS Code's agent terminal settings are not read.
- **Gemini CLI** has no setting that lists hosts, and local MCP servers under Claude Code and Cursor have none either, so those warn.

`*` or `0.0.0.0/0` in an allowlist fails. The Agents page shows each config's outbound access and its hosts. Only committed settings are read: whether a sandbox actually enforces them on each machine is not checked.

### A boundary outside the agent

Settings an agent reads are settings an agent can change. The same drill also looks for a boundary outside it, from repo files only, and records it per repo as `files.egress_boundary`:

- **CI jobs that run a coding agent** (`anthropics/claude-code-action`, `anthropics/claude-code-base-action`, `openai/codex-action`, `google-github-actions/run-gemini-cli`, or a `run:` step starting `claude`, `codex`, `gemini`, `cursor-agent` or `aider`). Make [`step-security/harden-runner`](https://github.com/step-security/harden-runner) the job's first step:

  ```yaml
  - uses: step-security/harden-runner@<full commit SHA> # pin it
    with:
      egress-policy: block
      allowed-endpoints: >
        api.anthropic.com:443
        github.com:443
  ```

  `audit` only logs, so it does not count. harden-runner does not work when the whole job runs in a container on a GitHub-hosted runner, and is a no-op on self-hosted runners without its Enterprise tier, so neither counts. A job container with `options: --network none` counts.
- **Dev containers** (`.devcontainer/devcontainer.json`, `.devcontainer/*/devcontainer.json`). A firewall counts when a lifecycle command runs an `init-firewall` script and `runArgs` grant `--cap-add=NET_ADMIN`, as in [Claude Code's reference container](https://code.claude.com/docs/en/devcontainer); so do `"runArgs": ["--network=none"]` and a compose service with `network_mode: none` or only `internal: true` networks.
- **Managed settings**, with `--include-home`: Claude Code's `managed-settings.json` (macOS `/Library/Application Support/ClaudeCode/`, Linux `/etc/claude-code/`, Windows `C:\Program Files\ClaudeCode\`) and `managed-settings.d/*.json`, with `sandbox.enabled`, `sandbox.network.allowManagedDomainsOnly` and a host list.

`boundary` is `enforced` when every place an agent is configured to run has one, `partial` when some do, `none` when none do, and `unknown` when there is no agent or nothing could be judged (agent configs with no dev container, read in CI without your machine's managed settings). The drill warns on `none` or `partial`, and fails only when a CI job runs a coding agent with no egress control at all while its workflow references a secret or its token can write. This shows that a boundary is configured, not that it is working on a given machine or run.

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
