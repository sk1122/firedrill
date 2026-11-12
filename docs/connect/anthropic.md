# Connect Anthropic

Anthropic unlocks `keys/ai-keys-capped`, together with OpenAI or on its own.

Firedrill reads every API key of your Claude Console organization: its ID, name, status, the provider's own partial hint (such as `sk-ant-api03-R2D...igAA`), who created it or acts through it, and its workspace. It never sees a key's secret, since the API never returns one.

## What to know before you start

An **Admin API key is powerful.** Anyone holding it can create and delete API keys, invite and remove members and change workspaces. Claude Console admin keys have no read-only scope.

Firedrill only ever sends it with **GET**, to two paths:

```
GET https://api.anthropic.com/v1/organizations/api_keys
GET https://api.anthropic.com/v1/organizations/workspaces
```

The read-only guard refuses every other method and every other path on `api.anthropic.com`, including inference, before the request leaves your machine. The key is read from the environment, sent only as the `x-api-key` header to `api.anthropic.com`, never followed through a redirect, and never written to a record, a log or the graph.

**What the API cannot show.** The Admin API shows no spend limit for a Console organization, workspace or key. Workspace spend limits exist in the Console, but nothing reads them back. So every Anthropic key is `limit_readable: false` and the drill warns until you declare the limit in `.firedrill/ai-keys.yaml` (step 4).

## 1. Create the admin key

You need the **admin** role in the organization.

1. In the Claude Console, open **Settings → Admin keys** (`platform.claude.com/settings/admin-keys`).
2. Choose **Create admin key**, name it `firedrill-read`, and pick an expiration. Prefer a short one, such as 90 days.
3. Copy the key (`sk-ant-admin01-...`). It is shown once.

## 2. Hand it to Firedrill

Keep it in your password manager or secrets store, never in the repo or `config.yaml`:

```bash
export FIREDRILL_ANTHROPIC_ADMIN_KEY=...   # from your secrets manager
```

## 3. Check it

```bash
firedrill connect anthropic
```

You should see `Connected. Read N items`, one per key. This records `anthropic` under `connected` in `config.yaml`; before that, Firedrill never calls Anthropic, whatever is in the environment.

## 4. Declare owners and limits the API cannot show

In `.firedrill/ai-keys.yaml`, one entry per workspace (or per key):

```yaml
- provider: anthropic
  workspace: acme-prod          # the workspace ID or name
  owner: "@acme/ml"             # a handle or team, never an email
  monthly_limit_usd: 500        # the limit set in the Console
  verified: 2026-11-01          # when someone last checked it there
- provider: anthropic
  key_id: apikey_01AcmeExample  # one key
  owner: "@acme/platform"
  verified: 2026-11-01
```

An entry with `monthly_limit_usd` above 0 marks every key it names as capped. An `owner` names an owner for keys the Console records no creator for.

## Rotate it

Create a new admin key, switch `FIREDRILL_ANTHROPIC_ADMIN_KEY` to it, run `firedrill connect anthropic`, then delete the old key under **Admin keys**. Delete it straight away if you stop using Firedrill.

## If something goes wrong

| What you see | Why, and what to do |
| --- | --- |
| `HTTP 401: the admin key was refused` | The key is wrong, expired or deleted, or is a normal API key rather than an admin key |
| `HTTP 403` | The key belongs to a Claude Enterprise organization, where these endpoints don't apply |
| `Not connected yet: connect anthropic` | `FIREDRILL_ANTHROPIC_ADMIN_KEY` is not set |
| `blocked by the read-only guard` | Something tried a call outside the two above. The run stops; please report it |

## In CI

Save the key as a repository secret and pass it as `FIREDRILL_ANTHROPIC_ADMIN_KEY` to the `firedrill run` step only.
