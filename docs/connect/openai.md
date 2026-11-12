# Connect OpenAI

OpenAI unlocks `keys/ai-keys-capped`, together with Anthropic or on its own.

Firedrill reads every active project's API keys: ID, name, the redacted value OpenAI shows (such as `sk-proj-abc...wxyz`), owner and creation date, and the hard spend limit of each project and of the organization. It never sees a key's secret, since the API never returns one. An owner's email is turned into a hashed ID at once and never stored.

## What to know before you start

An **Admin key is powerful.** Anyone holding it can create and delete keys, projects and service accounts, and change spend limits. OpenAI admin keys have no read-only scope.

Firedrill only ever sends it with **GET**, to four paths:

```
GET https://api.openai.com/v1/organization/projects
GET https://api.openai.com/v1/organization/projects/{project}/api_keys
GET https://api.openai.com/v1/organization/projects/{project}/spend_limit
GET https://api.openai.com/v1/organization/spend_limit
```

The read-only guard refuses every other method and every other path on `api.openai.com`, including inference and the admin key list, before the request leaves your machine. The key is read from the environment, sent only as the `Authorization` header to `api.openai.com`, never followed through a redirect, and never written to a record, a log or the graph.

**How a cap is read.** A hard spend limit above zero on the organization covers every key; one on a project covers that project's keys. A limit of zero is no cap. When OpenAI refuses or does not answer a limit read, the key reads `limit_readable: false` and the drill warns rather than guessing.

## 1. Create the admin key

You need to be an organization owner.

1. In the OpenAI dashboard, open **Organization settings → Admin keys**.
2. Create a key named `firedrill-read`.
3. Copy it. It is shown once.

## 2. Hand it to Firedrill

Keep it in your password manager or secrets store, never in the repo or `config.yaml`:

```bash
export FIREDRILL_OPENAI_ADMIN_KEY=...   # from your secrets manager
```

## 3. Check it

```bash
firedrill connect openai
```

You should see `Connected. Read N items`, one per key. This records `openai` under `connected` in `config.yaml`; before that, Firedrill never calls OpenAI, whatever is in the environment.

## 4. Declare what the API cannot show

Where a project's limit can't be read, or a key's owner has left, declare it in `.firedrill/ai-keys.yaml`:

```yaml
- provider: openai
  project: acme-prod            # the project ID or name
  owner: "@acme/ml"             # a handle or team, never an email
  monthly_limit_usd: 1000
  verified: 2026-11-01
```

## Rotate it

Create a new admin key, switch `FIREDRILL_OPENAI_ADMIN_KEY` to it, run `firedrill connect openai`, then delete the old one under **Admin keys**. Delete it straight away if you stop using Firedrill.

## If something goes wrong

| What you see | Why, and what to do |
| --- | --- |
| `HTTP 401: the admin key was refused` | The key is wrong or deleted, or is a project key rather than an admin key |
| `Read only in part: keys of project ... could not be listed` | The admin key cannot see that project. Its keys are left out, so the drill warns |
| `Not connected yet: connect openai` | `FIREDRILL_OPENAI_ADMIN_KEY` is not set |

## In CI

Save the key as a repository secret and pass it as `FIREDRILL_OPENAI_ADMIN_KEY` to the `firedrill run` step only.
