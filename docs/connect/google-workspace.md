# Connect Google Workspace

Google Workspace unlocks `access/admins-use-mfa`, `access/all-users-use-mfa`, the Workspace half of `access/no-dormant-admins`, and, with an HR export, `access/leavers-locked-out`.

Firedrill reads the user directory: each user's admin status, 2-Step Verification enrollment and enforcement, last login and creation date. Emails are kept in memory and stored only as hashes.

It reads through a service account with **domain-wide delegation**, which a **super admin** approves once. It asks for one scope:

```
https://www.googleapis.com/auth/admin.directory.user.readonly
```

## 1. Create the service account

In a Google Cloud project you control (`HOME_PROJECT` below):

```bash
gcloud services enable admin.googleapis.com --project HOME_PROJECT
```

```bash
gcloud iam service-accounts create firedrill-directory --project HOME_PROJECT --display-name "Firedrill directory reader"
```

The account needs no roles in Google Cloud. Its only access comes from step 3.

## 2. Create its key

```bash
gcloud iam service-accounts keys create ~/.config/firedrill/workspace-key.json --iam-account firedrill-directory@HOME_PROJECT.iam.gserviceaccount.com
```

```bash
chmod 600 ~/.config/firedrill/workspace-key.json
```

Keep the key outside every repo. It is long-lived, so `gcp/sa-keys-short-lived` will flag it after 90 days if you drill `HOME_PROJECT`: rotate it by creating a new key, switching to it, and deleting the old one.

## 3. Approve domain-wide delegation (super admin)

Get the account's client ID:

```bash
gcloud iam service-accounts describe firedrill-directory@HOME_PROJECT.iam.gserviceaccount.com --format 'value(uniqueId)'
```

Then in the [Admin console](https://admin.google.com):

1. Go to **Security → Access and data control → API controls**.
2. Under **Domain-wide delegation**, choose **Manage domain-wide delegation**, then **Add new**.
3. **Client ID:** the number from above.
4. **OAuth scopes:** `https://www.googleapis.com/auth/admin.directory.user.readonly`
5. Choose **Authorize**.

Approval can take a few minutes to apply.

## 4. Point Firedrill at it

```bash
export GOOGLE_APPLICATION_CREDENTIALS=~/.config/firedrill/workspace-key.json
```

In `.firedrill/config.yaml`:

```yaml
google:
  domain: acme.com              # the domain to read
  admin_email: admin@acme.com   # an admin the service account acts as, to read the directory
```

## 5. Check it

```bash
firedrill connect google
```

You should see `Connected. Read N items`, one per user.

## If something goes wrong

These are Google's usual messages for each problem.

| What you see | Why, and what to do |
| --- | --- |
| `unauthorized_client` | Delegation isn't approved for this client ID and scope yet, or hasn't applied. Check step 3, wait a few minutes |
| `Not Authorized to access this resource/api` | `admin_email` isn't an admin who can read users |
| `Not connected yet: connect google` | `google.domain`, `google.admin_email` or `GOOGLE_APPLICATION_CREDENTIALS` is missing |

## In CI

Save the key file's contents as a repository secret and write it to a file in the workflow before `firedrill run`, then set `GOOGLE_APPLICATION_CREDENTIALS` to that file. Delete the file at the end of the job.
