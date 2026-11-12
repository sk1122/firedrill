# Connect Google Workspace

Google Workspace unlocks `access/admins-use-mfa`, `access/all-users-use-mfa`, the Workspace half of `access/no-dormant-admins`, `access/third-party-apps-reviewed`, `access/every-admin-is-someone`, and, with an HR export, `access/leavers-gone-everywhere`.

Firedrill reads the user directory: each user's admin status, 2-Step Verification enrollment and enforcement, last login and creation date. It also reads the OAuth grants each user gave third-party apps: which app, which scopes. Emails are kept in memory and stored only as hashes.

It also reads the members of the Google groups that hold a role in a connected Google Cloud project, to tell who holds that role. No other group's members are read, and with no group in a GCP binding, no group call is made at all.

It reads through a service account with **domain-wide delegation**, which a **super admin** approves once. It asks for three scopes, each in its own token:

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.user.security
https://www.googleapis.com/auth/admin.directory.group.readonly
```

The second is what Google's [tokens.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list) requires. Google offers no read-only version of it: it also covers revoking grants. Firedrill's guard allows only GET on the Admin SDK, so it can list grants and never revoke one. Without it, every other Workspace drill still runs and `access/third-party-apps-reviewed` gives ERROR, saying the scope is missing.

Grants are read with one call per user, eight at a time, using each user's ID rather than their email, so no address appears in the call log.

The third scope is read-only. It is what [groups.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list) and [members.list](https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/list) require. Firedrill lists the account's groups once, to map each group's address and aliases to its ID, then lists the members of each group a GCP binding names, and of each group nested in one, by ID, so again no address appears in the call log. Without the scope, every other Workspace drill still runs; who holds a role through a group reads as unknown, never as nobody, and the people facts give WARN, saying the scope is missing. Google runs after Google Cloud in each run, so it can see which groups to read.

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
4. **OAuth scopes:** `https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/admin.directory.user.security,https://www.googleapis.com/auth/admin.directory.group.readonly`
5. Choose **Authorize**.

Approval can take a few minutes to apply.

Already connected with fewer scopes? Edit the same client ID's entry, add the missing ones, and run `firedrill connect google` again.

Optional: add `https://www.googleapis.com/auth/admin.reports.audit.readonly` to name who made a change. After each run's diff, Firedrill asks the [Reports API](https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list) (`GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/{admin, token or groups}`) for events in the window between the two runs only: `GRANT_ADMIN_PRIVILEGE` and `ASSIGN_ROLE` for a new admin, `SUSPEND_USER` and `UNSUSPEND_USER`, `authorize` for an OAuth grant, `add_user` for a group member. No address goes in the URL; the addresses in the answer are hashed at once and never stored. Without the scope, the diff says `google_reports: not readable` and each change keeps the window.

`admin_email` must be an admin whose role can read groups, such as a super admin or a Groups Admin, for the third scope to work.

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

You should see `Connected. Read N items`: users and the apps they granted access. If the second scope is missing, it also prints `Not readable yet:` with what to add.

## 6. Record who owns each third-party app

`access/third-party-apps-reviewed` fails for any app holding Gmail, Drive, admin or Cloud scopes that has no owner and current review. Record them in `.firedrill/apps.yaml`:

```yaml
- client_id: 1234567890-acmenotes.apps.googleusercontent.com   # from the drill's evidence or the Admin console
  name: Acme Notes AI
  owner: "@acme/it"          # a handle or team, never an email
  reviewed: 2026-11-01       # when someone last checked it still needs this access
  note: meeting notes, approved by security
```

A review stays current for 180 days; set `google.review_days` in `config.yaml` to change it. To remove an app instead, use **Security → Access and data control → API controls → App access control** in the Admin console.

## If something goes wrong

These are Google's usual messages for each problem.

| What you see | Why, and what to do |
| --- | --- |
| `unauthorized_client` | Delegation isn't approved for this client ID and scope yet, or hasn't applied. Check step 3, wait a few minutes |
| `Not Authorized to access this resource/api` | `admin_email` isn't an admin who can read users |
| `Not readable yet: could not read users' OAuth grants` | The `admin.directory.user.security` scope isn't approved for the client ID yet. Add it in step 3 |
| `Read only in part: the OAuth grants of N of M users could not be read` | Those users were deleted or moved during the run. Rerun |
| `could not read Google groups: … Add https://www.googleapis.com/auth/admin.directory.group.readonly` | The third scope isn't approved for the client ID yet. Add it in step 3 |
| `the members of N of M groups that hold a GCP role could not be read` | A group in a GCP binding is outside this Workspace account, or `admin_email` can't read it. Its people stay unknown |
| `Not connected yet: connect google` | `google.domain`, `google.admin_email` or `GOOGLE_APPLICATION_CREDENTIALS` is missing |

## In CI

Save the key file's contents as a repository secret and write it to a file in the workflow before `firedrill run`, then set `GOOGLE_APPLICATION_CREDENTIALS` to that file. Delete the file at the end of the job.
