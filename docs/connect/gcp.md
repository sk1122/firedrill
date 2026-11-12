# Connect Google Cloud

Google Cloud unlocks the GCP pack: public buckets, uniform bucket access, Owner and Editor only for your own domains, no Editor on service accounts, no project-wide impersonation, and service account keys no older than 90 days. With or without AWS, it also unlocks `recovery/backups-separate-and-retained` and `recovery/restore-exercised` for Cloud SQL, and lets `doors/no-live-key-in-public-bundle` tell whether a service account key found in public JavaScript is live.

Firedrill reads through a **reader service account** that has read roles only and **no key**. You log in as it through `gcloud`, so nothing long-lived is stored.

You'll run about a dozen `gcloud` commands once. Replace the values in the table first.

| Placeholder | What to put | Example |
| --- | --- | --- |
| `HOME_PROJECT` | The project the reader account lives in, and whose quota its calls use | `acme-security` |
| `PROJECTS` | Every project to drill, space-separated | `acme-prod acme-staging` |
| `YOU` | Your Google account | `you@acme.com` |

## 1. Install and log in to gcloud

Install the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install), then:

```bash
gcloud auth login
```

You need permission to create service accounts in `HOME_PROJECT` and to change IAM on each project in `PROJECTS`; Owner works.

## 2. Turn on the APIs

```bash
gcloud services enable iam.googleapis.com iamcredentials.googleapis.com cloudresourcemanager.googleapis.com policyanalyzer.googleapis.com sqladmin.googleapis.com --project HOME_PROJECT
```

Calls are billed to the reader's own project, so other projects need no APIs turned on. Google checks whether an API is on in the project a call is billed to (the [quota project](https://docs.cloud.google.com/docs/quotas/quota-project)), so `sqladmin.googleapis.com` must be on in `HOME_PROJECT` even when no database lives there.

## 3. Create the reader

```bash
gcloud iam service-accounts create firedrill-reader --project HOME_PROJECT --display-name "Firedrill read-only"
```

Don't create a key for it.

## 4. Give it read roles on every project

```bash
for P in PROJECTS; do
  for R in roles/viewer roles/iam.securityReviewer roles/policyanalyzer.activityAnalysisViewer roles/iam.roleViewer; do
    gcloud projects add-iam-policy-binding "$P" --member "serviceAccount:firedrill-reader@HOME_PROJECT.iam.gserviceaccount.com" --role "$R" --condition None --quiet
  done
done
```

Activity Analysis Viewer is only for the last time each key was used. Without it, keys are still judged by age.

Optional, to name who changed a project's IAM policy: Logs Viewer (`roles/logging.viewer`), which grants `logging.logEntries.list`. After each run's diff, Firedrill asks [Cloud Logging](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list) for the project's Admin Activity entries with method `SetIamPolicy` in the window between the two runs only. The caller's address is hashed at once and never stored. Without the role, the diff says `gcp_audit: not readable` and each change keeps the window. Viewer may already include it; the call simply fails softly if not.

Role Viewer lets Firedrill read the permissions of a custom role a binding names, with [roles.get](https://cloud.google.com/iam/docs/reference/rest/v1/projects.roles/get) (`iam.roles.get`). Without it, those bindings read as `power_known: false`, never as harmless, and the people facts give WARN. A custom role defined on the organization (`organizations/{org}/roles/...`) needs Role Viewer on the organization too; without it, the same applies.

## 5. Let yourself act as the reader

```bash
gcloud iam service-accounts add-iam-policy-binding firedrill-reader@HOME_PROJECT.iam.gserviceaccount.com --project HOME_PROJECT --member "user:YOU" --role roles/iam.serviceAccountTokenCreator
```

This grants it on the reader account alone, not the whole project.

## 6. Log in as the reader

```bash
gcloud auth application-default login --impersonate-service-account=firedrill-reader@HOME_PROJECT.iam.gserviceaccount.com
```

Firedrill reads this login from `~/.config/gcloud/application_default_credentials.json`. If your gcloud config lives elsewhere, `CLOUDSDK_CONFIG` is respected.

## 7. List the projects in config

```yaml
gcp:
  projects: [acme-prod, acme-staging]
  member_domains: [acme.com]   # your own email domains; defaults to google.domain
```

Name production projects, shared with AWS accounts, under `production` (see [aws.md](aws.md#5-say-what-is-production)):

```yaml
production: [acme-prod]
```

A Cloud SQL instance labelled `env` or `environment` = `prod` or `production` is production too.

The same list marks each project, and each IAM binding in it, `production`, which the people facts show next to each role someone holds. With nothing named under `production`, every project counts as production, and the facts say so.

Who holds each role: a `user:` member is matched to a person by email, and a `group:` member through its Google group's members, which the Google Workspace connection reads (see [google-workspace.md](google-workspace.md)). A service account with admin or delete power needs an owner in `.firedrill/owners.yaml`:

```yaml
- principal: ci@acme-prod.iam.gserviceaccount.com
  owner: "@acme/platform"    # a team or role, never an email
  note: deploys the API
```

### What the backups drill can see

Cloud SQL keeps automated backups in the instance's own project; the API has no setting for a copy in another project. So a Cloud SQL database reads `separate_copy: unknown`, and the drill warns, until you declare where its copy lives, such as a scheduled export to a bucket in another project, in `.firedrill/backups.yaml`:

```yaml
- database: orders                      # the instance name
  copy_location: nightly export to gs://acme-backup-vault in acme-backup
  owner: "@acme/platform"
  verified: 2026-11-01
```

Retention is the number of daily backups kept (`retainedBackups`), read as days. Read replicas are judged through their primary; a replica is not a backup.

### What the restore drill can see

`recovery/restore-exercised` asks that each production database was restored from its backups within `recovery.restore_days` (90 unless set in `config.yaml`). Firedrill reads each instance's operations (`operations.list`, GET only) and keeps the latest that finished with no error:

- **`CLONE`** runs on the instance being cloned, so a clone counts for that instance. It shows the data can be brought up elsewhere; the operation does not say whether it was a point-in-time clone.
- **`RESTORE_VOLUME`** restores a backup into the instance it runs on, usually a scratch instance. The operation does not name the backup it came from, so it counts for every database in that project, and the result says so.
- Imports, exports and backups are not restores. A failed or unfinished operation does not count.

Google does not document how long Cloud SQL keeps operations, so an older restore, or one done another way, goes in `.firedrill/restores.yaml`:

```yaml
- database: orders                      # the instance name
  restored: 2026-10-20
  by: platform-team                     # a team or role, never an email
  note: restored last night's backup into orders-restore-test; row counts matched
```

If an instance's operations cannot be read and nothing is declared, the drill warns rather than passing or failing. Only the newest 5,000 operations of an instance are read. AWS restores are not read (out of scope for now); an AWS database passes only with a restores.yaml entry.

## 8. Check it

```bash
firedrill connect gcp
```

You should see `Connected. Read N items`. Then:

```bash
firedrill run
```

## If something goes wrong

| What you see | Why, and what to do |
| --- | --- |
| HTTP 403 on a project or bucket right after step 4 | Role grants can take a few minutes to apply. Wait, then rerun. One unreadable bucket gives WARN for its project; one unreadable project gives ERROR for that project only |
| `gcloud` refuses `--scopes` without `cloud-platform` | gcloud's own login always needs the full scope. That's why Firedrill uses the reader: its roles keep it to reads, whatever the scope |
| `ACCESS_TOKEN_SCOPE_INSUFFICIENT` | You're on a Firedrill older than v0.1.0; upgrade |
| A project shows ERROR `could not read` | The reader has no roles there, or the project ID is wrong. Repeat step 4 for it |
| `Note: the Cloud SQL Admin API is not turned on in acme-a, acme-b, so there is no Cloud SQL instance there to read` | Nothing to do. The Service Usage API said the API is off in those projects themselves, so they hold no Cloud SQL instance; with every project like this the recovery drills give N/A |
| `Read only in part: Cloud SQL could not be read in acme-a, acme-b, where the Cloud SQL Admin API is on: turn on sqladmin.googleapis.com in …` | The API is on in those projects but off in the project calls are billed to. Turn on `sqladmin.googleapis.com` in `HOME_PROJECT` (step 2). The recovery drills give WARN, not ERROR, until then |
| `Read only in part: Cloud SQL could not be read in acme-a, and whether it is used there could not be told: …` | Turn on `sqladmin.googleapis.com` in `HOME_PROJECT`, or grant the reader Viewer on the project, which includes `serviceusage.services.get`, so Firedrill can tell whether the API is off there. The recovery drills give WARN |
| `Read only in part: Cloud SQL could not be read in acme-a: the reader may not list its instances; …` | Grant the reader Cloud SQL Viewer (`roles/cloudsql.viewer`), which Viewer includes, on the project (step 4). The recovery drills give WARN |
| `could not read Cloud SQL in acme-a: HTTP 5…` or a network error | A genuine failure: the backup drills give ERROR. Rerun |
| `Not connected yet: connect gcp` | No projects in config, or no login file. Do steps 6 and 7 |

## What Firedrill calls

Every call is a GET, including `GET https://sqladmin.googleapis.com/v1/projects/{project}/instances` and `GET https://sqladmin.googleapis.com/v1/projects/{project}/operations?instance={instance}` for Cloud SQL, `GET https://serviceusage.googleapis.com/v1/projects/{project}/services/sqladmin.googleapis.com` only when a Cloud SQL read says the API is not turned on (the guard allows no other path on that host, since it also turns services on and off; [services.get](https://docs.cloud.google.com/service-usage/docs/reference/rest/v1/services/get) needs `serviceusage.services.get`, which Viewer includes), and `GET https://iam.googleapis.com/v1/{projects/{project} or organizations/{org}}/roles/{role}` once per custom role a binding names, plus four exact POSTs the guard allows: the token exchange, minting the reader's token, `getIamPolicy` on each listed project, which only reads, and, only after a diff, `https://logging.googleapis.com/v2/entries:list`, which also only reads (filtered to one listed project's Admin Activity log, `SetIamPolicy` and the window between the two runs; at most 50 audit calls a run across every source). `firedrill run --dry-run` lists them all.

## In CI

The weekly workflow can't use your `gcloud` login. Today GCP in CI needs a key file for the reader, in `FIREDRILL_GCP_CREDENTIALS`. That's a long-lived key, which `gcp/sa-keys-short-lived` will flag after 90 days, so rotate it or run GCP drills from a laptop. Keyless CI login through Workload Identity Federation isn't supported yet.
