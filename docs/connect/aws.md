# Connect AWS

AWS unlocks `access/no-dormant-admins` (the AWS half), `agent/no-destructive-tokens`, `access/no-unused-aws-keys` and, with or without Google Cloud, `recovery/backups-separate-and-retained`.

Firedrill reads IAM in each account: users, roles, groups, their policies, access keys and when they were last used. It also reads RDS: each database's automated backup retention, deletion protection and tags, and the AWS Backup copy jobs that copied it somewhere. Every call is checked by action name against a fixed list, so it can't read secrets, objects, snapshots' contents or anything else, even if the credential allows it.

## 1. Create a read policy

In each account, create this IAM policy, for example named `FiredrillRead`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:GetAccountAuthorizationDetails",
      "iam:GetAccessKeyLastUsed",
      "iam:ListAccessKeys",
      "iam:GenerateCredentialReport",
      "iam:GetCredentialReport",
      "rds:DescribeDBInstances",
      "rds:DescribeDBClusters",
      "backup:ListCopyJobs"
    ],
    "Resource": "*"
  }]
}
```

`GenerateCredentialReport` creates IAM's own credential report, which is how AWS exposes when each password was last used. It changes nothing in your account.

The last three are for backups. Without them the IAM drills still run, and only the backups drill gives ERROR (no `rds:` actions) or WARN (no `backup:ListCopyJobs`, so whether a copy exists elsewhere is unknown).

## 2. Give it to a role you can assume

Attach the policy to a role, for example `FiredrillReader`, that your own identity may assume. With IAM Identity Center, use a permission set with this policy instead.

## 3. Add a profile per account

In `~/.aws/config`:

```ini
[profile firedrill-prod]
role_arn = arn:aws:iam::111111111111:role/FiredrillReader
source_profile = default
```

Or, with IAM Identity Center:

```ini
[profile firedrill-prod]
sso_session = acme
sso_account_id = 111111111111
sso_role_name = FiredrillRead
```

Firedrill uses the AWS SDK's normal credential chain for each profile, so anything the AWS CLI accepts works.

## 4. List the accounts in config

```yaml
aws:
  accounts:
    - profile: firedrill-prod
    - profile: firedrill-staging
  break_glass:   # emergency roles that are allowed to sit unused
    - arn:aws:iam::111111111111:role/BreakGlass
```

AWS-reserved and service-linked roles are left out automatically.

Databases are read in each region you list, or else in each profile's own region. Firedrill never lists all regions on its own:

```yaml
aws:
  regions: [us-east-1, eu-west-1]
```

## 5. Say what is production

The backups drill judges production databases. Name production accounts (by ID or profile) and Google Cloud projects in one list:

```yaml
production: ["111111111111", firedrill-prod, acme-prod]
```

A database tagged `env` or `environment` = `prod` or `production` is production too. With nothing named and nothing tagged, every database is judged, and the drill's reason says so. A repo listed there as `org/repo` (see [github.md](github.md#which-repos-deploy-to-production)) names no account or project, so it does not count here.

Automated backups must be kept at least 7 days; set `recovery.min_retention_days` to change it.

### What the backups drill can see

- **A copy in another account** is a completed AWS Backup copy job, in the last 35 days, into a vault whose ARN names a different account. That reads `separate_copy: yes`.
- **No such job** reads `no`, which fails: a copy in the same account, or cross-Region automated backup replication, dies with the account's credentials.
- **Copy jobs unreadable** reads `unknown` and warns.
- Copies made another way, such as snapshots shared to and copied by a backup account, can't be seen from this account. Declare them in `.firedrill/backups.yaml`:

```yaml
- database: orders                       # the DB instance or cluster identifier
  copy_location: snapshot copies in 444455556666, us-west-2
  owner: "@acme/platform"                # a handle or team, never an email
  verified: 2026-11-01                   # when someone last restored or checked one
```

Aurora and other clusters are judged on the cluster; read replicas through their source.

## 6. Check it

```bash
firedrill connect aws
```

## Limits

Firedrill reads the Allow statements in policy documents. It doesn't account for Deny statements, permission boundaries or service control policies yet, so it can overstate what a user or role can do: a FAIL may be a false alarm where a Deny or boundary blocks the action. It won't miss access an Allow grants.
