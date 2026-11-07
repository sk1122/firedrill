# Connect AWS

AWS unlocks `access/no-dormant-admins` (the AWS half), `agent/no-destructive-tokens`, and `access/no-unused-aws-keys`.

Firedrill reads IAM in each account: users, roles, groups, their policies, access keys and when they were last used. Every call is checked by action name against a fixed list, so it can't read secrets, objects or anything else, even if the credential allows it.

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
      "iam:GetCredentialReport"
    ],
    "Resource": "*"
  }]
}
```

`GenerateCredentialReport` creates IAM's own credential report, which is how AWS exposes when each password was last used. It changes nothing in your account.

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

## 5. Check it

```bash
firedrill connect aws
```

## Limits

Firedrill reads the Allow statements in policy documents. It doesn't account for Deny statements, permission boundaries or service control policies yet, so it can overstate what a user or role can do: a FAIL may be a false alarm where a Deny or boundary blocks the action. It won't miss access an Allow grants.
