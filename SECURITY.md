# Security

Firedrill holds read credentials to sensitive systems, so security reports get priority.

## Reporting a vulnerability

Report it privately through [GitHub's private vulnerability reporting](https://github.com/sk1122/firedrill/security/advisories/new). Please don't open a public issue.

Include what you found, how to reproduce it, and what an attacker could do with it. You'll get an acknowledgement within three working days, and a fix or a plan within 30 days. Reporters are credited in the advisory unless they ask not to be.

## In scope

- Any way Firedrill could write to, change or delete something in a connected system.
- Any way past the read-only guard: a call outside its allowed methods, hosts, URLs or AWS actions.
- A secret or personal data reaching a record, the board, a log, an issue or the network in clear text.
- A drill file or hub drill that can run code, read files outside its facts, or exhaust a run.
- Weaknesses in the record chain that let a changed record verify as untouched.

## Supported versions

Fixes go into the latest release.
