# Domains: DNS, certificate logs and web checks

The Doors drills look at your public surface: CNAMEs pointing at deleted hosts, hosts in public certificates with no owner, public API docs and source maps, credentials in public JavaScript, and scripts loaded from other hosts with no integrity hash. They use public DNS, the public [crt.sh](https://crt.sh) certificate search, and plain GETs to your own hosts.

Firedrill only looks at domains you **prove you own**, so it can't be pointed at someone else's site.

## 1. List your domains

```yaml
domains: [acme.com]
```

## 2. Prove you own each one

```bash
firedrill verify-domain acme.com
```

It prints a TXT record to publish, at `_firedrill.acme.com`. The value comes from your org's salt, so every machine with the same salt agrees on it. Add the record at your DNS provider, wait a few minutes, then run the same command again until it says `Verified.`

Firedrill checks the record at the start of every run. Remove it, and the domain's drills stop.

## 3. Name owners for your hosts

`doors/every-host-owned` fails for any host in your public certificates that has no owner. List them in `.firedrill/hosts.yaml`:

```yaml
- host: api.acme.com
  owner: "@platform-team"
- host: status.acme.com
  owner: "@sre"
```

## What it sends

- **DNS:** ordinary lookups through your system's resolver.
- **Certificate logs:** one search per verified domain on crt.sh, cached for 24 hours, because crt.sh is public and rate-limited. If crt.sh is down, the drill gives WARN.
- **Web:** GET requests only, to hosts under verified domains, at most 20 per host per drill and 500 per run, identified as `firedrill/<version>`. It keeps only headers and the first and last few kilobytes of each reply.

## What is scanned

Two drills read the replies above and send nothing of their own:

- **`doors/no-live-key-in-public-bundle`** scans each host's home page, the same-host JavaScript bundles named in the first 4 KB of that page, and each bundle's source map (its original sources), up to 20 MB each, for credentials. A finding is kept as a fingerprint, its kind, where it was found and, for a Google Cloud service account key file, its key ID; never the value, and the key is never tried. With Google Cloud connected, a key ID that matches a service account key Firedrill read is live unless that key is disabled. A live match fails, and so does any server-side credential (a private key, a service account key, a Stripe secret key, a database URL with a password, a personal token), live or not. A browser key, such as a Google API key or a Stripe publishable key, warns until you check it is restricted. AWS access key IDs are recorded but not matched (out of scope for now).
- **`doors/third-party-scripts-pinned`** lists the scripts each home page loads from other hosts (`<script src>`, and `<link rel="modulepreload">` or `rel="preload" as="script"`), and fails any from a host you don't own (not under a verified domain or in `hosts.yaml`) that has no `integrity` hash. Only home pages are read; nothing is crawled, and the scripts themselves are never requested. A script URL is kept as its host and a fingerprint, with its path when the path does not look like a token; never its query.

To leave a host out of web checks:

```yaml
web:
  exclude_hosts: [legacy.acme.com]
```

## Check it

```bash
firedrill connect dns
```
