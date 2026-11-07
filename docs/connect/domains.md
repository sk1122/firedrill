# Domains: DNS, certificate logs and web checks

The Doors drills look at your public surface: CNAMEs pointing at deleted hosts, hosts in public certificates with no owner, public API docs and source maps. They use public DNS, the public [crt.sh](https://crt.sh) certificate search, and plain GETs to your own hosts.

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

To leave a host out of web checks:

```yaml
web:
  exclude_hosts: [legacy.acme.com]
```

## Check it

```bash
firedrill connect dns
```
