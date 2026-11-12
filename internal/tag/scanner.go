package tag

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/secrets"
)

// exemptKeys are known structured fields: graph IDs, hashes and AWS access key
// IDs. An access key ID is an identifier, never the secret. A key name alone
// never exempts a value: a string under one of these keys is left alone only if
// it has a safe shape (see safeShape), and is scanned like any other otherwise.
var exemptKeys = map[string]bool{
	"id": true, "hash": true, "key_id": true, "read": true, "keys": true, "credentials": true,
	"shared_prod_staging": true, "shared_credentials": true, "workspace": true, "project": true,
}

// nameKeys hold names, such as the secrets a workflow references. A value under
// one is left alone only if it is shaped like a name (see secretName).
var nameKeys = map[string]bool{"secrets": true, "cloud_key_secrets": true}

// packageKeys hold package, image and command names, such as an MCP server's
// package or a dependency with an install script. A value under one is left
// alone only if it is shaped like a package name (see packageName).
var packageKeys = map[string]bool{"package": true, "command": true, "install_scripts": true, "new_install_scripts": true}

// loginKeys hold GitHub logins, which facts carry for conditions and evidence.
// A value under one is left alone only if it is shaped like a login (see
// githubLogin).
var loginKeys = map[string]bool{"login": true}

var (
	// secretNameRe is a GitHub secret or variable name as the workflow parser
	// writes it: upper-case words joined by underscores.
	secretNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$|^inherit$`)
	// hmacHex is what graph.Hasher.Sum writes.
	hmacHex = regexp.MustCompile(`^[0-9a-f]{32}$`)
	// hashedSecret is "secret:" and a Sum, as written for a credential.
	hashedSecret = regexp.MustCompile(`^secret:[0-9a-f]{32}$`)
	// varRef is "var:" and an environment variable name.
	varRef = regexp.MustCompile(`^var:[A-Za-z_][A-Za-z0-9_]*$`)
	// accessKeyID is an AWS access key ID, an identifier and never the secret.
	accessKeyID = regexp.MustCompile(`^(AKIA|ASIA)[0-9A-Z]{16}$`)
	// graphID is a node ID: a known source prefix and a path-like remainder with
	// no spaces, so a secret that merely starts with a prefix still has to pass
	// the segment check below.
	graphID = regexp.MustCompile(`^(api-doc|aws|codeowners|config-host|config-app|config-backup|config-ai-key|config|dns-cname|dns|domain|file|gcp|github|google|host|manifest|mcp|person|repo|scan|secret|semgrep|source-map|web|agent|tf|anthropic|openai):[A-Za-z0-9._/@:#=+~-]+$`)
	// providerID is an AI provider's object ID: a type word, an underscore and
	// an opaque ID, such as apikey_01..., wrkspc_01..., user_01... (Anthropic)
	// or key_..., proj_..., svc_acct_... (OpenAI). It names a key, workspace or
	// person and is never the secret; a provider's secret starts sk-.
	providerID = regexp.MustCompile(`^(apikey|wrkspc|user|svac|key|proj|svc_acct|org)_[0-9A-Za-z]{4,48}$`)
	// packageNameRe is an npm, PyPI or image name, or a command: no spaces,
	// quotes or = signs.
	packageNameRe = regexp.MustCompile(`^[A-Za-z0-9@.][A-Za-z0-9._~/@:+-]*$`)
	packageSplit  = regexp.MustCompile(`[-._/@:~+]`)
	// hexRun is a long hex word with a digit, as in a UUID or a token, which a
	// package name never has.
	hexRun = regexp.MustCompile(`^[0-9a-fA-F]{8,}$`)
	// loginRe is a GitHub login: letters, digits and single hyphens, neither
	// first nor last, or an app's bot account, which ends in [bot].
	loginRe  = regexp.MustCompile(`^[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*(?:\[bot\])?$`)
	segSplit = regexp.MustCompile(`[/:.@#=+~]`)
)

// mixedClass reports a string with a digit, a capital and a lowercase letter,
// which a name or a path rarely has at length.
func mixedClass(s string) bool {
	var d, u, l bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			d = true
		case r >= 'A' && r <= 'Z':
			u = true
		case r >= 'a' && r <= 'z':
			l = true
		}
	}
	return d && u && l
}

// hiddenSecret reports a segment of an otherwise safe-looking ID that is itself
// a secret. An AWS access key ID is an identifier, so it is not one.
func hiddenSecret(rest string) bool {
	for _, seg := range segSplit.Split(rest, -1) {
		if accessKeyID.MatchString(seg) || hmacHex.MatchString(seg) || providerID.MatchString(seg) {
			continue
		}
		if secrets.LooksLikeSecret(seg) && mixedClass(seg) {
			return true
		}
	}
	return false
}

// secretName reports a name such as ANTHROPIC_API_KEY. A long one has the
// entropy of a secret, so it is told apart by shape, and a word between the
// underscores that is itself secret-like still fails.
func secretName(v string) bool {
	if !secretNameRe.MatchString(v) {
		return false
	}
	for _, part := range strings.Split(v, "_") {
		if secrets.LooksLikeSecret(part) {
			return false
		}
	}
	return true
}

// packageName reports a name such as @acme/mcp-fs, ghcr.io/acme/mcp or
// node-pre-gyp-github. A long one has the entropy of a secret, so it is told
// apart by shape: every word between its separators must look like a word,
// so a UUID or a token, even with a prefix, still fails.
func packageName(v string) bool {
	if !packageNameRe.MatchString(v) || secrets.HasKnownPrefix(v) {
		return false
	}
	for _, part := range packageSplit.Split(v, -1) {
		if secrets.LooksLikeSecret(part) || (hexRun.MatchString(part) && strings.ContainsAny(part, "0123456789")) {
			return false
		}
	}
	return true
}

// githubLogin reports a login such as ana-acme or x7k2q9vz4m8w. GitHub caps a
// login at 39 characters. A random-looking login is still a login, so only a
// word with a known secret prefix, one with the mixed case and digits of a
// token at secret length, or a long hex run, fails.
func githubLogin(v string) bool {
	name := strings.TrimSuffix(v, "[bot]")
	if len(name) > 39 || !loginRe.MatchString(v) || secrets.HasKnownPrefix(v) {
		return false
	}
	for _, part := range strings.Split(name, "-") {
		if (secrets.LooksLikeSecret(part) && mixedClass(part)) || (len(part) >= 20 && hexRun.MatchString(part) && strings.ContainsAny(part, "0123456789")) {
			return false
		}
	}
	return true
}

// safeShape reports a string whose whole value is a known structured field:
// a hash, a hashed secret, a variable reference, an access key ID, an AI
// provider's object ID or a graph ID.
func safeShape(v string) bool {
	switch {
	case hmacHex.MatchString(v), hashedSecret.MatchString(v), accessKeyID.MatchString(v), providerID.MatchString(v):
		return true
	case varRef.MatchString(v):
		return !hiddenSecret(strings.TrimPrefix(v, "var:"))
	case graphID.MatchString(v):
		return !hiddenSecret(v[strings.Index(v, ":")+1:])
	}
	return false
}

// ScanValue replaces any string that looks like a secret with its hash, and
// returns a note for each. A hit never stops a run and never changes a verdict.
func ScanValue(v any, h graph.Hasher, where string, notes *[]string) any {
	return scanValue(v, h, where, notes, "")
}

// scanValue scans v, found under key. Under an exempt key, strings of a safe
// shape pass; under a name key, strings shaped like a name pass.
func scanValue(v any, h graph.Hasher, where string, notes *[]string, key string) any {
	exempt := exemptKeys[key]
	switch val := v.(type) {
	case string:
		if (exempt && safeShape(val)) || (nameKeys[key] && secretName(val)) || (packageKeys[key] && packageName(val)) ||
			(loginKeys[key] && githubLogin(val)) {
			return val
		}
		// LooksLikeSecret skips values with separators, so under an exempt key a
		// secret with a prefix is also looked for by segment.
		if secrets.LooksLikeSecret(val) || (exempt && hiddenSecret(val)) {
			*notes = append(*notes, fmt.Sprintf("%s looked like a secret and was replaced with its hash", where))
			return "secret:" + h.Sum(val)
		}
		return val
	case []any:
		out := make([]any, len(val))
		for i, x := range val {
			out[i] = scanValue(x, h, where, notes, key)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, x := range val {
			out[k] = scanValue(x, h, where+"."+k, notes, k)
		}
		return out
	}
	return v
}

// ScanTag scans a tag's evidence in place before it is written.
func ScanTag(t *Tag, h graph.Hasher) {
	var notes []string
	for alias, v := range t.Evidence.Facts {
		t.Evidence.Facts[alias] = ScanValue(v, h, alias, &notes)
	}
	// Reason and condition results are free text derived from evidence, so an
	// error message could echo a value.
	t.Header.Reason = scanText(t.Header.Reason, h, "reason", &notes)
	for i := range t.Header.Conditions {
		t.Header.Conditions[i].Result = scanText(t.Header.Conditions[i].Result, h, fmt.Sprintf("conditions[%d].result", i), &notes)
	}
	t.Header.ScannerNotes = append(t.Header.ScannerNotes, notes...)
}

// ScanSnapshot scans a snapshot's attributes before it is written, returning how
// many values it replaced.
func ScanSnapshot(s *graph.Snapshot, h graph.Hasher) int {
	var notes []string
	for i := range s.Nodes {
		if s.Nodes[i].Attrs == nil {
			continue
		}
		s.Nodes[i].Attrs, _ = ScanValue(s.Nodes[i].Attrs, h, string(s.Nodes[i].ID), &notes).(map[string]any)
	}
	return len(notes)
}

// ScanDiff scans a diff before it is stored or shown. Summaries and skip notes
// are free text and before and after values are attribute values, so either
// could carry a value. Node IDs are scanned as IDs: a safe-shaped ID passes
// untouched, so the diff still names the node it means.
func ScanDiff(d *graph.DiffResult, h graph.Hasher) int {
	var notes []string
	id := func(v graph.ID, where string) graph.ID {
		s, _ := scanValue(string(v), h, where, &notes, "id").(string)
		return graph.ID(s)
	}
	for i := range d.Changes {
		c := &d.Changes[i]
		where := fmt.Sprintf("changes[%d]", i)
		c.Subject = id(c.Subject, where+".subject")
		if c.Edge != nil {
			c.Edge.From, c.Edge.To = id(c.Edge.From, where+".edge.from"), id(c.Edge.To, where+".edge.to")
		}
		c.Summary = scanText(c.Summary, h, where+".summary", &notes)
		if c.Before != nil {
			c.Before = scanValue(c.Before, h, where+".before", &notes, c.Attr)
		}
		if c.After != nil {
			c.After = scanValue(c.After, h, where+".after", &notes, c.Attr)
		}
	}
	for i, s := range d.Skipped {
		d.Skipped[i] = scanText(s, h, fmt.Sprintf("skipped[%d]", i), &notes)
	}
	return len(notes)
}

// scanText scans free text word by word, and replaces each word that looks like
// a secret with its hash. A whole-string test would miss a secret inside a
// sentence, because LooksLikeSecret skips values with spaces.
func scanText(text string, h graph.Hasher, where string, notes *[]string) string {
	if text == "" {
		return text
	}
	words := strings.Fields(text)
	changed := false
	for i, w := range words {
		w = strings.Trim(w, "\"'`()[]{}<>,;")
		if w == "" || safeShape(w) || !secrets.LooksLikeSecret(w) {
			continue
		}
		*notes = append(*notes, fmt.Sprintf("%s looked like a secret and was replaced with its hash", where))
		words[i] = strings.Replace(words[i], w, "secret:"+h.Sum(w), 1)
		changed = true
	}
	if !changed {
		return text
	}
	return strings.Join(words, " ")
}
