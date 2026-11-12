package secrets

import (
	"regexp"
	"sort"
	"strings"
)

// ClientSide is the one table of credential kinds that are built to be
// shipped to a browser, or that web pages commonly embed. One found in a public
// JavaScript bundle is not a leak by itself, though it still has to be
// restricted. Every kind not listed is a server-side credential, which a public
// bundle must never hold.
var ClientSide = map[string]bool{
	// AIza…: a Google browser API key, as in Maps or a Firebase web config. It
	// identifies a project and is limited by referrer and API restrictions,
	// not kept secret.
	"google_api_key": true,
	// pk_live_…: a Stripe publishable key, made for Stripe.js in the browser.
	"stripe_publishable": true,
	// rzp_live_…: a Razorpay key ID, which Razorpay Checkout needs in the
	// page. The key secret that goes with it is never shown in this shape.
	"razorpay_live": true,
	// A credential-named variable with a key or token name, such as a site
	// key or a public search key. The name alone cannot say whether it is
	// meant to be public. A name with SECRET, PASSWORD or PRIVATE is
	// generic_secret instead, which is server-side.
	"generic": true,
}

// IsClientSide says whether a kind is one a web page may carry.
func IsClientSide(kind string) bool { return ClientSide[kind] }

// publicPrefixes are kinds looked for only in public web content, on top of
// the shared ones. A browser key is normal in a page and in a repo, so the repo
// scanner leaves these out.
var publicPrefixes = []prefixKind{
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"stripe_publishable", regexp.MustCompile(`\bpk_live_[0-9A-Za-z]{10,}\b`)},
	// A database URL with a user and password in it.
	{"database_url", regexp.MustCompile(`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?)://[^\s:/@"'\x60]+:[^\s@/"'\x60$]{6,}@[^\s"'\x60/]+`)},
}

var (
	// pemKey is a private key in PEM form, with real or escaped newlines, as a
	// JSON key file or a JavaScript string holds it.
	pemKey = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[A-Za-z0-9+/=\s\\]{64,}?-----END [A-Z ]*PRIVATE KEY-----`)
	// privateKeyID is a service account key file's private_key_id, quoted or
	// not, with escaped quotes allowed: the key's ID, never the secret.
	privateKeyID = regexp.MustCompile(`private_key_id\\{0,3}["']?\s*:\s*\\{0,3}["']([0-9a-f]{40})\\{0,3}["']`)
	escapedLine  = regexp.MustCompile(`\\+[nr]`)
	pemSpace     = regexp.MustCompile(`[\s\\]+`)
)

// keyWindow is how far from a private_key_id a private key may sit and still
// be read as the same service account key file.
const keyWindow = 4096

// ScanPublic finds credentials in public web content, such as a JavaScript
// bundle or a source map's sources: every kind Scan finds, plus Google browser
// keys, Stripe publishable keys, database URLs with a password, private keys,
// and Google Cloud service account keys, whose KeyID is the key file's
// private_key_id. A credential-named variable is generic_secret when its name
// says secret, password or private, and generic otherwise. Values are held in
// memory only, to be hashed.
func ScanPublic(text string) []Finding {
	var out []Finding
	pems := pemKey.FindAllStringIndex(text, -1)
	used := make([]bool, len(pems))
	lineAt := func(i int) int { return strings.Count(text[:i], "\n") + 1 }
	for _, m := range privateKeyID.FindAllStringSubmatchIndex(text, -1) {
		id := text[m[2]:m[3]]
		best := -1
		for j, p := range pems {
			if used[j] || p[0] > m[0]+keyWindow || p[1] < m[0]-keyWindow {
				continue
			}
			if best < 0 || abs(p[0]-m[0]) < abs(pems[best][0]-m[0]) {
				best = j
			}
		}
		// An ID with no key near it is not a credential.
		if best < 0 {
			continue
		}
		used[best] = true
		out = append(out, Finding{Kind: "gcp_sa_key", Line: lineAt(m[0]), Value: normPEM(text[pems[best][0]:pems[best][1]]), KeyID: id})
	}
	for j, p := range pems {
		if !used[j] {
			out = append(out, Finding{Kind: "private_key", Line: lineAt(p[0]), Value: normPEM(text[p[0]:p[1]])})
		}
	}
	// Blank the keys, keeping line breaks, so no part of one is found again.
	if len(pems) > 0 {
		b := []byte(text)
		for _, p := range pems {
			for i := p[0]; i < p[1]; i++ {
				if b[i] != '\n' {
					b[i] = ' '
				}
			}
		}
		text = string(b)
	}
	for _, f := range scanLines(text, publicPrefixes, nil, genericKind) {
		if f.Kind == "database_url" && placeholder(f.Value) {
			continue
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// genericKind names a credential-named variable's value by its name.
func genericKind(name string) string {
	n := strings.ToUpper(name)
	if strings.Contains(n, "SECRET") || strings.Contains(n, "PASSWORD") || strings.Contains(n, "PRIVATE") {
		return "generic_secret"
	}
	return "generic"
}

// normPEM drops line breaks, escapes and spaces, so one key reads the same
// whether a file or a JavaScript string holds it.
func normPEM(s string) string {
	return pemSpace.ReplaceAllString(escapedLine.ReplaceAllString(s, ""), "")
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
