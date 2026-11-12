package web

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/secrets"
)

// Script is one script a page loads, as its tag gives it.
type Script struct {
	URL         string // as written, resolved against the page
	Host        string // the script's hostname, lower case
	Path        string // its path without the query
	Integrity   bool   // an integrity attribute with a sha256, sha384 or sha512 hash
	CrossOrigin bool   // a crossorigin attribute, which a cross-origin integrity check needs
}

var (
	htmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)
	// openTag finds a script or link start tag. Attribute values may hold >,
	// so quoted values are matched whole.
	openTag = regexp.MustCompile(`(?is)<(script|link)\b((?:[^>"']|"[^"]*"|'[^']*')*)>`)
	attrRe  = regexp.MustCompile(`([^\s"'=<>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+)))?`)
	sriHash = regexp.MustCompile(`^sha(256|384|512)-[A-Za-z0-9+/_-]+={0,2}$`)
)

func attrs(s string) map[string]string {
	out := map[string]string{}
	for _, m := range attrRe.FindAllStringSubmatch(s, -1) {
		name := strings.ToLower(m[1])
		if _, dup := out[name]; dup {
			continue // the first of a repeated attribute wins, as in a browser
		}
		out[name] = strings.TrimSpace(m[2] + m[3] + m[4])
	}
	return out
}

func hasWord(list, word string) bool {
	for _, w := range strings.Fields(strings.ToLower(list)) {
		if w == word {
			return true
		}
	}
	return false
}

// PageScripts lists the scripts a page loads from <script src> tags and from
// <link rel="modulepreload"> or <link rel="preload" as="script">, resolved
// against the page. Commented-out tags are left out, and so are data: and
// blob: sources.
func PageScripts(host, page, html string) []Script {
	base, err := url.Parse("https://" + host + page)
	if err != nil {
		return nil
	}
	html = htmlComment.ReplaceAllString(html, "")
	var out []Script
	for _, m := range openTag.FindAllStringSubmatch(html, -1) {
		a := attrs(m[2])
		ref := ""
		switch strings.ToLower(m[1]) {
		case "script":
			ref = a["src"]
		case "link":
			rel := a["rel"]
			if hasWord(rel, "modulepreload") || (hasWord(rel, "preload") && strings.EqualFold(a["as"], "script")) {
				ref = a["href"]
			}
		}
		if ref == "" {
			continue
		}
		u, err := base.Parse(ref)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			continue
		}
		sc := Script{URL: u.String(), Host: strings.ToLower(u.Hostname()), Path: u.EscapedPath()}
		for _, h := range strings.Fields(a["integrity"]) {
			if sriHash.MatchString(h) {
				sc.Integrity = true
			}
		}
		_, sc.CrossOrigin = a["crossorigin"]
		out = append(out, sc)
	}
	return out
}

// maxScriptPath is the most of a script's path kept.
const maxScriptPath = 200

// safePath returns a script's path for the record, or "" when a part of it
// looks like a credential, since a path can carry a token as well as a query.
func safePath(p string) string {
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return strings.ContainsRune("/._-~", r) }) {
		if secrets.LooksLikeSecret(seg) || secrets.HasKnownPrefix(seg) {
			return ""
		}
	}
	if len(p) > maxScriptPath {
		p = p[:maxScriptPath]
	}
	return p
}

// writeScripts writes one page_script node for each script the page loads
// from another host. A script on the page's own host is the page's own code,
// and is not written. The full URL is kept only as a fingerprint, since its
// query can carry a token.
func writeScripts(ps *pageScan, host, page, html string) {
	scripts := PageScripts(host, page, html)
	sort.SliceStable(scripts, func(i, j int) bool { return scripts[i].URL < scripts[j].URL })
	for _, sc := range scripts {
		if strings.EqualFold(sc.Host, host) {
			continue
		}
		hash := ps.s.Hasher.Sum(sc.URL)
		id := graph.ID("page-script:" + host + page + "@" + hash)
		if ps.seen[id] {
			continue
		}
		ps.seen[id] = true
		ps.out.Node(graph.Node{ID: id, Kind: graph.KindPageScript, Source: "web", SeenAt: ps.s.Now,
			Attrs: map[string]any{"domain": ps.domain, "host": host, "page": page, "script_host": sc.Host,
				"script_path": safePath(sc.Path), "script_hash": hash, "has_integrity": sc.Integrity,
				"crossorigin": sc.CrossOrigin, "owned": connector.HostOwned(sc.Host, ps.s)}})
	}
}
