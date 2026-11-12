// Package web makes passive GET checks on verified domains only.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/secrets"
)

// Request limits.
const (
	PerHostLimit  = 20
	TotalLimit    = 500
	headBytes     = 4 << 10
	tailBytes     = 1 << 10
	maxBodyToRead = 20 << 20
)

// APIDocPaths is the approved list of paths checked on each host.
var APIDocPaths = []string{
	"/swagger.json", "/swagger-ui/", "/swagger-ui.html", "/openapi.json", "/openapi.yaml",
	"/api-docs", "/v2/api-docs", "/v3/api-docs", "/redoc", "/config.json", "/env.js", "/env.json", "/.env",
}

// Connector makes the checks.
type Connector struct {
	connector.Base
	Scheme string
}

// New returns the connector.
func New() *Connector {
	return &Connector{ConnectorName: "web", Limit: 5, Burst: 5, Scheme: "https"}
}

func init() { connector.Register(New()) }

// Collections lists what it checks.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{Name: "doors",
		Nodes: []string{graph.KindSourceMap, graph.KindAPIDoc, graph.KindWebResponse, graph.KindPublicSecret, graph.KindPageScript},
		Calls: []string{
			"GET each API doc path on hosts under verified domains, at most 20 per host and drill, 500 in total",
			"GET each host's home page, its JavaScript bundles and their source maps, within the same limits",
			"No further call: the home page, bundles and maps above are scanned for credentials, and the home page's script tags are listed; a script on another host is never requested",
		}}}
}

// Available is true when a domain is verified.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if len(s.VerifiedDomains) == 0 {
		return false, "verify-domain"
	}
	return true, ""
}

func (c *Connector) client(s connector.Scope) *http.Client {
	b := c.Base
	verified := s.VerifiedDomains
	b.Policy = connector.Policy{HostAllowed: func(host string) bool {
		for _, d := range verified {
			if connector.UnderDomain(host, d) {
				return true
			}
		}
		return false
	}}
	cl := b.HTTP(s.Log)
	// A verified host may redirect elsewhere. That is not followed, so it can't
	// reach an unverified host.
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return cl
}

type response struct {
	status  int
	ctype   string
	headers http.Header
	head    string
	tail    string
	// body is the whole body, kept only when asked for, up to headBytes and
	// maxBodyToRead; truncated says the body was longer.
	body      string
	truncated bool
}

// budget counts requests for one drill.
type budget struct {
	total   atomic.Int64
	perHost map[string]*atomic.Int64
	over    atomic.Int64
}

func (b *budget) take(host string) bool {
	h := b.perHost[host]
	if h == nil {
		return false
	}
	if h.Add(1) > PerHostLimit || b.total.Add(1) > TotalLimit {
		b.over.Add(1)
		return false
	}
	return true
}

// get makes one GET. With keep, the whole body is kept for the secret scan and
// the script list; it is the same request and the same bounded read.
func (c *Connector) get(ctx context.Context, cl *http.Client, host, p string, keep bool) (*response, error) {
	u := c.Scheme + "://" + host + p
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "firedrill/"+connector.Version)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out := &response{status: resp.StatusCode, ctype: resp.Header.Get("Content-Type"), headers: resp.Header}
	head := make([]byte, headBytes)
	n, err := io.ReadFull(resp.Body, head)
	out.head = string(head[:n])
	if err == io.ErrUnexpectedEOF || err == io.EOF {
		out.tail = lastN(out.head, tailBytes)
		if keep {
			out.body = out.head
		}
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	// Keep only the last 1 KB of the rest, reading a bounded amount, or all
	// of it when asked.
	var whole []byte
	if keep {
		whole = append(whole, head[:n]...)
	}
	tail := make([]byte, 0, tailBytes)
	buf := make([]byte, 32<<10)
	rest := io.LimitReader(resp.Body, maxBodyToRead)
	read := 0
	for {
		m, err := rest.Read(buf)
		if m > 0 {
			read += m
			if keep {
				whole = append(whole, buf[:m]...)
			}
			tail = append(tail, buf[:m]...)
			if len(tail) > tailBytes {
				tail = append(tail[:0], tail[len(tail)-tailBytes:]...)
			}
		}
		if err != nil {
			break
		}
	}
	out.tail = string(tail)
	if keep {
		out.body = string(whole)
		if read >= maxBodyToRead {
			// One more byte says whether the body went on.
			var one [1]byte
			if m, _ := resp.Body.Read(one[:]); m > 0 {
				out.truncated = true
			}
		}
	}
	return out, nil
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// hostsOf reads hosts for a domain from the graph, minus exclusions.
func hostsOf(r graph.Reader, domain string, s connector.Scope) []string {
	exclude := map[string]bool{}
	for _, h := range s.Project.Config.Web.ExcludeHosts {
		exclude[strings.ToLower(h)] = true
	}
	var out []string
	for _, n := range r.Nodes(graph.KindHost) {
		host, _ := n.Attrs["host"].(string)
		if n.Attrs["domain"] == domain && !exclude[host] {
			out = append(out, host)
		}
	}
	sort.Strings(out)
	return out
}

func newBudget(hosts []string) *budget {
	b := &budget{perHost: map[string]*atomic.Int64{}}
	for _, h := range hosts {
		b.perHost[h] = &atomic.Int64{}
	}
	return b
}

// Collect runs the checks for every verified domain.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	reader, ok := out.(graph.Reader)
	if !ok {
		return errors.New("web: the graph is not readable")
	}
	cl := c.client(s)
	for _, domain := range s.VerifiedDomains {
		hosts := hostsOf(reader, domain, s)
		if err := c.apiDocs(ctx, cl, domain, hosts, s, out); err != nil {
			return err
		}
		if err := c.sourceMaps(ctx, cl, domain, hosts, s, out); err != nil {
			return err
		}
	}
	for _, w := range s.WebGets {
		host, p := w[0], w[1]
		r, err := c.get(ctx, cl, host, p, false)
		if err != nil {
			return fmt.Errorf("web %s%s: %w", host, p, err)
		}
		headers := map[string]any{}
		for k, v := range r.headers {
			headers[strings.ToLower(k)] = strings.Join(v, ", ")
		}
		out.Node(graph.Node{ID: graph.ID("web:" + host + p), Kind: graph.KindWebResponse, Source: "web", SeenAt: s.Now,
			Attrs: map[string]any{"status": int64(r.status), "headers": headers, "head": r.head, "tail": r.tail}})
	}
	return nil
}

func partialOf(b *budget, failures int) string {
	var parts []string
	if n := b.over.Load(); n > 0 {
		parts = append(parts, fmt.Sprintf("%d requests over the limit were not made", n))
	}
	if failures > 0 {
		parts = append(parts, fmt.Sprintf("%d requests failed", failures))
	}
	return strings.Join(parts, "; ")
}

func looksLikeDoc(p string, r *response) bool {
	if r.status != http.StatusOK {
		return false
	}
	html := strings.Contains(strings.ToLower(r.ctype), "text/html")
	head := strings.ToLower(r.head)
	switch p {
	case "/swagger-ui/", "/swagger-ui.html":
		return strings.Contains(head, "swagger")
	case "/redoc":
		return strings.Contains(head, "redoc")
	}
	// A site that answers every path with its home page is not exposing a file.
	return !html
}

func (c *Connector) apiDocs(ctx context.Context, cl *http.Client, domain string, hosts []string, s connector.Scope, out graph.Writer) error {
	b := newBudget(hosts)
	checked := 0
	for _, host := range hosts {
		reached := false
		for _, p := range APIDocPaths {
			if !b.take(host) {
				continue
			}
			r, err := c.get(ctx, cl, host, p, false)
			if err != nil {
				if errors.Is(err, connector.ErrBlocked) {
					return err
				}
				// A host in old certificates that no longer answers is not an
				// open door, and must not hold the drill on WARN forever.
				continue
			}
			reached = true
			if looksLikeDoc(p, r) {
				out.Node(graph.Node{ID: graph.ID("api-doc:" + host + p), Kind: graph.KindAPIDoc, Source: "web", SeenAt: s.Now,
					Attrs: map[string]any{"domain": domain, "host": host, "path": p, "status": int64(r.status)}})
			}
		}
		if reached {
			checked++
		}
	}
	graph.WriteScan(out, "web", "web_api_docs", domain, checked, partialOf(b, 0), s.Now)
	return nil
}

var (
	scriptSrc = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+\.js[^"']*)["']`)
	mapURL    = regexp.MustCompile(`[#@]\s*sourceMappingURL=([^\s*]+)`)
)

// pageScan gathers what one domain's home pages, bundles and source maps
// show: the bodies scanned for credentials and the scripts each page loads.
type pageScan struct {
	domain    string
	s         connector.Scope
	out       graph.Writer
	bodies    int // bodies scanned for credentials
	truncated int // bodies longer than the read limit, scanned in part
	pages     int // home pages read, whose scripts are listed
	seen      map[graph.ID]bool
}

// secrets scans one public body for credentials and writes each by
// fingerprint, kind and key ID. The value never leaves this function.
func (p *pageScan) secrets(host, at, text string, truncated bool) {
	p.bodies++
	if truncated {
		p.truncated++
	}
	for _, f := range secrets.ScanPublic(text) {
		hash := p.s.Hasher.Sum(f.Value)
		id := graph.ID("public-secret:" + host + at + "#" + hash)
		if p.seen[id] {
			continue
		}
		p.seen[id] = true
		p.out.Node(graph.Node{ID: id, Kind: graph.KindPublicSecret, Source: "web", SeenAt: p.s.Now,
			Attrs: map[string]any{"domain": p.domain, "host": host, "path": at, "kind": f.Kind, "hash": hash,
				"key_id": f.KeyID, "client_side": secrets.IsClientSide(f.Kind)}})
	}
}

// mapSources returns a source map's original sources, so code in them reads
// line by line as it was written. A map that is not JSON is scanned as it is.
func mapSources(body string) string {
	var m struct {
		SourcesContent []*string `json:"sourcesContent"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil || len(m.SourcesContent) == 0 {
		return body
	}
	var b strings.Builder
	for _, src := range m.SourcesContent {
		if src != nil {
			b.WriteString(*src)
			b.WriteString("\n")
		}
	}
	return b.String()
}

func (c *Connector) sourceMaps(ctx context.Context, cl *http.Client, domain string, hosts []string, s connector.Scope, out graph.Writer) error {
	b := newBudget(hosts)
	bundles, failures := 0, 0
	ps := &pageScan{domain: domain, s: s, out: out, seen: map[graph.ID]bool{}}
	for _, host := range hosts {
		if !b.take(host) {
			continue
		}
		home, err := c.get(ctx, cl, host, "/", true)
		if err != nil {
			if errors.Is(err, connector.ErrBlocked) {
				return err
			}
			continue
		}
		if home.status == http.StatusOK {
			ps.pages++
			ps.secrets(host, "/", home.body, home.truncated)
			writeScripts(ps, host, "/", home.body)
		}
		// Bundles are found in the first 4 KB of the page, as before: reading
		// the whole page for its script list makes no further request.
		for _, m := range scriptSrc.FindAllStringSubmatch(home.head, -1) {
			bundlePath, ok := samePath(host, "/", m[1])
			if !ok || !b.take(host) {
				continue
			}
			r, err := c.get(ctx, cl, host, bundlePath, true)
			if err != nil {
				failures++
				continue
			}
			if r.status != http.StatusOK {
				continue
			}
			bundles++
			if !strings.Contains(strings.ToLower(r.ctype), "text/html") {
				ps.secrets(host, bundlePath, r.body, r.truncated)
			}
			ref := r.headers.Get("SourceMap")
			if ref == "" {
				ref = r.headers.Get("X-SourceMap")
			}
			if ref == "" {
				if mm := mapURL.FindStringSubmatch(r.tail); mm != nil {
					ref = mm[1]
				}
			}
			if ref == "" || strings.HasPrefix(ref, "data:") {
				continue
			}
			mp, ok := samePath(host, bundlePath, ref)
			if !ok || !b.take(host) {
				continue
			}
			mr, err := c.get(ctx, cl, host, mp, true)
			if err != nil {
				failures++
				continue
			}
			if mr.status == http.StatusOK && !strings.Contains(strings.ToLower(mr.ctype), "text/html") {
				out.Node(graph.Node{ID: graph.ID("source-map:" + host + mp), Kind: graph.KindSourceMap, Source: "web", SeenAt: s.Now,
					Attrs: map[string]any{"domain": domain, "host": host, "bundle": bundlePath, "map_url": mp}})
				ps.secrets(host, mp, mapSources(mr.body), mr.truncated)
			}
		}
	}
	partial := partialOf(b, failures)
	graph.WriteScan(out, "web", "web_source_maps", domain, bundles, partial, s.Now)
	secretsPartial := partial
	if ps.truncated > 0 {
		secretsPartial = strings.TrimPrefix(secretsPartial+fmt.Sprintf("; %d bodies over 20 MB were scanned only in part", ps.truncated), "; ")
	}
	graph.WriteScan(out, "web", PublicSecretsScanner, domain, ps.bodies, secretsPartial, s.Now)
	graph.WriteScan(out, "web", PageScriptsScanner, domain, ps.pages, partial, s.Now)
	return nil
}

// Scan records of the two checks that read the same responses as the
// source-map check.
const (
	PublicSecretsScanner = "web_public_secrets"
	PageScriptsScanner   = "web_page_scripts"
)

// samePath resolves a reference against a page, keeping only references to the
// same host, so a bundle on a CDN is reported nowhere and requested never.
func samePath(host, base, ref string) (string, bool) {
	u, err := url.Parse(ref)
	if err != nil {
		return "", false
	}
	if u.Host != "" && !strings.EqualFold(u.Host, host) {
		return "", false
	}
	if strings.HasPrefix(u.Path, "/") {
		return u.Path, true
	}
	return path.Join(path.Dir(base), u.Path), true
}
