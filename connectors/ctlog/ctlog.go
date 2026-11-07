// Package ctlog reads hostnames from public certificates through crt.sh, which is
// public and rate-limited, so results are cached for 24 hours.
package ctlog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// Connector reads certificate logs.
type Connector struct {
	connector.Base
	BaseURL string
}

// New returns the connector.
func New() *Connector {
	return &Connector{
		ConnectorName: "ctlog", Policy: connector.Policy{Hosts: map[string]bool{"crt.sh": true}}, Limit: 0.5, Burst: 1,
		BaseURL: "https://crt.sh/",
	}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{Name: "certificates", Nodes: []string{graph.KindHost},
		Calls: []string{"GET https://crt.sh/?q=%.{domain}&output=json, one per verified domain"}}}
}

// Available is true when a domain is verified.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if len(s.VerifiedDomains) == 0 {
		return false, "verify-domain"
	}
	return true, ""
}

type cacheFile struct {
	Time  time.Time `json:"time"`
	Names []string  `json:"names"`
}

// Collect reads hosts for every verified domain.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	for _, domain := range s.VerifiedDomains {
		names, partial := c.names(ctx, domain, s)
		hosts := map[string]bool{}
		for _, n := range names {
			for h := range strings.SplitSeq(n, "\n") {
				h = strings.ToLower(strings.TrimSpace(h))
				h = strings.TrimPrefix(h, "*.")
				if h != "" && connector.UnderDomain(h, domain) {
					hosts[h] = true
				}
			}
		}
		sorted := make([]string, 0, len(hosts))
		for h := range hosts {
			sorted = append(sorted, h)
		}
		sort.Strings(sorted)
		for _, h := range sorted {
			out.Node(graph.Node{ID: graph.ID("host:" + h), Kind: graph.KindHost, Source: "ctlog", SeenAt: s.Now,
				Attrs: map[string]any{"domain": domain, "host": h}})
		}
		graph.WriteScan(out, "ctlog", "ctlog", domain, len(sorted), partial, s.Now)
	}
	return nil
}

func (c *Connector) cachePath(domain string, s connector.Scope) string {
	return filepath.Join(s.Project.Dir, "local", "crtsh-"+domain+".json")
}

func (c *Connector) names(ctx context.Context, domain string, s connector.Scope) ([]string, string) {
	path := c.cachePath(domain, s)
	var cached cacheFile
	haveCache := false
	if b, err := os.ReadFile(path); err == nil && json.Unmarshal(b, &cached) == nil {
		haveCache = true
		if s.Now.Sub(cached.Time) < 24*time.Hour {
			return cached.Names, ""
		}
	}
	names, err := c.fetch(ctx, domain, s)
	if err != nil {
		partial := "crt.sh is down: " + err.Error()
		if haveCache {
			return cached.Names, partial + "; using results from " + cached.Time.Format("2006-01-02")
		}
		return nil, partial
	}
	if b, err := json.Marshal(cacheFile{Time: s.Now, Names: names}); err == nil {
		if os.MkdirAll(filepath.Dir(path), 0o755) == nil {
			_ = os.WriteFile(path, b, 0o644)
		}
	}
	return names, ""
}

func (c *Connector) fetch(ctx context.Context, domain string, s connector.Scope) ([]string, error) {
	u := c.BaseURL + "?q=" + url.QueryEscape("%."+domain) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "firedrill/"+connector.Version)
	resp, err := c.HTTP(s.Log).Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.NameValue)
	}
	return out, nil
}
