// Package connector is the interface every connector satisfies, the shared base
// holding the guarded client, and the registry.
package connector

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"golang.org/x/time/rate"

	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

// Version is the Firedrill version sent in the user agent. It is set at build time.
var Version = "0.0.1"

// Collection is one thing a connector can fetch.
type Collection struct {
	Name       string
	Nodes      []string // node kinds it writes
	Permission string   // the access it needs
	Calls      []string // the calls it makes, printed by --dry-run
}

// Scope is what a run asks a connector to cover.
type Scope struct {
	Project         *config.Project
	Hasher          graph.Hasher
	Now             time.Time
	Log             *CallLog
	Paths           []string // local checkouts from --path
	IncludeHome     bool     // read user-level agent files
	HomeDir         string   // where user-level files live
	Token           string   // GitHub token, in memory only
	Getenv          func(string) string
	Tarball         func(ctx context.Context, repo string) (io.ReadCloser, error)
	FilePaths       []string    // paths named through files.json and files.yaml
	DNSHosts        []string    // hosts named through dns.records
	WebGets         [][2]string // host and path named through web.get
	VerifiedDomains []string
	RepoTargets     []string // every repo name in scope
}

// Connector is one system Firedrill can read.
type Connector interface {
	Name() string
	Collections() []Collection
	// Available says whether the system is connected. The reason says how to
	// connect it.
	Available(s Scope) (bool, string)
	Collect(ctx context.Context, c Collection, s Scope, out graph.Writer) error
}

// Base holds what every connector shares.
type Base struct {
	ConnectorName string
	Policy        Policy
	Limit         rate.Limit
	Burst         int
	Next          http.RoundTripper // set in tests to reach a fake server
	limiter       *rate.Limiter
}

// Name returns the connector's name.
func (b *Base) Name() string { return b.ConnectorName }

// HTTP returns the guarded, rate-limited client. A connector never builds its
// own, so every call passes the guard and the log.
func (b *Base) HTTP(log *CallLog) *http.Client {
	if b.limiter == nil {
		limit, burst := b.Limit, b.Burst
		if limit == 0 {
			limit = 5
		}
		if burst == 0 {
			burst = 5
		}
		b.limiter = rate.NewLimiter(limit, burst)
	}
	return Client(b.ConnectorName, b.Policy, log, &limited{next: b.Next, limiter: b.limiter})
}

// limited waits for the rate limiter and retries once on 429, honoring the
// server's Retry-After.
type limited struct {
	next    http.RoundTripper
	limiter *rate.Limiter
}

func (l *limited) RoundTrip(r *http.Request) (*http.Response, error) {
	next := l.next
	if next == nil {
		next = http.DefaultTransport
	}
	for attempt := 0; ; attempt++ {
		if err := l.limiter.Wait(r.Context()); err != nil {
			return nil, err
		}
		resp, err := next.RoundTrip(r)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests || attempt >= 2 || r.Body != nil {
			return resp, err
		}
		wait := 2 * time.Second
		if s := resp.Header.Get("Retry-After"); s != "" {
			var secs int
			if _, err := fmt.Sscanf(s, "%d", &secs); err == nil && secs >= 0 && secs <= 60 {
				wait = time.Duration(secs) * time.Second
			}
		}
		_ = resp.Body.Close()
		select {
		case <-r.Context().Done():
			return nil, r.Context().Err()
		case <-time.After(wait):
		}
	}
}

var registry = map[string]Connector{}

// Register adds a connector, the same pattern as database/sql drivers.
func Register(c Connector) {
	if _, dup := registry[c.Name()]; dup {
		panic("connector: duplicate " + c.Name())
	}
	registry[c.Name()] = c
}

// Lookup returns a registered connector.
func Lookup(name string) (Connector, bool) {
	c, ok := registry[name]
	return c, ok
}

// All returns every registered connector sorted by name.
func All() []Connector {
	out := make([]Connector, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}
