// Package graph is the node and edge model every connector writes into and
// every fact reads from.
package graph

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"
)

// ID is a stable node identifier made from a source system and that system's
// own identifier, so the same thing gets the same ID on every run.
type ID string

// Node is one thing seen in a system. Private attributes live only for the
// current run and are never written to snapshots.
type Node struct {
	ID      ID             `json:"id"`
	Kind    string         `json:"kind"`
	Attrs   map[string]any `json:"attrs,omitempty"`
	Private map[string]any `json:"-"`
	Source  string         `json:"source"`
	SeenAt  time.Time      `json:"seen_at"`
}

// Edge links two nodes.
type Edge struct {
	From   ID     `json:"from"`
	To     ID     `json:"to"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
}

// Writer is the only way data enters the graph.
type Writer interface {
	Node(n Node)
	Edge(e Edge)
}

// Reader is how facts query the graph.
type Reader interface {
	Get(id ID) (Node, bool)
	Nodes(kind string) []Node
	Edges(kind string) []Edge
}

// Graph is an in-memory graph, safe for concurrent writers.
type Graph struct {
	mu    sync.RWMutex
	nodes map[ID]Node
	edges map[Edge]struct{}
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{nodes: map[ID]Node{}, edges: map[Edge]struct{}{}}
}

// Node adds or replaces a node.
func (g *Graph) Node(n Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.nodes[n.ID] = n
}

// Edge adds an edge.
func (g *Graph) Edge(e Edge) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.edges[e] = struct{}{}
}

// Get returns one node.
func (g *Graph) Get(id ID) (Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[id]
	return n, ok
}

// Nodes returns the nodes of a kind sorted by ID, or all nodes when kind is empty.
func (g *Graph) Nodes(kind string) []Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := []Node{}
	for _, n := range g.nodes {
		if kind == "" || n.Kind == kind {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Edges returns the edges of a kind in a stable order, or all edges when kind is empty.
func (g *Graph) Edges(kind string) []Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := []Edge{}
	for e := range g.edges {
		if kind == "" || e.Kind == kind {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})
	return out
}

// Hasher turns secrets and emails into stable HMACs using the org's salt.
type Hasher struct{ salt []byte }

// NewHasher returns a Hasher for a salt.
func NewHasher(salt string) Hasher { return Hasher{salt: []byte(salt)} }

// Sum returns the hex HMAC-SHA-256 of a value, shortened to 32 characters.
func (h Hasher) Sum(v string) string {
	m := hmac.New(sha256.New, h.salt)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:32]
}

// Email hashes an email address after normalizing it.
func (h Hasher) Email(email string) string {
	return h.Sum(strings.ToLower(strings.TrimSpace(email)))
}

// Fingerprint is a short value that identifies the salt without revealing it.
func (h Hasher) Fingerprint() string { return h.Sum("firedrill-salt-fingerprint")[:8] }

// Node kinds. Facts read these and connectors write them.
const (
	KindTargetRepo    = "target_repo"
	KindGitHubRepo    = "github_repo"
	KindBranchRule    = "branch_rule"
	KindEnvironment   = "github_environment"
	KindActionsPerms  = "actions_permissions"
	KindIdentityUser  = "identity_user"
	KindPerson        = "person"
	KindAWSPrincipal  = "aws_principal"
	KindAWSKey        = "aws_key"
	KindSecret        = "secret"
	KindSecretSeen    = "secret_occurrence"
	KindAgentConfig   = "agent_config"
	KindWorkflow      = "workflow"
	KindTFBucket      = "tf_bucket"
	KindFileDoc       = "file_doc"
	KindCodeowners    = "codeowners"
	KindSemgrep       = "semgrep_finding"
	KindHost          = "host"
	KindCNAME         = "dns_cname"
	KindDNSRecord     = "dns_record"
	KindWebResponse   = "web_response"
	KindSourceMap     = "public_source_map"
	KindAPIDoc        = "public_api_doc"
	KindLeaver        = "hr_leaver"
	KindConfigHost    = "config_host"
	KindConfigDomain  = "config_domain"
	KindScan          = "scan"
	KindConnectorFail = "connector_failure"
)

// Edge kinds.
const (
	EdgeMemberOf   = "member_of"
	EdgeAdminOf    = "admin_of"
	EdgeHolds      = "holds"
	EdgeFoundIn    = "found_in"
	EdgeSamePerson = "same_person"
	EdgeOwns       = "owns"
	EdgePointsTo   = "points_to"
	EdgeDeploysTo  = "deploys_to"
)

// ScanID names the record of what a scanner inspected. Scope is a repo, a
// domain, or empty for a global scan.
func ScanID(scanner, scope string) ID { return ID("scan:" + scanner + "/" + scope) }

// WriteScan records how many sources a scanner inspected. Partial, when not
// empty, says what could not be read.
func WriteScan(w Writer, source, scanner, scope string, inspected int, partial string, at time.Time) {
	attrs := map[string]any{"scanner": scanner, "scope": scope, "inspected": int64(inspected)}
	if partial != "" {
		attrs["partial"] = partial
	}
	w.Node(Node{ID: ScanID(scanner, scope), Kind: KindScan, Attrs: attrs, Source: source, SeenAt: at})
}
