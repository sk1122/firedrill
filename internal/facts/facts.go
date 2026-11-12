// Package facts holds the named, tested queries drills read. Facts are the whole
// interface between drills and systems.
package facts

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/graph"
)

// Shape describes the fields of a fact, so validate can reject unknown ones.
type Shape struct {
	Kind   string // string, bool, int, list, object, any
	Fields map[string]*Shape
	Elem   *Shape
}

// Shape constructors.
var (
	Str  = &Shape{Kind: "string"}
	Bool = &Shape{Kind: "bool"}
	Int  = &Shape{Kind: "int"}
	Any  = &Shape{Kind: "any"}
)

// List returns a list shape.
func List(elem *Shape) *Shape { return &Shape{Kind: "list", Elem: elem} }

// Obj returns an object shape.
func Obj(fields map[string]*Shape) *Shape { return &Shape{Kind: "object", Fields: fields} }

// Args are the resolved arguments of one fact on one target.
type Args struct {
	Values map[string]any
	Target map[string]any
	Now    time.Time
	// Previous is the graph of the previous run of the same stream, read from
	// its snapshot, or nil when there is none. No fact reads it yet.
	Previous graph.Reader
}

// String returns a string argument.
func (a Args) String(name string) string {
	s, _ := a.Values[name].(string)
	return s
}

// TargetName returns the name of the current repo target.
func (a Args) TargetName() string {
	s, _ := a.Target["name"].(string)
	return s
}

// Result is what a fact returns: its data, how many sources it inspected, and
// the node IDs it read. Partial says what could not be read.
type Result struct {
	Data      any
	Inspected int
	Read      []graph.ID
	Partial   string
	Source    string
}

// Evidence tiers. Verified was read from a live API, declared from a config
// file or an admin export, and inferred was worked out from naming or another
// heuristic rather than read.
const (
	TierVerified = "verified"
	TierDeclared = "declared"
	TierInferred = "inferred"
)

// TierOf gives the tier of a fact result from its source. It is the one place
// a source becomes a tier: api is verified; file, config and an admin export
// (admin_export, with or without its detail) are declared. Any other source,
// such as a test fixture, has no tier.
func TierOf(source string) string {
	switch {
	case source == "api":
		return TierVerified
	case source == "file", source == "config", source == "admin_export", strings.HasPrefix(source, "admin_export:"):
		return TierDeclared
	}
	return ""
}

// IsInferred says whether a field path, spelled as conditions read it, is one
// of a fact's inferred fields or nested under one.
func IsInferred(path string, inferred []string) bool {
	for _, p := range inferred {
		if p == "" || path == p || strings.HasPrefix(path, p+".") {
			return true
		}
	}
	return false
}

// Func is one tested query over the graph.
type Func func(g graph.Reader, a Args) (Result, error)

// Def describes one fact.
type Def struct {
	Name      string
	Connector string // the connector that must be available, empty for none
	// AnyConnector, for a fact with no single connector, lists connectors of
	// which at least one must be available. The fact returns what those that
	// were read hold, so a drill on it runs for a company using only one.
	AnyConnector []string
	Args         []string // accepted argument names
	Scanning     bool     // returns found and inspected
	Shape        *Shape
	Fn           Func
	// Inferred lists the field paths whose values come from a heuristic rather
	// than being read, spelled as conditions read them: a list adds no segment,
	// so found.env_class is the env_class of every found row. A FAIL that rests
	// only on these fields is a WARN. No shipped fact marks any field yet.
	Inferred []string
	// Identity lists the field paths that say which thing a row is, spelled as
	// Inferred is. They are kept in a tag's evidence beside the fields the
	// conditions read, so a reader can tell which file, key or database a
	// verdict is about. They locate a thing and are never personal data or a
	// secret: a person is named by their hashed id, never an address or login.
	Identity []string
}

var registry = map[string]Def{}

// Register adds a fact.
func Register(d Def) {
	if _, dup := registry[d.Name]; dup {
		panic("facts: duplicate fact " + d.Name)
	}
	registry[d.Name] = d
}

// Lookup returns a fact by name.
func Lookup(name string) (Def, bool) {
	d, ok := registry[name]
	return d, ok
}

// All returns every fact sorted by name.
func All() []Def {
	out := make([]Def, 0, len(registry))
	for _, d := range registry {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Names returns every fact name sorted, for error messages.
func Names() []string {
	out := []string{}
	for _, d := range All() {
		out = append(out, d.Name)
	}
	return out
}

// scanOf reads what a scanner inspected in one scope.
func scanOf(g graph.Reader, scanner, scope string) (inspected int, partial string, id graph.ID, ok bool) {
	id = graph.ScanID(scanner, scope)
	n, ok := g.Get(id)
	if !ok {
		return 0, "", id, false
	}
	v, _ := n.Attrs["inspected"].(int64)
	p, _ := n.Attrs["partial"].(string)
	return int(v), p, id, true
}

// attrsOf copies selected attributes into a fact row. A missing attribute stays
// missing, so a condition reading it gives ERROR rather than passing quietly.
func attrsOf(n graph.Node, fields ...string) map[string]any {
	row := map[string]any{}
	for _, f := range fields {
		if v, ok := n.Attrs[f]; ok {
			row[f] = v
		}
	}
	return row
}

func strAttr(n graph.Node, name string) string {
	s, _ := n.Attrs[name].(string)
	return s
}

// daysSince returns whole days since an RFC 3339 time, or -1 when it is empty
// or unreadable.
func daysSince(ts string, now time.Time) int64 {
	if ts == "" {
		return -1
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return -1
	}
	return int64(now.Sub(t).Hours() / 24)
}

func notCollected(name, id string) error {
	return fmt.Errorf("%s: %s was not collected", name, id)
}
