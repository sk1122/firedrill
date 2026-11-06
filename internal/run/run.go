package run

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// Version is set at build time.
var Version = "0.0.1"

// Config is one run's inputs.
type Config struct {
	Project    *config.Project
	Drills     []*drill.Drill
	Connectors []connector.Connector
	Scope      connector.Scope
	Stream     string // local or ci
	RanBy      string
	Records    string // directory holding tags/ and snapshots/
	// WriteRecords is false in a public repo, where only counts may be printed.
	WriteRecords bool
	DryRun       bool
	PhaseTwo     map[string]bool // connectors that read what others wrote
}

// Result is one run's outputs.
type Result struct {
	Outcomes  []*Outcome
	Attention Attention
	Skips     []Skip
	Graph     *graph.Graph
	Calls     []string // printed by --dry-run
	Fatal     string
	Stream    string
	Available map[string]bool
	Failures  map[string]string
}

// Skip is one drill waiting for a system.
type Skip struct {
	DrillID string
	Needs   string
}

// DefaultPhaseTwo names the connectors that depend on hosts from others.
func DefaultPhaseTwo() map[string]bool { return map[string]bool{"dns": true, "web": true} }

// Run executes the steps: plan, collect, link, decide, record.
func Run(ctx context.Context, c Config) (*Result, error) {
	res := &Result{Graph: graph.New(), Available: map[string]bool{}, Failures: map[string]string{}, Stream: c.Stream}
	scope := c.Scope
	if c.PhaseTwo == nil {
		c.PhaseTwo = DefaultPhaseTwo()
	}
	needed := plan(c.Drills, &scope)

	var phase1, phase2 []connector.Connector
	for _, conn := range c.Connectors {
		ok, _ := conn.Available(scope)
		res.Available[conn.Name()] = ok
		if !ok {
			continue
		}
		if !needed[conn.Name()] && conn.Name() != "config" {
			continue
		}
		if c.DryRun {
			for _, col := range conn.Collections() {
				for _, call := range col.Calls {
					res.Calls = append(res.Calls, conn.Name()+": "+call)
				}
			}
			continue
		}
		if c.PhaseTwo[conn.Name()] {
			phase2 = append(phase2, conn)
		} else {
			phase1 = append(phase1, conn)
		}
	}
	if c.DryRun {
		sort.Strings(res.Calls)
		return res, nil
	}

	// Config goes first, since it names targets every other connector reads.
	rest := phase1[:0:0]
	for _, conn := range phase1 {
		if conn.Name() == "config" {
			collectOne(ctx, conn, scope, res)
			continue
		}
		rest = append(rest, conn)
	}
	collectAll(ctx, rest, scope, res)
	collectAll(ctx, phase2, scope, res)

	if v := scope.Log.Violations(); len(v) > 0 {
		res.Fatal = "the read-only guard stopped this run: " + strings.Join(v, "; ")
		return res, nil
	}

	link(res.Graph, scope.Hasher)

	store := tag.Store{Root: c.Records}
	opts := Options{Now: scope.Now, Available: res.Available, Failures: res.Failures, Waivers: c.Project.Waivers}
	for _, d := range c.Drills {
		outcomes := Decide(d, res.Graph, opts)
		outcomes, skip := carryForward(d, outcomes, store)
		if skip != nil {
			res.Skips = append(res.Skips, *skip)
		}
		for _, o := range outcomes {
			prev, err := store.Latest(d.ID, o.Target)
			if err != nil {
				return nil, err
			}
			ApplyState(o, prev, c.Project.Config.RetiredTarget(o.Target))
			o.Owner = owner(d, o, res.Graph, c.Project)
		}
		res.Outcomes = append(res.Outcomes, outcomes...)
	}
	SortOutcomes(res.Outcomes)
	res.Attention = BuildAttention(res.Outcomes)

	if !c.WriteRecords {
		return res, nil
	}
	for _, o := range res.Outcomes {
		t := toTag(o, c, scope)
		tag.ScanTag(t, scope.Hasher)
		if _, err := store.Write(t); err != nil {
			return nil, fmt.Errorf("write tag: %w", err)
		}
	}
	snap := graph.TakeSnapshot(res.Graph, scope.Now)
	tag.ScanSnapshot(&snap, scope.Hasher)
	if _, err := graph.WriteSnapshot(filepath.Join(c.Records, "snapshots"), snap); err != nil {
		return nil, fmt.Errorf("write snapshot: %w", err)
	}
	return res, nil
}

// plan works out which connectors the drills need, and what facts name.
func plan(drills []*drill.Drill, s *connector.Scope) map[string]bool {
	needed := map[string]bool{"config": true}
	paths, dnsHosts := map[string]bool{}, map[string]bool{}
	webs := map[[2]string]bool{}
	for _, d := range drills {
		names := []string{d.ForEach}
		for _, f := range d.Fetches {
			names = append(names, f.Fact)
			switch f.Fact {
			case "files.json", "files.yaml":
				paths[f.Args["path"]] = true
			case "dns.records":
				dnsHosts[f.Args["host"]] = true
			case "web.get":
				webs[[2]string{f.Args["host"], f.Args["path"]}] = true
			}
		}
		for _, n := range names {
			if strings.HasPrefix(n, "files.") {
				needed["files"] = true
			}
			if def, ok := facts.Lookup(n); ok && def.Connector != "" {
				needed[def.Connector] = true
			}
			if n == "github.repos" {
				needed["github"] = true
			}
		}
	}
	// DNS and web both read hosts from certificate logs.
	if needed["dns"] || needed["web"] {
		needed["ctlog"] = true
	}
	// AWS agent keys join against what the file scanner found.
	if needed["aws"] {
		needed["files"] = true
	}
	for p := range paths {
		s.FilePaths = append(s.FilePaths, p)
	}
	for h := range dnsHosts {
		s.DNSHosts = append(s.DNSHosts, h)
	}
	for w := range webs {
		s.WebGets = append(s.WebGets, w)
	}
	sort.Strings(s.FilePaths)
	sort.Strings(s.DNSHosts)
	return needed
}

func collectAll(ctx context.Context, conns []connector.Connector, s connector.Scope, res *Result) {
	var wg sync.WaitGroup
	for _, conn := range conns {
		wg.Add(1)
		go func() {
			defer wg.Done()
			collectOne(ctx, conn, s, res)
		}()
	}
	wg.Wait()
}

var failMu sync.Mutex

func collectOne(ctx context.Context, conn connector.Connector, s connector.Scope, res *Result) {
	for _, col := range conn.Collections() {
		if err := conn.Collect(ctx, col, s, res.Graph); err != nil {
			failMu.Lock()
			if errors.Is(err, connector.ErrBlocked) {
				res.Failures[conn.Name()] = "blocked: " + err.Error()
			} else {
				res.Failures[conn.Name()] = err.Error()
			}
			failMu.Unlock()
			return
		}
	}
}

// link matches accounts to people and marks accounts the same person holds.
func link(g *graph.Graph, h graph.Hasher) {
	for _, n := range g.Nodes(graph.KindIdentityUser) {
		email, _ := n.Private["email"].(string)
		if email == "" {
			continue
		}
		person := graph.ID("person:" + h.Email(email))
		g.Node(graph.Node{ID: person, Kind: graph.KindPerson, Source: "link", SeenAt: n.SeenAt})
		g.Edge(graph.Edge{From: person, To: n.ID, Kind: graph.EdgeSamePerson, Source: "link"})
	}
}

// carryForward keeps every safeguard with history visible. A drill whose system
// was disconnected, or a target no longer listed, still appears, so a failure
// cannot disappear that way.
func carryForward(d *drill.Drill, outcomes []*Outcome, store tag.Store) ([]*Outcome, *Skip) {
	keys, err := store.Keys()
	if err != nil {
		return outcomes, nil
	}
	var known []*tag.Tag
	for _, k := range keys {
		if k.DrillID != d.ID {
			continue
		}
		l, err := store.Latest(d.ID, k.TargetSlug)
		if err == nil && l != nil {
			known = append(known, l)
		}
	}
	if len(outcomes) == 1 && outcomes[0].Target == "" && outcomes[0].Verdict == tag.Skip {
		skip := &Skip{DrillID: d.ID, Needs: outcomes[0].Reason}
		out := []*Outcome{}
		for _, l := range known {
			if l.Header.Target == "" && len(known) > 1 {
				continue
			}
			out = append(out, &Outcome{Drill: d, Target: l.Header.Target, Verdict: tag.Skip, Reason: outcomes[0].Reason})
		}
		return out, skip
	}
	present := map[string]bool{}
	for _, o := range outcomes {
		present[o.Target] = true
	}
	for _, l := range known {
		if !present[l.Header.Target] {
			outcomes = append(outcomes, &Outcome{Drill: d, Target: l.Header.Target, Verdict: tag.NA, Reason: "target is no longer listed in this run"})
		}
	}
	return outcomes, nil
}

// owner resolves who answers for a result: the drill, then CODEOWNERS for the
// affected path in the target repo, then the default owner.
func owner(d *drill.Drill, o *Outcome, g graph.Reader, p *config.Project) string {
	if d.Owner != "" {
		return d.Owner
	}
	if n, ok := g.Get(graph.ID("codeowners:" + o.Target)); ok {
		if who := codeownerOf(n, affectedPath(o)); who != "" {
			return who
		}
	}
	return p.Config.DefaultOwner
}

func affectedPath(o *Outcome) string {
	for _, v := range o.Facts {
		m, _ := v.(map[string]any)
		found, _ := m["found"].([]any)
		for _, item := range found {
			row, _ := item.(map[string]any)
			if f, _ := row["file"].(string); f != "" {
				return f
			}
		}
	}
	return ""
}

// codeownerOf applies CODEOWNERS order: the last matching rule wins.
func codeownerOf(n graph.Node, file string) string {
	rules, _ := n.Attrs["rules"].([]any)
	who := ""
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		pattern, _ := rule["pattern"].(string)
		owners, _ := rule["owners"].([]any)
		if len(owners) == 0 || !codeownerMatch(pattern, file) {
			continue
		}
		who, _ = owners[0].(string)
	}
	return who
}

func codeownerMatch(pattern, file string) bool {
	if pattern == "*" {
		return true
	}
	if file == "" {
		return false
	}
	p := strings.TrimPrefix(pattern, "/")
	if strings.HasSuffix(p, "/") {
		return strings.HasPrefix(file, p) || strings.Contains(file, "/"+p)
	}
	if ok, _ := filepath.Match(p, file); ok {
		return true
	}
	ok, _ := filepath.Match(p, filepath.Base(file))
	return ok || strings.HasPrefix(file, p+"/")
}

func toTag(o *Outcome, c Config, s connector.Scope) *tag.Tag {
	read := make([]string, 0, len(o.Read))
	for _, id := range o.Read {
		read = append(read, string(id))
	}
	sort.Strings(read)
	return &tag.Tag{
		Header: tag.Header{
			DrillID: o.Drill.ID, DrillHash: o.Drill.Hash, Version: Version, Target: o.Target, Stream: c.Stream,
			Verdict: o.Verdict, Reason: o.Reason, State: o.State, Waived: o.Waived, WaivedParts: o.WaivedParts,
			Severity: o.Drill.Severity, Owner: o.Owner, Conditions: o.Conditions, FactSources: o.Sources,
			Time: s.Now.UTC().Truncate(time.Second), RanBy: c.RanBy, SaltPrint: s.Hasher.Fingerprint(),
		},
		Evidence: tag.Evidence{Facts: o.Facts, Read: read},
	}
}
