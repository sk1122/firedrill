// Package run plans a run, collects through connectors, decides verdicts and
// applies the safeguard state rule.
package run

import (
	"fmt"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// Outcome is one verdict on one target.
type Outcome struct {
	Drill       *drill.Drill
	Target      string
	TargetAttrs map[string]any
	Verdict     string
	Reason      string
	Conditions  []tag.Condition
	Facts       map[string]any
	Read        []graph.ID
	Sources     map[string]string
	Waived      bool
	Waivers     []config.Waiver
	WaivedParts int
	Owner       string
	Prev        string
	State       string
	NewlyOpen   bool
	NewlyClosed bool
	Unverified  string
	Retired     string
}

// Options controls decisions.
type Options struct {
	Now       time.Time
	Available map[string]bool // connectors that can run
	Failures  map[string]string
	Waivers   []config.Waiver
}

// Decide evaluates one drill across its targets.
func Decide(d *drill.Drill, g graph.Reader, o Options) []*Outcome {
	if missing := missingConnector(d, o); missing != "" {
		return []*Outcome{{Drill: d, Verdict: tag.Skip, Reason: "needs " + missing}}
	}
	if d.ForEach == "" {
		return []*Outcome{decideTarget(d, g, o, "", nil)}
	}
	def, ok := facts.Lookup(d.ForEach)
	if !ok {
		return []*Outcome{{Drill: d, Verdict: tag.Error, Reason: "unknown for_each " + d.ForEach}}
	}
	res, err := def.Fn(g, facts.Args{Now: o.Now})
	if err != nil {
		return []*Outcome{{Drill: d, Verdict: tag.Error, Reason: err.Error()}}
	}
	targets, _ := res.Data.([]any)
	if len(targets) == 0 {
		if d.ForEach == "config.domains" {
			return []*Outcome{{Drill: d, Verdict: tag.Skip, Reason: "needs a verified domain"}}
		}
		return []*Outcome{{Drill: d, Verdict: tag.Skip, Reason: "needs a target from " + d.ForEach}}
	}
	out := make([]*Outcome, 0, len(targets))
	for i, t := range targets {
		attrs, _ := t.(map[string]any)
		oc := decideTarget(d, g, o, targetName(attrs), attrs)
		// The target itself was read, so its page lists this verdict.
		if i < len(res.Read) {
			oc.Read = append(oc.Read, res.Read[i])
		}
		out = append(out, oc)
	}
	return out
}

func targetName(attrs map[string]any) string {
	for _, k := range []string{"name", "domain", "host"} {
		if s, ok := attrs[k].(string); ok {
			return s
		}
	}
	return ""
}

func missingConnector(d *drill.Drill, o Options) string {
	names := []string{d.ForEach}
	for _, f := range d.Fetches {
		names = append(names, f.Fact)
	}
	for _, n := range names {
		if def, ok := facts.Lookup(n); ok && def.Connector != "" && !o.Available[def.Connector] {
			return def.Connector
		}
	}
	return ""
}

func decideTarget(d *drill.Drill, g graph.Reader, o Options, target string, attrs map[string]any) *Outcome {
	out := &Outcome{Drill: d, Target: target, TargetAttrs: attrs, Sources: map[string]string{}, Facts: map[string]any{}}
	vars := map[string]any{"target": attrs}
	if attrs == nil {
		vars["target"] = map[string]any{}
	}
	sawScan, inspectedAny := false, false
	partial := []string{}
	raw := map[string]facts.Result{}
	for _, f := range d.Fetches {
		def, ok := facts.Lookup(f.Fact)
		if !ok {
			out.Verdict, out.Reason = tag.Error, "unknown fact "+f.Fact
			return out
		}
		args := facts.Args{Values: map[string]any{}, Target: attrs, Now: o.Now}
		for k, v := range f.Args {
			if field, ok := strings.CutPrefix(v, "target."); ok {
				args.Values[k] = attrs[field]
			} else {
				args.Values[k] = v
			}
		}
		if def.Connector != "" {
			if msg := o.Failures[def.Connector]; msg != "" {
				out.Verdict, out.Reason = tag.Error, def.Connector+": "+msg
				return out
			}
		}
		res, err := def.Fn(g, args)
		if err != nil {
			out.Verdict, out.Reason = tag.Error, err.Error()
			return out
		}
		raw[f.Alias] = res
		vars[f.Alias] = res.Data
		out.Read = append(out.Read, res.Read...)
		out.Sources[f.Alias] = res.Source
		if def.Scanning {
			sawScan = true
			if res.Inspected > 0 {
				inspectedAny = true
			}
		}
		if res.Partial != "" {
			partial = append(partial, res.Partial)
		}
	}
	out.Facts = trimEvidence(d, raw)
	ev, err := drill.NewEvaluator(d)
	if err != nil {
		out.Verdict, out.Reason = tag.Error, err.Error()
		return out
	}
	if sawScan && !inspectedAny {
		out.Verdict, out.Reason = tag.NA, naReason(d, "nothing to inspect")
		return out
	}
	if d.AppliesWhen != nil {
		ok, err := ev.Eval(d.AppliesWhen.Expr, vars)
		if err != nil {
			out.Verdict, out.Reason = tag.Error, err.Error()
			return out
		}
		if !ok {
			out.Verdict, out.Reason = tag.NA, naReason(d, "applies_when is false")
			return out
		}
	}
	failed, failing, errMsg := evalAll(d, ev, vars, &out.Conditions)
	if errMsg != "" {
		out.Verdict, out.Reason = tag.Error, errMsg
		return out
	}
	switch {
	case failed:
		out.Verdict, out.Reason = tag.Fail, failReason(d, ev, vars, failing, raw)
		applyWaivers(out, d, ev, vars, raw, target, o)
	default:
		out.Verdict = tag.Pass
		for _, c := range d.WarnWhen {
			hit, err := ev.Eval(c.Expr, vars)
			if err != nil {
				out.Verdict, out.Reason = tag.Error, err.Error()
				return out
			}
			if hit {
				out.Verdict, out.Reason = tag.Warn, "warn_when matched: "+c.Expr
				break
			}
		}
		if out.Verdict == tag.Pass && len(partial) > 0 {
			out.Verdict, out.Reason = tag.Warn, "could read only part: "+strings.Join(partial, "; ")
		}
	}
	return out
}

func naReason(d *drill.Drill, fallback string) string {
	if d.NAReason != "" {
		return d.NAReason
	}
	return fallback
}

func evalAll(d *drill.Drill, ev *drill.Evaluator, vars map[string]any, record *[]tag.Condition) (bool, []string, string) {
	failed := false
	var failing []string
	for _, c := range d.PassWhen {
		ok, err := ev.Eval(c.Expr, vars)
		if err != nil {
			if record != nil {
				*record = append(*record, tag.Condition{Expr: c.Expr, Result: err.Error()})
			}
			return false, nil, err.Error()
		}
		if record != nil {
			*record = append(*record, tag.Condition{Expr: c.Expr, Result: fmt.Sprint(ok)})
		}
		if !ok {
			failed = true
			failing = append(failing, c.Expr)
		}
	}
	return failed, failing, ""
}

// failReason names what actually failed. A row is to blame when the drill still
// fails with only that row in its list, so a harmless finding beside a real one
// is never the one reported.
func failReason(d *drill.Drill, ev *drill.Evaluator, vars map[string]any, failing []string, raw map[string]facts.Result) string {
	aliases := make([]string, 0, len(raw))
	for a := range raw {
		aliases = append(aliases, a)
	}
	sort.Strings(aliases)
	for _, alias := range aliases {
		m, ok := raw[alias].Data.(map[string]any)
		if !ok {
			continue
		}
		found, ok := m["found"].([]any)
		if !ok || len(found) == 0 {
			continue
		}
		var blamed []map[string]any
		for _, item := range found {
			if len(blamed) >= maxBlameRows {
				break
			}
			trial := map[string]any{}
			maps.Copy(trial, vars)
			cp := map[string]any{}
			maps.Copy(cp, m)
			cp["found"] = []any{item}
			trial[alias] = cp
			if stillFails, _, errMsg := evalAll(d, ev, trial, nil); errMsg == "" && stillFails {
				row, _ := item.(map[string]any)
				blamed = append(blamed, row)
			}
		}
		if len(blamed) == 0 {
			continue
		}
		return describeRow(blamed[0], len(blamed))
	}
	return "failed: " + strings.Join(strings.Fields(failing[0]), " ")
}

// maxBlameRows bounds how many rows are tried, so a huge list stays cheap.
const maxBlameRows = 200

func describeRow(row map[string]any, n int) string {
	count := fmt.Sprintf("%d failing", n)
	if n >= maxBlameRows {
		count = fmt.Sprintf("%d+ failing", maxBlameRows)
	}
	if f, _ := row["file"].(string); f != "" {
		if cls, _ := row["env_class"].(string); cls != "" {
			return fmt.Sprintf("%s, first: %s credential in %s", count, cls, f)
		}
		return fmt.Sprintf("%s, first in %s", count, f)
	}
	if h, _ := row["host"].(string); h != "" {
		return fmt.Sprintf("%s, first on %s", count, h)
	}
	return count
}

// applyWaivers decides whether a FAIL is waived. A drill-wide waiver covers it.
// A finding waiver covers it only if the drill passes once every waived finding
// is removed, so one accepted fake key never hides a real one.
func applyWaivers(out *Outcome, d *drill.Drill, ev *drill.Evaluator, vars map[string]any, raw map[string]facts.Result, target string, o Options) {
	var findings []config.Waiver
	for _, w := range o.Waivers {
		if w.Drill != d.ID || (w.Target != "" && w.Target != target) || !w.Active(o.Now) {
			continue
		}
		if w.Finding == nil {
			out.Waived = true
			out.Waivers = append(out.Waivers, w)
			return
		}
		findings = append(findings, w)
	}
	if len(findings) == 0 {
		return
	}
	filtered := map[string]any{}
	maps.Copy(filtered, vars)
	removed := 0
	for alias, r := range raw {
		m, ok := r.Data.(map[string]any)
		if !ok {
			continue
		}
		list, ok := m["found"].([]any)
		if !ok {
			continue
		}
		keep := make([]any, 0, len(list))
		for _, item := range list {
			row, _ := item.(map[string]any)
			if matchesFinding(row, findings) {
				removed++
				continue
			}
			keep = append(keep, item)
		}
		cp := map[string]any{}
		maps.Copy(cp, m)
		cp["found"] = keep
		filtered[alias] = cp
	}
	out.WaivedParts = removed
	if removed == 0 {
		return
	}
	failed, _, errMsg := evalAll(d, ev, filtered, nil)
	if errMsg == "" && !failed {
		out.Waived = true
		out.Waivers = findings
	}
}

func matchesFinding(row map[string]any, ws []config.Waiver) bool {
	file, _ := row["file"].(string)
	hash, _ := row["hash"].(string)
	for _, w := range ws {
		if w.Finding.File == file && strings.TrimPrefix(w.Finding.Hash, "secret:") == hash {
			return true
		}
	}
	return false
}

// trimEvidence keeps only the fields conditions used. A value used only through
// its size is recorded as a count.
func trimEvidence(d *drill.Drill, raw map[string]facts.Result) map[string]any {
	used := drill.UsedPaths(d)
	out := map[string]any{}
	for alias, r := range raw {
		paths := used[alias]
		out[alias] = trimValue(r.Data, paths)
	}
	return out
}

func trimValue(v any, paths []string) any {
	children := map[string][]string{}
	leaf := false
	for _, p := range paths {
		if p == "" {
			leaf = true
			continue
		}
		head, rest, _ := strings.Cut(p, ".")
		children[head] = append(children[head], rest)
	}
	switch val := v.(type) {
	case map[string]any:
		if len(children) == 0 {
			if len(val) == 0 {
				return val
			}
			return map[string]any{"fields": len(val)}
		}
		out := map[string]any{}
		for k, sub := range children {
			if x, ok := val[k]; ok {
				out[k] = trimValue(x, sub)
			}
		}
		return out
	case []any:
		if len(children) == 0 && leaf {
			if isScalars(val) {
				return val
			}
			return map[string]any{"count": len(val)}
		}
		out := make([]any, 0, len(val))
		for _, x := range val {
			out = append(out, trimValue(x, paths))
		}
		return out
	}
	return v
}

func isScalars(l []any) bool {
	for _, x := range l {
		switch x.(type) {
		case map[string]any, []any:
			return false
		}
	}
	return true
}

// Attention is what leads every output.
type Attention struct {
	NewlyOpen        []*Outcome
	NewlyClosed      []*Outcome
	OpenUnverified   []*Outcome
	ClosedUnverified []*Outcome
}

// BuildAttention groups outcomes by what changed.
func BuildAttention(all []*Outcome) Attention {
	var a Attention
	for _, o := range all {
		switch {
		case o.NewlyOpen:
			a.NewlyOpen = append(a.NewlyOpen, o)
		case o.NewlyClosed:
			a.NewlyClosed = append(a.NewlyClosed, o)
		case o.State == tag.Open && o.Verdict != tag.Fail:
			a.OpenUnverified = append(a.OpenUnverified, o)
		case o.State == tag.Closed && o.Verdict != tag.Pass:
			a.ClosedUnverified = append(a.ClosedUnverified, o)
		}
	}
	return a
}

// ApplyState works out state and what changed from the previous tag. A waiver
// that just expired on an open safeguard counts as newly open.
func ApplyState(o *Outcome, prev *tag.Tag, retired *config.Retired) {
	prevState, prevWaived := "", false
	if prev != nil {
		prevState, prevWaived = prev.Header.State, prev.Header.Waived
	}
	o.Prev = prevState
	if retired != nil {
		o.Retired = retired.Reason
	}
	o.State = tag.NextState(prevState, o.Verdict, retired != nil)
	o.NewlyOpen = o.State == tag.Open && !o.Waived && (prevState != tag.Open || prevWaived)
	if o.Waived {
		o.NewlyOpen = false
	}
	o.NewlyClosed = prevState == tag.Open && o.State == tag.Closed
	if o.State == tag.Open && o.Verdict != tag.Fail {
		o.Unverified = "open, unverified this run"
	}
	if o.State == tag.Closed && o.Verdict != tag.Pass && prev != nil {
		o.Unverified = "closed, unverified since " + prev.Header.Time.Format("2006-01-02")
	}
}

// ExitCode applies the exit rules. failOn is "", "open" or "any".
func ExitCode(all []*Outcome, failOn string) int {
	code := 0
	for _, o := range all {
		if o.Verdict == tag.Error {
			return 2
		}
		sev := o.Drill.Severity == "critical" || o.Drill.Severity == "high"
		unwaivedOpen := o.State == tag.Open && !o.Waived
		switch {
		case o.NewlyOpen && sev:
			code = 1
		case failOn == "open" && unwaivedOpen && sev:
			code = 1
		case failOn == "any" && unwaivedOpen:
			code = 1
		}
	}
	return code
}

// SortOutcomes orders outcomes by drill and target.
func SortOutcomes(all []*Outcome) {
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Drill.ID != all[j].Drill.ID {
			return all[i].Drill.ID < all[j].Drill.ID
		}
		return all[i].Target < all[j].Target
	})
}
