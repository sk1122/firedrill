package drill

import (
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"

	"github.com/sk1122/firedrill/internal/facts"
)

// costLimit bounds one condition, so a drill cannot hang a run.
const costLimit = 1_000_000

func newEnv(d *Drill) (*cel.Env, error) {
	opts := []cel.EnvOption{cel.Variable("target", cel.DynType)}
	for _, f := range d.Fetches {
		opts = append(opts, cel.Variable(f.Alias, cel.DynType))
	}
	return cel.NewEnv(opts...)
}

// Validate checks a parsed drill against the list of facts and fields.
func Validate(d *Drill) []Issue {
	var issues []Issue
	add := func(line int, warning bool, format string, args ...any) {
		issues = append(issues, Issue{File: d.File, Line: line, Warning: warning, Message: fmt.Sprintf(format, args...)})
	}
	shapes := map[string]*facts.Shape{}
	if d.ForEach != "" {
		def, ok := facts.Lookup(d.ForEach)
		switch {
		case !ok:
			add(0, false, "for_each names unknown fact %q", d.ForEach)
		case def.Shape.Kind != "list":
			add(0, false, "for_each fact %q is not a list", d.ForEach)
		default:
			shapes["target"] = def.Shape.Elem
		}
	}
	seen := map[string]bool{}
	for _, f := range d.Fetches {
		if f.Alias == "target" {
			add(f.Line, false, "fetch name %q is reserved", f.Alias)
		}
		if seen[f.Alias] {
			add(f.Line, false, "fetch name %q is used twice", f.Alias)
		}
		seen[f.Alias] = true
		def, ok := facts.Lookup(f.Fact)
		if !ok {
			add(f.Line, false, "unknown fact %q. Known facts: %s", f.Fact, strings.Join(facts.Names(), ", "))
			continue
		}
		shapes[f.Alias] = def.Shape
		for name, val := range f.Args {
			if !contains(def.Args, name) {
				add(f.Line, false, "fact %q has no argument %q", f.Fact, name)
			}
			if strings.HasPrefix(val, "target.") && d.ForEach == "" {
				add(f.Line, false, "argument %q reads target, but the drill has no for_each", name)
			}
		}
	}
	env, err := newEnv(d)
	if err != nil {
		add(0, false, "bad fetch names: %v", err)
		return issues
	}
	check := func(field string, c Condition) {
		ast, iss := env.Parse(c.Expr)
		if iss != nil && iss.Err() != nil {
			add(c.Line, false, "%s: not valid CEL: %v", field, iss.Err())
			return
		}
		a := analyzer{shapes: shapes, used: map[string]map[string]bool{}, onErr: func(msg string) {
			add(c.Line, false, "%s: %s", field, msg)
		}}
		parsed, err := cel.AstToParsedExpr(ast)
		if err != nil {
			add(c.Line, false, "%s: %v", field, err)
			return
		}
		a.walk(parsed.GetExpr(), nil)
		if _, iss := env.Check(ast); iss != nil && iss.Err() != nil {
			add(c.Line, false, "%s: %v", field, iss.Err())
		}
	}
	if d.AppliesWhen != nil {
		check("applies_when", *d.AppliesWhen)
	}
	for _, c := range d.PassWhen {
		check("pass_when", c)
	}
	for _, c := range d.WarnWhen {
		check("warn_when", c)
	}
	scanning := false
	for _, f := range d.Fetches {
		if def, ok := facts.Lookup(f.Fact); ok && def.Scanning {
			scanning = true
		}
	}
	if d.AppliesWhen == nil && !scanning {
		for _, f := range d.Fetches {
			if def, ok := facts.Lookup(f.Fact); ok && !def.Scanning && def.Shape.Kind == "list" {
				add(f.Line, true, "fact %q is a list of a system's objects: declare applies_when, or an empty list passes", f.Fact)
			}
		}
	}
	return issues
}

func contains(s []string, v string) bool {
	return slices.Contains(s, v)
}

// analyzer walks a parsed condition, rejecting fields a fact does not have and
// recording the fields used, so evidence can be trimmed to them.
type analyzer struct {
	shapes map[string]*facts.Shape
	used   map[string]map[string]bool
	onErr  func(string)
}

type value struct {
	shape *facts.Shape
	alias string
	path  string
}

func (a *analyzer) use(v value) {
	if v.alias == "" {
		return
	}
	if a.used[v.alias] == nil {
		a.used[v.alias] = map[string]bool{}
	}
	a.used[v.alias][v.path] = true
}

func (a *analyzer) walk(e *exprpb.Expr, scope map[string]value) value {
	switch k := e.ExprKind.(type) {
	case *exprpb.Expr_IdentExpr:
		if v, ok := scope[k.IdentExpr.Name]; ok {
			a.use(v)
			return v
		}
		if s, ok := a.shapes[k.IdentExpr.Name]; ok {
			v := value{shape: s, alias: k.IdentExpr.Name}
			a.use(v)
			return v
		}
		return value{}
	case *exprpb.Expr_SelectExpr:
		operand := a.walk(k.SelectExpr.Operand, scope)
		field := k.SelectExpr.Field
		if operand.shape == nil || operand.shape.Kind == "any" {
			v := value{shape: facts.Any, alias: operand.alias, path: joinPath(operand.path, field)}
			a.use(v)
			return v
		}
		if operand.shape.Kind != "object" {
			a.onErr(fmt.Sprintf("field %q read on a %s value", field, operand.shape.Kind))
			return value{}
		}
		s, ok := operand.shape.Fields[field]
		if !ok {
			a.onErr(fmt.Sprintf("unknown field %q on %s. Known fields: %s", field, nameOf(operand), fieldNames(operand.shape)))
			return value{}
		}
		v := value{shape: s, alias: operand.alias, path: joinPath(operand.path, field)}
		a.use(v)
		return v
	case *exprpb.Expr_CallExpr:
		if k.CallExpr.Target != nil {
			a.walk(k.CallExpr.Target, scope)
		}
		var first value
		for i, arg := range k.CallExpr.Args {
			v := a.walk(arg, scope)
			if i == 0 {
				first = v
			}
		}
		_ = first
		return value{}
	case *exprpb.Expr_ListExpr:
		for _, el := range k.ListExpr.Elements {
			a.walk(el, scope)
		}
		return value{}
	case *exprpb.Expr_StructExpr:
		for _, en := range k.StructExpr.Entries {
			if key := en.GetMapKey(); key != nil {
				a.walk(key, scope)
			}
			a.walk(en.Value, scope)
		}
		return value{}
	case *exprpb.Expr_ComprehensionExpr:
		c := k.ComprehensionExpr
		rng := a.walk(c.IterRange, scope)
		inner := map[string]value{}
		maps.Copy(inner, scope)
		elem := value{alias: rng.alias, path: rng.path}
		if rng.shape != nil && rng.shape.Kind == "list" {
			elem.shape = rng.shape.Elem
		} else if rng.shape != nil && rng.shape.Kind != "any" {
			a.onErr(fmt.Sprintf("%s is not a list", nameOf(rng)))
		}
		inner[c.IterVar] = elem
		inner[c.AccuVar] = value{}
		a.walk(c.AccuInit, inner)
		a.walk(c.LoopCondition, inner)
		a.walk(c.LoopStep, inner)
		a.walk(c.Result, inner)
		if isFilter(c) {
			return rng
		}
		return value{}
	}
	return value{}
}

// isFilter recognizes the expansion of list.filter, whose result has the same
// element shape as its range, so field checks carry through chained macros.
func isFilter(c *exprpb.Expr_Comprehension) bool {
	call := c.LoopStep.GetCallExpr()
	if call == nil || call.Function != "_?_:_" || len(call.Args) != 3 {
		return false
	}
	add := call.Args[1].GetCallExpr()
	if add == nil || add.Function != "_+_" || len(add.Args) != 2 {
		return false
	}
	list := add.Args[1].GetListExpr()
	return list != nil && len(list.Elements) == 1 && list.Elements[0].GetIdentExpr() != nil &&
		list.Elements[0].GetIdentExpr().Name == c.IterVar
}

func nameOf(v value) string {
	if v.alias == "" {
		return "this value"
	}
	return joinPath(v.alias, v.path)
}

func joinPath(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

func fieldNames(s *facts.Shape) string {
	names := []string{}
	for n := range s.Fields {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// UsedPaths returns, per fetch alias, the field paths a drill's conditions read.
func UsedPaths(d *Drill) map[string][]string {
	shapes := map[string]*facts.Shape{}
	if def, ok := facts.Lookup(d.ForEach); ok && def.Shape.Elem != nil {
		shapes["target"] = def.Shape.Elem
	}
	for _, f := range d.Fetches {
		if def, ok := facts.Lookup(f.Fact); ok {
			shapes[f.Alias] = def.Shape
		}
	}
	env, err := newEnv(d)
	if err != nil {
		return nil
	}
	a := analyzer{shapes: shapes, used: map[string]map[string]bool{}, onErr: func(string) {}}
	var all []Condition
	all = append(all, d.PassWhen...)
	all = append(all, d.WarnWhen...)
	if d.AppliesWhen != nil {
		all = append(all, *d.AppliesWhen)
	}
	for _, c := range all {
		if ast, iss := env.Parse(c.Expr); iss == nil || iss.Err() == nil {
			if parsed, err := cel.AstToParsedExpr(ast); err == nil {
				a.walk(parsed.GetExpr(), nil)
			}
		}
	}
	out := map[string][]string{}
	for alias, paths := range a.used {
		for p := range paths {
			out[alias] = append(out[alias], p)
		}
		sort.Strings(out[alias])
	}
	return out
}

// Evaluator evaluates one drill's conditions over fact data.
type Evaluator struct {
	env *cel.Env
}

// NewEvaluator returns an Evaluator for a drill.
func NewEvaluator(d *Drill) (*Evaluator, error) {
	env, err := newEnv(d)
	if err != nil {
		return nil, err
	}
	return &Evaluator{env: env}, nil
}

// Eval runs one condition. A missing field, a non-bool result or an exceeded
// cost limit is an error, so a typo can never pass quietly.
func (e *Evaluator) Eval(expr string, vars map[string]any) (bool, error) {
	ast, iss := e.env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return false, iss.Err()
	}
	prg, err := e.env.Program(ast, cel.CostLimit(costLimit))
	if err != nil {
		return false, err
	}
	out, _, err := prg.Eval(vars)
	if err != nil {
		return false, err
	}
	return asBool(out)
}

func asBool(v ref.Val) (bool, error) {
	if b, ok := v.(types.Bool); ok {
		return bool(b), nil
	}
	return false, fmt.Errorf("condition returned %s, not true or false", v.Type().TypeName())
}
