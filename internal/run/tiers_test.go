package run

import (
	"testing"

	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// Two facts that exist only in tests: one whose class and each found row's env
// are guessed from naming, read from a file, and one read from a live API. No
// shipped fact marks a field inferred.
func init() {
	facts.Register(facts.Def{
		Name: "test.guessed",
		Shape: facts.Obj(map[string]*facts.Shape{
			"class": facts.Str, "file": facts.Str,
			"found": facts.List(facts.Obj(map[string]*facts.Shape{"file": facts.Str, "env": facts.Str})),
		}),
		Inferred: []string{"class", "found.env"},
		Fn: func(g graph.Reader, _ facts.Args) (facts.Result, error) {
			n, _ := g.Get("test:guessed")
			return facts.Result{Read: []graph.ID{n.ID}, Source: "file", Data: n.Attrs}, nil
		},
	})
	facts.Register(facts.Def{
		Name:  "test.read",
		Shape: facts.Obj(map[string]*facts.Shape{"ok": facts.Bool}),
		Fn: func(g graph.Reader, _ facts.Args) (facts.Result, error) {
			n, _ := g.Get("test:read")
			return facts.Result{Read: []graph.ID{n.ID}, Source: "api", Data: n.Attrs}, nil
		},
	})
}

func tierDrill(t *testing.T, passWhen ...string) *drill.Drill {
	t.Helper()
	src := "firedrill: v0\nid: test/tiers\nsafeguard: \"Nothing guessed is prod.\"\nseverity: high\n" +
		"fetch:\n  guess: { fact: test.guessed }\n  real: { fact: test.read }\npass_when:\n"
	for _, p := range passWhen {
		src += "  - '" + p + "'\n"
	}
	src += "fix: \"Fix it.\"\n"
	d, issues := drill.Load("test/tiers.drill.yaml", []byte(src))
	if drill.HasErrors(issues) {
		t.Fatal(issues)
	}
	return d
}

func tierGraph(class, env string, ok bool) *graph.Graph {
	g := graph.New()
	node(g, "test:guessed", "test", map[string]any{"class": class, "file": ".env",
		"found": []any{map[string]any{"file": ".env", "env": env}}})
	node(g, "test:read", "test", map[string]any{"ok": ok})
	return g
}

func decideOne(t *testing.T, d *drill.Drill, g *graph.Graph) *Outcome {
	t.Helper()
	out := Decide(d, g, Options{Now: testNow, Available: map[string]bool{}})
	if len(out) != 1 {
		t.Fatalf("%d outcomes", len(out))
	}
	return out[0]
}

func TestFailOnOnlyInferredEvidenceWarns(t *testing.T) {
	for name, cond := range map[string]string{
		"plain field": `guess.class != "prod"`,
		"list field":  `guess.found.all(x, x.env != "prod")`,
	} {
		o := decideOne(t, tierDrill(t, cond), tierGraph("prod", "prod", true))
		if o.Verdict != tag.Warn || o.Reason[:len("only inferred evidence: ")] != "only inferred evidence: " {
			t.Errorf("%s: %s %q", name, o.Verdict, o.Reason)
		}
	}
	// Passing stays PASS: the rule only softens a FAIL.
	if o := decideOne(t, tierDrill(t, `guess.class != "prod"`), tierGraph("dev", "dev", true)); o.Verdict != tag.Pass {
		t.Errorf("pass: %s", o.Verdict)
	}
}

func TestFailOnReadEvidenceStaysFail(t *testing.T) {
	cases := map[string][]string{
		"mixed in one condition":       {`guess.class != "prod" || real.ok`},
		"a verified failing too":       {`guess.class != "prod"`, `real.ok`},
		"a declared field":             {`guess.file != ".env"`},
		"a found row read whole":       {`size(guess.found) == 0`},
		"a condition reading no field": {`1 == 2`},
	}
	for name, conds := range cases {
		o := decideOne(t, tierDrill(t, conds...), tierGraph("prod", "prod", false))
		if o.Verdict != tag.Fail {
			t.Errorf("%s: %s %q", name, o.Verdict, o.Reason)
		}
	}
}

// Tiers are recorded in the tag: each fetch by its source, and each inferred
// field a condition read. A WARN on inferred evidence never opens the safeguard.
func TestTiersAreRecorded(t *testing.T) {
	d := []*drill.Drill{tierDrill(t, `guess.found.all(x, x.env != "prod")`, `real.ok`)}
	c := baseConfig(t, d)
	g := tierGraph("dev", "prod", true)
	res := runAt(t, c, 0, &fake{name: "config", available: true, write: func(w graph.Writer) {
		for _, n := range g.Nodes("") {
			w.Node(n)
		}
	}})
	o := res.Outcomes[0]
	if o.Verdict != tag.Warn || o.State != tag.Unknown || o.NewlyOpen || ExitCode(res.Outcomes, "any") != 0 {
		t.Fatalf("%+v", o)
	}
	want := map[string]string{"guess": facts.TierDeclared, "real": facts.TierVerified, "guess.found.env": facts.TierInferred}
	h, _ := tag.Store{Root: c.Records}.History("test/tiers", "")
	if len(h) != 1 {
		t.Fatalf("%d tags", len(h))
	}
	for k, v := range want {
		if o.Tiers[k] != v || h[0].Header.FactTiers[k] != v {
			t.Errorf("%s: outcome %q, tag %q, want %q", k, o.Tiers[k], h[0].Header.FactTiers[k], v)
		}
	}
	if len(h[0].Header.FactTiers) != len(want) {
		t.Errorf("tiers %v", h[0].Header.FactTiers)
	}
}

// Shipped drills record tiers from their sources and no inferred field.
func TestShippedDrillTiers(t *testing.T) {
	g := graph.New()
	ghRepo(g, "team", true)
	branchRule(g, 0, "none", false)
	out := Decide(loadDrill(t, "change/human-review-required"), g, Options{Now: testNow, Available: map[string]bool{"github": true}})
	if o := out[0]; o.Verdict != tag.Fail || len(o.Tiers) != 2 || o.Tiers["rules"] != facts.TierVerified || o.Tiers["bots"] != facts.TierVerified {
		t.Fatalf("%s %v", o.Verdict, o.Tiers)
	}
}
