package drill

import (
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/packs"
)

func TestLibraryDrillsAreValid(t *testing.T) {
	count := 0
	err := fs.WalkDir(packs.FS, ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".drill.yaml") {
			return err
		}
		count++
		data, err := packs.FS.ReadFile(p)
		if err != nil {
			return err
		}
		d, issues := Load(p, data)
		if HasErrors(issues) {
			t.Errorf("%s: %v", p, issues)
		}
		for _, i := range issues {
			if i.Warning {
				t.Errorf("%s: library drills must have no warnings: %v", p, i)
			}
		}
		if d != nil && p != d.ID+".drill.yaml" {
			t.Errorf("%s: id %s does not match its path", p, d.ID)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 24 {
		t.Errorf("library has %d drills, want 24", count)
	}
}

func TestSpecExamplesParse(t *testing.T) {
	data, err := os.ReadFile("../../docs/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	blocks := regexp.MustCompile("(?s)```yaml\n(firedrill: v0.*?)```").FindAllSubmatch(data, -1)
	if len(blocks) == 0 {
		t.Fatal("no drill examples found in the spec")
	}
	for _, b := range blocks {
		if _, issues := Load("spec", b[1]); HasErrors(issues) {
			t.Errorf("spec example does not validate: %v", issues)
		}
	}
}

const good = `firedrill: v0
id: change/x
safeguard: "A rule."
severity: high
for_each: github.repos
fetch:
  rules: { fact: github.branch_rules, args: { branch: default } }
pass_when:
  - rules.required_approvals >= 1
`

func TestGoodDrillIsAccepted(t *testing.T) {
	if _, issues := Load("good", []byte(good)); len(issues) != 0 {
		t.Fatalf("unexpected issues: %v", issues)
	}
}

func TestBrokenDrillsAreRejectedWithClearMessages(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"not yaml", "a: [", "not valid YAML"},
		{"plain multi-line ternary", strings.Replace(good, "  - rules.required_approvals >= 1", "  - rules.bypass == \"none\"\n      ? true\n      : false", 1), "folded block"},
		{"not a mapping", "- a\n- b\n", "must be a YAML mapping"},
		{"missing version", strings.Replace(good, "firedrill: v0\n", "", 1), "missing required field firedrill"},
		{"wrong version", strings.Replace(good, "firedrill: v0", "firedrill: v9", 1), "unsupported format version"},
		{"missing id", strings.Replace(good, "id: change/x\n", "", 1), "missing required field id"},
		{"bad id", strings.Replace(good, "id: change/x", "id: Change X", 1), "must be pack/slug"},
		{"missing safeguard", strings.Replace(good, "safeguard: \"A rule.\"\n", "", 1), "missing required field safeguard"},
		{"missing severity", strings.Replace(good, "severity: high\n", "", 1), "missing required field severity"},
		{"bad severity", strings.Replace(good, "severity: high", "severity: huge", 1), "must be critical, high, medium or low"},
		{"unknown field", good + "colour: red\n", "unknown field \"colour\""},
		{"missing pass_when", strings.Split(good, "pass_when:")[0], "missing required field pass_when"},
		{"pass_when not a list", strings.Replace(good, "pass_when:\n  - rules.required_approvals >= 1", "pass_when: rules.required_approvals >= 1", 1), "must be a list"},
		{"missing fetch", strings.Replace(good, "fetch:\n  rules: { fact: github.branch_rules, args: { branch: default } }\n", "", 1), "missing required field fetch"},
		{"unknown fact", strings.Replace(good, "github.branch_rules", "github.nope", 1), "unknown fact \"github.nope\""},
		{"unknown field in condition", strings.Replace(good, "required_approvals", "required_aprovals", 1), "unknown field \"required_aprovals\""},
		{"bad CEL", strings.Replace(good, "rules.required_approvals >= 1", "rules.required_approvals >=", 1), "not valid CEL"},
		{"unknown variable", strings.Replace(good, "rules.required_approvals >= 1", "ruels.required_approvals >= 1", 1), "ruels"},
		{"unknown fact argument", strings.Replace(good, "branch: default", "branchh: default", 1), "has no argument \"branchh\""},
		{"unknown for_each", strings.Replace(good, "for_each: github.repos", "for_each: github.nope", 1), "for_each names unknown fact"},
		{"for_each not a list", strings.Replace(good, "for_each: github.repos", "for_each: github.actions_permissions", 1), "is not a list"},
		{"reserved fetch name", strings.Replace(good, "  rules: {", "  target: {", 1), "reserved"},
		{"field on element of a filtered list", strings.Replace(good, "rules.required_approvals >= 1", "true", 1) + "warn_when:\n  - rules.bypass_actor == \"x\"\n", "unknown field"},
	}
	if len(cases) < 20 {
		t.Fatalf("spec asks for 20 broken drills, have %d", len(cases))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, issues := Load("broken", []byte(c.input))
			if !HasErrors(issues) {
				t.Fatalf("accepted a broken drill: %s", c.input)
			}
			joined := ""
			for _, i := range issues {
				joined += i.String() + "\n"
			}
			if !strings.Contains(joined, c.want) {
				t.Errorf("message does not mention %q:\n%s", c.want, joined)
			}
		})
	}
}

func TestFieldChecksCarryThroughFilter(t *testing.T) {
	input := `firedrill: v0
id: access/x
safeguard: "A rule."
severity: high
fetch:
  users: { fact: identity.users }
applies_when: users.size() > 0
pass_when:
  - users.filter(u, u.suspended).all(u, u.nope)
`
	_, issues := Load("f", []byte(input))
	if !HasErrors(issues) || !strings.Contains(issues[0].Message, "nope") {
		t.Fatalf("want an unknown field error, got %v", issues)
	}
}

func TestListFactWithoutAppliesWhenWarns(t *testing.T) {
	input := `firedrill: v0
id: access/x
safeguard: "A rule."
severity: high
fetch:
  users: { fact: identity.users }
pass_when:
  - users.all(u, u.suspended)
`
	_, issues := Load("f", []byte(input))
	if HasErrors(issues) || len(issues) != 1 || !issues[0].Warning {
		t.Fatalf("want one warning, got %v", issues)
	}
}

func TestEvalMissingFieldIsAnError(t *testing.T) {
	d, _ := Parse("x", []byte(good))
	ev, err := NewEvaluator(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ev.Eval("rules.required_approvals >= 1", map[string]any{"rules": map[string]any{}, "target": map[string]any{}}); err == nil {
		t.Fatal("a missing field must be an error")
	}
	ok, err := ev.Eval("rules.required_approvals >= 1", map[string]any{"rules": map[string]any{"required_approvals": int64(2)}, "target": map[string]any{}})
	if err != nil || !ok {
		t.Fatalf("got %v %v", ok, err)
	}
	if _, err := ev.Eval("rules.required_approvals", map[string]any{"rules": map[string]any{"required_approvals": int64(2)}, "target": map[string]any{}}); err == nil {
		t.Fatal("a non-bool result must be an error")
	}
}

func TestUsedPaths(t *testing.T) {
	data, _ := packs.FS.ReadFile("agent/no-prod-secrets-in-agent-reach.drill.yaml")
	d, _ := Parse("x", data)
	got := UsedPaths(d)["secrets"]
	want := "agent_readable"
	if !strings.Contains(strings.Join(got, ","), want) {
		t.Fatalf("used paths %v missing %s", got, want)
	}
}
