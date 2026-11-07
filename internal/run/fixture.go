package run

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/tag"
)

// TestFile is a drill's test fixtures, <slug>.test.yaml beside the drill.
type TestFile struct {
	Firedrill string     `yaml:"firedrill"`
	Drill     string     `yaml:"drill"`
	Cases     []TestCase `yaml:"cases"`
}

// TestCase gives the fact values for one setup and the verdict they must give.
type TestCase struct {
	Name      string            `yaml:"name"`
	Expect    string            `yaml:"expect"`
	Target    map[string]any    `yaml:"target,omitempty"`
	Facts     map[string]any    `yaml:"facts"`
	Inspected map[string]int    `yaml:"inspected,omitempty"`
	Partial   map[string]string `yaml:"partial,omitempty"`
}

// CaseResult is one case's outcome.
type CaseResult struct {
	Name, Expect, Got, Reason string
}

// OK reports whether the case gave the expected verdict.
func (c CaseResult) OK() bool { return c.Got == c.Expect }

// TestPath returns the fixtures file for a drill file.
func TestPath(drillFile string) string {
	return strings.TrimSuffix(drillFile, ".drill.yaml") + ".test.yaml"
}

// fixtureNow is the fixed time fixtures run at, so day counts never drift.
var fixtureNow = time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)

// RunTests runs a drill's fixtures. It fails a file that lacks a passing, a
// failing or a not-applicable case.
func RunTests(d *drill.Drill, data []byte) ([]CaseResult, error) {
	var tf TestFile
	if err := yaml.Unmarshal(data, &tf); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	if tf.Drill != d.ID {
		return nil, fmt.Errorf("names drill %q, but the drill is %q", tf.Drill, d.ID)
	}
	have := map[string]bool{}
	var out []CaseResult
	for _, c := range tf.Cases {
		have[c.Expect] = true
		oc := DecideFixture(d, c)
		out = append(out, CaseResult{Name: c.Name, Expect: c.Expect, Got: oc.Verdict, Reason: oc.Reason})
	}
	var missing []string
	for _, v := range []string{tag.Pass, tag.Fail, tag.NA} {
		if !have[v] {
			missing = append(missing, v)
		}
	}
	if len(missing) > 0 {
		return out, fmt.Errorf("needs a case for each of PASS, FAIL and N/A; missing %s", strings.Join(missing, ", "))
	}
	return out, nil
}

// DecideFixture decides one drill on one target from fixture values.
func DecideFixture(d *drill.Drill, c TestCase) *Outcome {
	values := map[string]facts.Result{}
	for alias, v := range c.Facts {
		values[alias] = facts.Result{Data: normalize(v), Inspected: c.Inspected[alias], Partial: c.Partial[alias], Source: "fixture"}
	}
	target, _ := normalize(c.Target).(map[string]any)
	o := Options{Now: fixtureNow, Fixture: values, Available: map[string]bool{}}
	return decideTarget(d, nil, o, targetName(target), target)
}

// normalize turns YAML's ints into int64, as facts return them.
func normalize(v any) any {
	switch x := v.(type) {
	case int:
		return int64(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = normalize(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	}
	return v
}

// TestDir runs every drill under dir that has a fixtures file, and reports the
// drills that have none.
func TestDir(dir string) (results map[string][]CaseResult, problems map[string]string, err error) {
	results, problems = map[string][]CaseResult{}, map[string]string{}
	err = filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".drill.yaml") {
			return err
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		d, issues := drill.Load(p, data)
		if drill.HasErrors(issues) {
			problems[p] = "does not validate"
			return nil
		}
		td, err := os.ReadFile(TestPath(p))
		if err != nil {
			problems[p] = "has no " + filepath.Base(TestPath(p))
			return nil
		}
		res, err := RunTests(d, td)
		results[p] = res
		if err != nil {
			problems[p] = err.Error()
		}
		return nil
	})
	return results, problems, err
}

// SortedKeys returns a map's keys in order.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
