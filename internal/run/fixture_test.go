package run

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// TestGenerateStarterFixtures writes packs/<pack>/<slug>.test.yaml from the
// engine cases, recording the fact values each one produced. It runs only
// with FIREDRILL_GEN_FIXTURES=1.
func TestGenerateStarterFixtures(t *testing.T) {
	if os.Getenv("FIREDRILL_GEN_FIXTURES") != "1" {
		t.Skip("set FIREDRILL_GEN_FIXTURES=1 to regenerate")
	}
	files := map[string]*TestFile{}
	for _, c := range drillCases() {
		g := graph.New()
		c.setup(g)
		vals := map[string]facts.Result{}
		o := Options{Now: testNow, Available: allConnectors, Record: func(a string, r facts.Result) { vals[a] = r }}
		got := Decide(loadDrill(t, c.id), g, o)
		if len(got) != 1 || got[0].Verdict != c.verdictWant {
			t.Fatalf("%s %s: %v", c.id, c.name, got)
		}
		tc := TestCase{Name: c.name, Expect: c.verdictWant, Facts: map[string]any{}, Target: got[0].TargetAttrs}
		for a, r := range vals {
			tc.Facts[a] = r.Data
			if r.Inspected > 0 {
				if tc.Inspected == nil {
					tc.Inspected = map[string]int{}
				}
				tc.Inspected[a] = r.Inspected
			}
			if r.Partial != "" {
				if tc.Partial == nil {
					tc.Partial = map[string]string{}
				}
				tc.Partial[a] = r.Partial
			}
		}
		if files[c.id] == nil {
			files[c.id] = &TestFile{Firedrill: "v0", Drill: c.id}
		}
		files[c.id].Cases = append(files[c.id].Cases, tc)
	}
	ids := make([]string, 0, len(files))
	for id := range files {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		b, err := yaml.Marshal(files[id])
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join("..", "..", "packs", id+".test.yaml")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStarterFixturesPass(t *testing.T) {
	results, problems, err := TestDir(filepath.Join("..", "..", "packs"))
	if err != nil {
		t.Fatal(err)
	}
	for p, msg := range problems {
		t.Errorf("%s: %s", p, msg)
	}
	if len(results) != 32 {
		t.Errorf("tested %d drills, want 32", len(results))
	}
	for p, cases := range results {
		for _, c := range cases {
			if !c.OK() {
				t.Errorf("%s %q: want %s, got %s (%s)", p, c.Name, c.Expect, c.Got, c.Reason)
			}
		}
	}
}

func TestFixtureNeedsAllThreeVerdicts(t *testing.T) {
	d := loadDrill(t, "change/no-force-push-main")
	only := []byte("firedrill: v0\ndrill: change/no-force-push-main\ncases:\n  - name: pass\n    expect: PASS\n    target: {name: a/b, protection_available: true}\n    facts:\n      rules: {force_push_allowed: false, deletion_allowed: false, bypass: none}\n")
	res, err := RunTests(d, only)
	if err == nil || len(res) != 1 || !res[0].OK() {
		t.Fatalf("one passing case runs, and the missing verdicts are an error: %v %v", res, err)
	}
	wrong := []byte("firedrill: v0\ndrill: change/other\ncases: []\n")
	if _, err := RunTests(d, wrong); err == nil {
		t.Fatal("a fixture for another drill is an error")
	}
	_ = drill.Issue{}
	_ = tag.Pass
}
