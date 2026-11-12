package run

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// fake writes a fixture graph, or misbehaves as a test asks.
type fake struct {
	name      string
	available bool
	write     func(graph.Writer)
	collect   func(connector.Scope) error
}

func (f *fake) Name() string { return f.name }
func (f *fake) Collections() []connector.Collection {
	return []connector.Collection{{Name: "all", Calls: []string{"GET https://example.test/" + f.name}}}
}
func (f *fake) Available(connector.Scope) (bool, string) { return f.available, "connect " + f.name }
func (f *fake) Collect(_ context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	if f.collect != nil {
		return f.collect(s)
	}
	if f.write != nil {
		f.write(out)
	}
	return nil
}

func baseConfig(t *testing.T, drills []*drill.Drill, conns ...connector.Connector) Config {
	t.Helper()
	return Config{
		Project: &config.Project{Config: config.Config{DefaultOwner: "@default"}},
		Drills:  drills, Connectors: conns,
		Scope:        connector.Scope{Now: testNow, Log: &connector.CallLog{}, Hasher: graph.NewHasher("salt")},
		Stream:       "local",
		RanBy:        "test",
		Records:      t.TempDir(),
		WriteRecords: true,
	}
}

func ghWriter(approvals int64) func(graph.Writer) {
	return func(w graph.Writer) {
		g := graph.New()
		ghRepo(g, "team", true)
		branchRule(g, approvals, "none", false)
		for _, n := range g.Nodes("") {
			w.Node(n)
		}
	}
}

func TestRunWritesChainedTagsAndSnapshotAndTracksState(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: ghWriter(0)})
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	o := res.Outcomes[0]
	if o.Verdict != tag.Fail || o.State != tag.Open || !o.NewlyOpen || o.Owner != "@default" {
		t.Fatalf("%+v", o)
	}
	if ExitCode(res.Outcomes, "") != 1 {
		t.Fatal("newly open high safeguard exits 1")
	}
	if files, _ := graph.SnapshotFiles(filepath.Join(c.Records, "snapshots")); len(files) != 1 {
		t.Fatalf("snapshots: %v", files)
	}

	// The system is disconnected next week: the safeguard stays open and visible.
	c2 := c
	c2.Connectors = []connector.Connector{&fake{name: "github", available: false}}
	c2.Scope.Now = testNow.AddDate(0, 0, 7)
	res, err = Run(context.Background(), c2)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Outcomes) != 1 || res.Outcomes[0].Verdict != tag.Skip || res.Outcomes[0].State != tag.Open || len(res.Attention.OpenUnverified) != 1 {
		t.Fatalf("FAIL then SKIP must stay OPEN: %+v", res.Outcomes)
	}
	if len(res.Skips) != 1 {
		t.Fatalf("skips: %v", res.Skips)
	}

	// Fixed the week after: only a passing run closes it.
	c3 := c
	c3.Connectors = []connector.Connector{&fake{name: "github", available: true, write: ghWriter(1)}}
	c3.Scope.Now = testNow.AddDate(0, 0, 14)
	res, err = Run(context.Background(), c3)
	if err != nil {
		t.Fatal(err)
	}
	if o := res.Outcomes[0]; o.State != tag.Closed || !o.NewlyClosed {
		t.Fatalf("%+v", o)
	}
	h, err := tag.Store{Root: c.Records}.History(d[0].ID, "acme/api")
	if err != nil || len(h) != 3 {
		t.Fatalf("%v %d", err, len(h))
	}
	if st := tag.VerifyChain(h); !st.OK {
		t.Fatalf("chain: %+v", st)
	}
}

func TestTargetNoLongerListedStaysOpen(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: ghWriter(0)})
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Connectors = []connector.Connector{&fake{name: "github", available: true, write: func(w graph.Writer) {
		g := graph.New()
		node(g, "github:repo/acme/web", graph.KindGitHubRepo, map[string]any{"name": "acme/web", "private": true, "plan": "team", "protection_available": true})
		node(g, "github:actions/acme/web", graph.KindActionsPerms, map[string]any{"can_approve_pull_requests": false, "default_token_permission": "read"})
		node(g, "github:branch-rule/acme/web/default", graph.KindBranchRule, map[string]any{"required_approvals": int64(1), "dismiss_stale": true, "code_owner_review": false, "bypass": "none", "bypass_source": "api", "force_push_allowed": false, "deletion_allowed": false})
		for _, n := range g.Nodes("") {
			w.Node(n)
		}
	}}}
	c.Scope.Now = testNow.AddDate(0, 0, 7)
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, o := range res.Outcomes {
		if o.Target == "acme/api" {
			found = true
			if o.State != tag.Open || o.Verdict != tag.NA {
				t.Fatalf("%+v", o)
			}
		}
	}
	if !found {
		t.Fatal("a target dropped from config must stay visible while open")
	}
}

func TestPublicRepoWritesNoRecords(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: ghWriter(0)})
	c.WriteRecords = false
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(c.Records)
	if len(entries) != 0 {
		t.Fatalf("a public repo must get no record files: %v", entries)
	}
}

func TestDryRunMakesNoCalls(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	called := false
	c := baseConfig(t, d, &fake{name: "github", available: true, collect: func(connector.Scope) error { called = true; return nil }})
	c.DryRun = true
	res, err := Run(context.Background(), c)
	if err != nil || called {
		t.Fatalf("%v called=%v", err, called)
	}
	if len(res.Calls) != 1 {
		t.Fatalf("dry run must print calls: %v", res.Calls)
	}
}

func TestGuardViolationStopsTheRun(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, collect: func(s connector.Scope) error {
		client := connector.Client("github", connector.Policy{}, s.Log, http.DefaultTransport)
		req, _ := http.NewRequest(http.MethodDelete, "https://example.test/repos/a", nil)
		_, err := client.Do(req)
		if !errors.Is(err, connector.ErrBlocked) {
			t.Errorf("got %v", err)
		}
		return err
	}})
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fatal == "" {
		t.Fatal("a call outside the guard must stop the run")
	}
	entries, _ := os.ReadDir(c.Records)
	if len(entries) != 0 {
		t.Fatal("a stopped run must write no records")
	}
}

func TestConnectorFailureIsError(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "access/admins-use-mfa")}
	c := baseConfig(t, d, &fake{name: "google", available: true, collect: func(connector.Scope) error { return errors.New("boom") }})
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcomes[0].Verdict != tag.Error || ExitCode(res.Outcomes, "") != 2 {
		t.Fatalf("%+v", res.Outcomes[0])
	}
}

func TestSameSecondRunsDoNotCollide(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: ghWriter(0)})
	for range 2 {
		if _, err := Run(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	h, _ := tag.Store{Root: c.Records}.History(d[0].ID, "acme/api")
	if len(h) != 2 || !h[1].Header.Time.After(h[0].Header.Time) {
		t.Fatalf("%d tags", len(h))
	}
	if st := tag.VerifyChain(h); !st.OK {
		t.Fatalf("%+v", st)
	}
	_ = time.Second
}

// ghErrorWriter lists the repo but leaves out a branch rule field, so the drill
// errors on acme/api.
func ghErrorWriter(w graph.Writer) {
	g := graph.New()
	ghRepo(g, "team", true)
	node(g, "github:branch-rule/acme/api/default", graph.KindBranchRule, map[string]any{"bypass": "none"})
	for _, n := range g.Nodes("") {
		w.Node(n)
	}
}

// waiverStep is one run in a sequence and what it must report.
type waiverStep struct {
	name      string
	days      int
	conn      *fake
	verdict   string
	waived    bool
	newlyOpen bool
	exit      int // exit code with failOn ""
	exitOpen  int // exit code with failOn "open"
}

func runWaiverSteps(t *testing.T, expires string, steps []waiverStep) {
	t.Helper()
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d)
	c.Project.Waivers = []config.Waiver{{Drill: d[0].ID, Target: "acme/api", Reason: "r", ApprovedBy: "@a", Expires: expires}}
	for _, s := range steps {
		c.Connectors = []connector.Connector{s.conn}
		c.Scope.Now = testNow.AddDate(0, 0, s.days)
		res, err := Run(context.Background(), c)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Outcomes) != 1 {
			t.Fatalf("%s: outcomes %+v", s.name, res.Outcomes)
		}
		o := res.Outcomes[0]
		if o.Verdict != s.verdict || o.State != tag.Open || o.Waived != s.waived || o.NewlyOpen != s.newlyOpen {
			t.Errorf("%s: verdict=%s state=%s waived=%v newlyOpen=%v, want verdict=%s state=OPEN waived=%v newlyOpen=%v",
				s.name, o.Verdict, o.State, o.Waived, o.NewlyOpen, s.verdict, s.waived, s.newlyOpen)
		}
		if got := ExitCode(res.Outcomes, ""); got != s.exit {
			t.Errorf("%s: exit %d, want %d", s.name, got, s.exit)
		}
		if got := ExitCode(res.Outcomes, "open"); got != s.exitOpen {
			t.Errorf("%s: exit --fail-on open %d, want %d", s.name, got, s.exitOpen)
		}
		if a := BuildAttention(res.Outcomes); (len(a.NewlyOpen) == 1) != s.newlyOpen {
			t.Errorf("%s: attention newly open %d", s.name, len(a.NewlyOpen))
		}
	}
}

// A waived open safeguard stays waived through runs that cannot judge it, and
// counts as newly open exactly once when the waiver expires.
func TestWaiverHoldsThroughUnjudgedRuns(t *testing.T) {
	failing := func() *fake { return &fake{name: "github", available: true, write: ghWriter(0)} }
	gone := func() *fake { return &fake{name: "github", available: false} }
	broken := func() *fake { return &fake{name: "github", available: true, write: ghErrorWriter} }
	runWaiverSteps(t, "2026-11-20", []waiverStep{
		{"FAIL waived", 0, failing(), tag.Fail, true, false, 0, 0},
		{"SKIP waived", 1, gone(), tag.Skip, true, false, 0, 0},
		{"ERROR waived", 2, broken(), tag.Error, true, false, 2, 2},
		{"FAIL still waived", 3, failing(), tag.Fail, true, false, 0, 0},
		{"SKIP after expiry", 14, gone(), tag.Skip, false, true, 1, 1},
		{"SKIP again", 15, gone(), tag.Skip, false, false, 0, 1},
		{"FAIL again", 16, failing(), tag.Fail, false, false, 0, 1},
	})
}

// The waiver expires between a SKIP and the next FAIL: that FAIL is newly open.
func TestWaiverExpiryAfterSkipIsNewlyOpen(t *testing.T) {
	failing := func() *fake { return &fake{name: "github", available: true, write: ghWriter(0)} }
	gone := func() *fake { return &fake{name: "github", available: false} }
	runWaiverSteps(t, "2026-11-20", []waiverStep{
		{"FAIL waived", 0, failing(), tag.Fail, true, false, 0, 0},
		{"SKIP waived", 1, gone(), tag.Skip, true, false, 0, 0},
		{"FAIL after expiry", 14, failing(), tag.Fail, false, true, 1, 1},
		{"FAIL again", 15, failing(), tag.Fail, false, false, 0, 1},
	})
}
