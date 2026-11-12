package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
)

// githubWriter writes one repo as the GitHub connector does.
func githubWriter(approvals int64, bypass string) func(graph.Writer) {
	return func(w graph.Writer) {
		w.Node(graph.Node{ID: "github:repo/acme/api", Kind: graph.KindGitHubRepo, Source: "github", SeenAt: testNow,
			Attrs: map[string]any{"name": "acme/api", "private": true, "plan": "team", "protection_available": true}})
		w.Node(graph.Node{ID: "github:actions/acme/api", Kind: graph.KindActionsPerms, Source: "github", SeenAt: testNow,
			Attrs: map[string]any{"can_approve_pull_requests": false, "default_token_permission": "read"}})
		w.Node(graph.Node{ID: "github:branch-rule/acme/api/default", Kind: graph.KindBranchRule, Source: "github", SeenAt: testNow,
			Attrs: map[string]any{"required_approvals": approvals, "dismiss_stale": true, "code_owner_review": false, "bypass": bypass,
				"bypass_source": "api", "force_push_allowed": false, "deletion_allowed": false}})
	}
}

func TestRunStoresWhatChangedSinceThePreviousRun(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: githubWriter(1, "none")})
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Diff != nil || res.DiffPath != "" {
		t.Fatal("the first run has nothing to compare with")
	}

	c.Connectors = []connector.Connector{&fake{name: "github", available: true, write: githubWriter(0, "allowed")}}
	c.Scope.Now = testNow.AddDate(0, 0, 7)
	res, err = Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Diff == nil || res.DiffPath == "" {
		t.Fatal("no diff")
	}
	got := []string{}
	for _, ch := range res.Diff.Changes {
		got = append(got, ch.Type)
		if len(ch.CaughtBy) != 1 || ch.CaughtBy[0].Drill != "change/human-review-required" {
			t.Errorf("the failing drill read this node, so it also caught it: %+v", ch)
		}
	}
	if !slices.Equal(got, []string{graph.ChangeBypassOn, graph.ChangeWeakened}) {
		t.Fatalf("types = %v", got)
	}

	stored, err := ReadDiff(res.DiffPath)
	if err != nil {
		t.Fatal(err)
	}
	snaps, _ := RunSnapshots(filepath.Join(c.Records, "snapshots"))
	if len(snaps) != 2 || filepath.Base(res.DiffPath) != DiffName(snaps[1]) {
		t.Fatalf("diff %s for snapshots %v", res.DiffPath, snaps)
	}
	for i, want := range []string{stored.FromSHA256, stored.ToSHA256} {
		if sum, _ := FileSHA256(snaps[i]); sum != want || want == "" {
			t.Fatalf("snapshot %d: sha %s, recorded %s", i, sum, want)
		}
	}
	if len(stored.Changes) != 2 || stored.From.IsZero() || stored.To.IsZero() {
		t.Fatalf("%+v", stored)
	}
	latest, _ := graph.ReadSnapshot(snaps[1])
	if latest.Stream != "local" || latest.Coverage == nil || !slices.Equal(latest.Coverage.Read, []string{"github"}) {
		t.Fatalf("coverage not recorded: %+v %+v", latest.Stream, latest.Coverage)
	}

	// Compacting the snapshots does not break reading the diff.
	if n, err := graph.Compact(filepath.Join(c.Records, "snapshots"), testNow.AddDate(3, 0, 0)); err != nil || n != 2 {
		t.Fatalf("compact: %d %v", n, err)
	}
	if again, err := LatestDiff(c.Records); err != nil || again == nil || len(again.Changes) != 2 {
		t.Fatalf("diff after compaction: %v %v", again, err)
	}
}

func TestRunWithAFailedConnectorReportsNoRemovals(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: githubWriter(1, "none")})
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Connectors = []connector.Connector{&fake{name: "github", available: true, collect: func(connector.Scope) error {
		return errors.New("502 from api.github.com")
	}}}
	c.Scope.Now = testNow.AddDate(0, 0, 7)
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Diff.Changes) != 0 {
		t.Fatalf("an outage read as removals: %+v", res.Diff.Changes)
	}
	if !slices.Equal(res.Diff.Skipped, []string{"github: failed in the later run"}) {
		t.Fatalf("skipped = %v", res.Diff.Skipped)
	}
}

func TestRunInAPublicRepoDiffsButWritesNothing(t *testing.T) {
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: githubWriter(1, "none")})
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.WriteRecords = false
	c.Connectors = []connector.Connector{&fake{name: "github", available: true, write: githubWriter(1, "allowed")}}
	c.Scope.Now = testNow.AddDate(0, 0, 7)
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Diff == nil || len(res.Diff.Changes) != 1 || res.DiffPath != "" {
		t.Fatalf("%+v %q", res.Diff, res.DiffPath)
	}
	if _, err := os.Stat(filepath.Join(c.Records, "diffs")); !os.IsNotExist(err) {
		t.Fatal("a public run wrote a diff")
	}
}

var previousFact sync.Once

func TestFactReceivesThePreviousRun(t *testing.T) {
	var seen []graph.Reader
	previousFact.Do(func() {
		facts.Register(facts.Def{Name: "test.previous", Connector: "github", Shape: facts.List(facts.Any), Fn: func(_ graph.Reader, a facts.Args) (facts.Result, error) {
			seen = append(seen, a.Previous)
			return facts.Result{Data: []any{}}, nil
		}})
	})
	d := []*drill.Drill{{ID: "test/previous", ForEach: "test.previous", Severity: "low"}}
	c := baseConfig(t, d, &fake{name: "github", available: true, write: githubWriter(1, "none")})
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Scope.Now = testNow.AddDate(0, 0, 7)
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] != nil || seen[1] == nil {
		t.Fatalf("previous per run: %v", seen)
	}
	if _, ok := seen[1].Get("github:branch-rule/acme/api/default"); !ok {
		t.Fatal("the previous graph does not hold the previous run")
	}

	// A drill test fixture has no previous run.
	o := Options{Now: testNow, Available: map[string]bool{"github": true}, Fixture: map[string]facts.Result{}}
	Decide(&drill.Drill{ID: "test/previous", ForEach: "test.previous"}, graph.New(), o)
	if len(seen) != 3 || seen[2] != nil {
		t.Fatal("a fixture run has no previous graph")
	}
}

func TestAnnotateGroupsByPerson(t *testing.T) {
	old := graph.Snapshot{}
	new := graph.Snapshot{Edges: []graph.Edge{{From: "person:aaaa1111bbbb2222", To: "google:user/x", Kind: graph.EdgeSamePerson, Source: "link"}}}
	d := graph.DiffResult{Changes: []graph.Change{
		{Type: graph.ChangeNewAdmin, Subject: "google:user/x", Weakening: true},
		{Type: graph.ChangeNewKey, Subject: "aws:key/AKIAAAAAAAAAAAAAAAA1", Weakening: true},
		{Type: graph.ChangeRemoved, Subject: "google:user/x", Attr: "suspended"},
	}}
	Annotate(&d, old, new, Caught{"aws:key/AKIAAAAAAAAAAAAAAAA1": {{Drill: "access/no-shared-prod-keys", Target: ""}}})
	if d.Changes[0].Person != "aaaa1111" || d.Changes[1].Person != "" || d.Changes[1].CaughtBy[0].Drill != "access/no-shared-prod-keys" {
		t.Fatalf("%+v", d.Changes)
	}
	groups := GroupChanges(d.Changes)
	titles := []string{}
	for _, g := range groups {
		titles = append(titles, g.Title)
	}
	if !slices.Equal(titles, []string{"Person aaaa1111", "New key held", "Person aaaa1111"}) {
		t.Fatalf("groups %v", titles)
	}
}

// Linking joins GitHub and GCP accounts to people, so one person's changes
// across systems read as one story.
func TestAnnotateGroupsGitHubAndGCPByPerson(t *testing.T) {
	res, _ := runPeople(t, peopleEstate{})
	snap := graph.TakeSnapshot(res.Graph, testNow)
	ana := personID("ana@acme.example")
	var gh, binding graph.ID
	for _, e := range res.Graph.Edges(graph.EdgeSamePerson) {
		if e.From != ana {
			continue
		}
		switch {
		case strings.HasPrefix(string(e.To), "github:user/"):
			gh = e.To
		case strings.HasPrefix(string(e.To), "gcp:binding/"):
			binding = e.To
		}
	}
	if gh == "" || binding == "" {
		t.Fatalf("ana is not linked to her GitHub account and GCP binding")
	}
	d := graph.DiffResult{Changes: []graph.Change{
		{Type: graph.ChangeNewAdmin, Subject: gh, Weakening: true},
		{Type: graph.ChangeNewAdmin, Subject: binding, Weakening: true},
		{Type: graph.ChangeNewAdmin, Subject: graph.ID("google:user/" + salt.Email("ana@acme.example")), Weakening: true},
	}}
	Annotate(&d, graph.Snapshot{}, snap, Caught{})
	want := PersonShortID(ana)
	for _, ch := range d.Changes {
		if ch.Person != want {
			t.Fatalf("not grouped under ana: %+v", ch)
		}
	}
	if groups := GroupChanges(d.Changes); len(groups) != 1 || groups[0].Person != want || len(groups[0].Changes) != 3 {
		t.Fatalf("%+v", groups)
	}
}
