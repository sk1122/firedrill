package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

var now = time.Date(2026, 11, 7, 9, 0, 0, 0, time.UTC)

func writeTag(t *testing.T, s tag.Store, verdict, state string, at time.Time, read ...string) {
	t.Helper()
	tg := &tag.Tag{Header: tag.Header{DrillID: "change/x", Target: "acme/api", Verdict: verdict, State: state, Time: at, Severity: "high", Owner: "@a"},
		Evidence: tag.Evidence{Read: read}}
	if _, err := s.Write(tg); err != nil {
		t.Fatal(err)
	}
}

func estate() *graph.Estate {
	g := graph.New()
	g.Node(graph.Node{ID: "github:repo/acme/api", Kind: graph.KindGitHubRepo, Attrs: map[string]any{"name": "acme/api"}, SeenAt: now})
	g.Node(graph.Node{ID: "github:repo/acme/web", Kind: graph.KindGitHubRepo, Attrs: map[string]any{"name": "acme/web"}, SeenAt: now})
	g.Node(graph.Node{ID: "codeowners:acme/api", Kind: graph.KindCodeowners, SeenAt: now})
	g.Node(graph.Node{ID: "host:a.acme.com", Kind: graph.KindHost, Attrs: map[string]any{"host": "a.acme.com"}, SeenAt: now})
	g.Node(graph.Node{ID: "aws:iam-role/1/Admin", Kind: graph.KindAWSPrincipal, Attrs: map[string]any{"name": "Admin", "is_admin": true, "excluded": false}, SeenAt: now})
	g.Node(graph.Node{ID: "aws:iam-role/1/Glass", Kind: graph.KindAWSPrincipal, Attrs: map[string]any{"name": "Glass", "is_admin": true, "excluded": true}, SeenAt: now})
	g.Node(graph.Node{ID: "google:user/abc123", Kind: graph.KindIdentityUser, Attrs: map[string]any{"is_admin": true}, SeenAt: now})
	g.Edge(graph.Edge{From: "person:abc", To: "google:user/abc123", Kind: graph.EdgeSamePerson})
	e := graph.NewEstate()
	e.Merge(graph.TakeSnapshot(g, now))
	return e
}

func TestBoardCoverageStateAndPages(t *testing.T) {
	s := tag.Store{Root: t.TempDir()}
	for i := range 10 {
		writeTag(t, s, tag.Pass, tag.Closed, now.AddDate(0, 0, -70+7*i), "github:repo/acme/api")
	}
	writeTag(t, s, tag.Fail, tag.Open, now.AddDate(0, 0, 1), "github:repo/acme/api")
	writeTag(t, s, tag.NA, tag.Open, now.AddDate(0, 0, 8), "github:repo/acme/api")

	b, err := Build(s, estate(), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Packs) != 1 || len(b.Packs[0].Safeguards) != 1 {
		t.Fatalf("%+v", b.Packs)
	}
	sg := b.Packs[0].Safeguards[0]
	if sg.Lamp != "fail" || sg.Label != "OPEN" || !sg.Unverified {
		t.Fatalf("an open safeguard stays red under N/A: %+v", sg)
	}
	if len(sg.Runs) != LastRuns {
		t.Fatalf("runs: %d", len(sg.Runs))
	}
	if b.Counts.Open != 1 {
		t.Fatalf("%+v", b.Counts)
	}
	if len(b.Attention) != 1 || b.Attention[0].Kind != "Open, unverified" {
		t.Fatalf("the board leads with what needs attention: %+v", b.Attention)
	}
	names := func(items []Item) string {
		var out []string
		for _, it := range items {
			out = append(out, it.Name)
		}
		return strings.Join(out, ",")
	}
	untouched := names(b.Untouched)
	if strings.Contains(untouched, "acme/api") || !strings.Contains(untouched, "acme/web") {
		t.Fatalf("untouched: %s", untouched)
	}
	unowned := names(b.Unowned)
	if strings.Contains(unowned, "acme/api") || strings.Contains(unowned, "Glass") || strings.Contains(unowned, "abc123") {
		t.Fatalf("unowned has an owned item: %s", unowned)
	}
	for _, want := range []string{"acme/web", "a.acme.com", "Admin"} {
		if !strings.Contains(unowned, want) {
			t.Fatalf("unowned missing %s: %s", want, unowned)
		}
	}

	dir := t.TempDir()
	path, err := Write(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(path)
	for _, want := range []string{"change/x", "@a", "OPEN", "items/"} {
		if !strings.Contains(string(html), want) {
			t.Errorf("board missing %q", want)
		}
	}
	item, err := os.ReadFile(filepath.Join(dir, "items", tag.Slug("github:repo/acme/api")+".html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(item), "change/x") {
		t.Error("an item page lists every verdict that involved it")
	}
}

func TestLamp(t *testing.T) {
	cases := []struct{ verdict, state, class, label string }{
		{tag.Pass, tag.Closed, "pass", "PASS"},
		{tag.Fail, tag.Open, "fail", "OPEN"},
		{tag.Warn, tag.Open, "fail", "OPEN"},
		{tag.Warn, tag.Unknown, "warn", "WARN"},
		{tag.NA, tag.Unknown, "na", "N/A"},
		{tag.Skip, tag.Unknown, "skip", "SKIP"},
		{tag.Error, tag.Closed, "err", "ERR"},
	}
	for _, c := range cases {
		class, label := lamp(c.verdict, c.state)
		if class != c.class || label != c.label {
			t.Errorf("%s/%s: got %s %s", c.verdict, c.state, class, label)
		}
	}
}

func TestEmptyBoardRenders(t *testing.T) {
	b, err := Build(tag.Store{Root: t.TempDir()}, graph.NewEstate(), nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Write(t.TempDir(), b); err != nil {
		t.Fatal(err)
	}
}
