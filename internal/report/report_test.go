package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
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

	b, err := Build(s, estate(), nil, now, run.Rules{})
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
	b, err := Build(tag.Store{Root: t.TempDir()}, graph.NewEstate(), nil, now, run.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Write(t.TempDir(), b); err != nil {
		t.Fatal(err)
	}
}

func writeFor(t *testing.T, s tag.Store, drillID, target, sev, verdict, state, reason string, waived bool, at time.Time) {
	t.Helper()
	tg := &tag.Tag{Header: tag.Header{DrillID: drillID, Target: target, Verdict: verdict, State: state, Time: at,
		Severity: sev, Owner: "@a", Reason: reason, Waived: waived}}
	if _, err := s.Write(tg); err != nil {
		t.Fatal(err)
	}
}

func TestStillOpenStaysOnTopAndNAFolds(t *testing.T) {
	s := tag.Store{Root: t.TempDir()}
	day1, day2 := now.AddDate(0, 0, -7), now
	// Open in both runs: nothing changed, but it must still lead the board.
	writeFor(t, s, "gcp/keys", "p1", "high", tag.Fail, tag.Open, "old key", false, day1)
	writeFor(t, s, "gcp/keys", "p1", "high", tag.Fail, tag.Open, "old key", false, day2)
	writeFor(t, s, "gcp/buckets", "p1", "critical", tag.Fail, tag.Open, "bucket site", false, day1)
	writeFor(t, s, "gcp/buckets", "p1", "critical", tag.Fail, tag.Open, "bucket site", false, day2)
	// Waived and open: not listed.
	writeFor(t, s, "gcp/owners", "p1", "critical", tag.Fail, tag.Open, "", true, day2)
	// N/A and not open: folded away.
	writeFor(t, s, "gcp/editors", "p2", "high", tag.NA, tag.Unknown, "no bindings", false, day2)
	// N/A but still open: stays shown.
	writeFor(t, s, "gcp/editors", "p3", "high", tag.Fail, tag.Open, "", false, day1)
	writeFor(t, s, "gcp/editors", "p3", "high", tag.NA, tag.Open, "", false, day2)

	b, err := Build(s, nil, nil, now, run.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range b.Attention {
		got = append(got, r.Kind+" "+r.DrillID+" "+r.Target+" "+r.Severity)
	}
	want := []string{"Open, unverified gcp/editors p3 high", "Still open gcp/buckets p1 critical", "Still open gcp/keys p1 high"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("attention:\n got %q\nwant %q", got, want)
	}
	if b.Attention[1].Reason != "bucket site" {
		t.Fatalf("the reason is listed: %+v", b.Attention[1])
	}
	pk := b.Packs[0]
	if len(pk.NotApplicable) != 1 || pk.NotApplicable[0].Target != "p2" {
		t.Fatalf("N/A folds: %+v", pk.NotApplicable)
	}
	if len(pk.Shown) != 4 {
		t.Fatalf("shown: %d", len(pk.Shown))
	}

	path, err := Write(t.TempDir(), b)
	if err != nil {
		t.Fatal(err)
	}
	html, _ := os.ReadFile(path)
	if !strings.Contains(string(html), "<summary>1 not applicable</summary>") || !strings.Contains(string(html), "Still open") {
		t.Fatal("the board folds N/A and lists still-open safeguards")
	}
}

func TestChangesPage(t *testing.T) {
	s := tag.Store{Root: t.TempDir()}
	writeTag(t, s, tag.Fail, tag.Open, now, "github:repo/acme/api")
	b, err := Build(s, estate(), nil, now, run.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	rec := &run.DiffRecord{DiffResult: graph.DiffResult{From: now.AddDate(0, 0, -7), To: now, Skipped: []string{"aws: failed in the later run"},
		Changes: []graph.Change{
			{Type: graph.ChangeNewAdmin, Summary: "Google user abc12300: is now an admin", Subject: "google:user/abc123", Kind: graph.KindIdentityUser, System: "google", Weakening: true, Person: "abc"},
			{Type: graph.ChangePublic, Summary: "repo acme/api: is now public", Subject: "github:repo/acme/api", Kind: graph.KindGitHubRepo, System: "github", Weakening: true,
				CaughtBy: []graph.DrillRef{{Drill: "change/x", Target: "acme/api"}}},
			{Type: graph.ChangeRemoved, Summary: "gone: host b.acme.com", Subject: "host:b.acme.com", Kind: graph.KindHost, System: "ctlog"},
		}}}
	AddChanges(b, rec)
	dir := t.TempDir()
	path, err := Write(dir, b)
	if err != nil {
		t.Fatal(err)
	}
	index, _ := os.ReadFile(path)
	if !strings.Contains(string(index), `href="changes.html">Changed since the last run: 2 weakening, 1 other`) {
		t.Fatal("the board links to the Changes page")
	}
	slug := tag.Slug("change/x-" + tag.Slug("acme/api"))
	if !strings.Contains(string(index), `id="`+slug+`"`) {
		t.Fatal("a safeguard card carries an anchor to link to")
	}
	page, err := os.ReadFile(filepath.Join(dir, "changes.html"))
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	weak, person, other := strings.Index(html, "Weakenings (2)"), strings.Index(html, "Person abc (1)"), strings.Index(html, "Other changes (1)")
	if weak < 0 || person < weak || other < person {
		t.Fatalf("weakenings first, grouped by person:\n%s", html)
	}
	for _, want := range []string{
		`<a href="index.html#` + slug + `">change/x</a>`,
		`<a href="items/` + tag.Slug("github:repo/acme/api") + `.html">repo acme/api: is now public</a>`,
		`<a href="items/` + tag.Slug("google:user/abc123") + `.html">`,
		"gone: host b.acme.com", "aws: failed in the later run",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("changes page missing %q", want)
		}
	}

	// An empty diff is one line.
	AddChanges(b, &run.DiffRecord{DiffResult: graph.DiffResult{From: now.AddDate(0, 0, -7), To: now}})
	if _, err := Write(dir, b); err != nil {
		t.Fatal(err)
	}
	page, _ = os.ReadFile(filepath.Join(dir, "changes.html"))
	if !strings.Contains(string(page), "<p>Nothing changed since the last run.</p>") || strings.Contains(string(page), "weakening") {
		t.Fatalf("empty diff:\n%s", page)
	}
}

func TestTier1KindsAreCovered(t *testing.T) {
	g := graph.New()
	g.Node(graph.Node{ID: "google:oauth-app/1234-notes.apps.googleusercontent.com", Kind: graph.KindOAuthApp, Attrs: map[string]any{"name": "Acme Notes AI"}, SeenAt: now})
	g.Node(graph.Node{ID: "aws:db/111122223333/us-east-1/orders", Kind: graph.KindDatabase, Attrs: map[string]any{"name": "orders"}, SeenAt: now})
	g.Node(graph.Node{ID: "openai:key/proj_acme/key_acmeci", Kind: graph.KindAIKey, Attrs: map[string]any{"name": "ci"}, SeenAt: now})
	e := graph.NewEstate()
	e.Merge(graph.TakeSnapshot(g, now))
	b, err := Build(tag.Store{Root: t.TempDir()}, e, nil, now, run.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, it := range b.Untouched {
		names = append(names, it.Name)
	}
	got := strings.Join(names, ",")
	for _, want := range []string{"Acme Notes AI", "orders", "ci"} {
		if !strings.Contains(got, want) {
			t.Errorf("coverage lists %s: %s", want, got)
		}
	}
}

func TestDisplayNameOfGitHubPeople(t *testing.T) {
	u := &graph.EstateItem{ID: "github:user/aaaa1111bbbb2222cccc3333dddd4444", Kind: graph.KindGitHubUser,
		Attrs: map[string]any{"org": "acme", "org_role": "admin", "type": "user"}}
	if got := displayName(u); got != "GitHub user aaaa1111" {
		t.Fatalf("a GitHub user shows by a short hashed ID: %q", got)
	}
	team := &graph.EstateItem{ID: "github:team/acme/core", Kind: graph.KindGitHubTeam, Attrs: map[string]any{"slug": "core"}}
	if got := displayName(team); got != "team core" {
		t.Fatal(got)
	}
	for _, k := range []string{graph.KindGitHubUser, graph.KindGitHubTeam, graph.KindGitHubApp, graph.KindDeployKey} {
		if !coverageKinds[k] {
			t.Errorf("%s is listed in coverage", k)
		}
	}
}

// An admin binding is owned by the person who holds it, directly or through a
// group, or by its owners.yaml entry. A project's own owns edges own nothing.
func TestUnownedUsesLinksAndOwnersRegister(t *testing.T) {
	g := graph.New()
	bind := func(id graph.ID, member string, attrs map[string]any) {
		a := map[string]any{"project": "acme-prod", "role": "roles/owner", "member_type": member, "is_admin": true, "power_known": true}
		for k, v := range attrs {
			a[k] = v
		}
		g.Node(graph.Node{ID: id, Kind: graph.KindGCPBinding, Attrs: a, SeenAt: now})
		g.Edge(graph.Edge{From: "gcp:project/acme-prod", To: id, Kind: graph.EdgeOwns})
	}
	bind("gcp:binding/acme-prod/roles/owner/aaaa1111", "user", nil)
	bind("gcp:binding/acme-prod/roles/owner/bbbb2222", "group", nil)
	bind("gcp:binding/acme-prod/roles/owner/cccc3333", "service_account", nil)
	bind("gcp:binding/acme-prod/roles/owner/dddd4444", "service_account", nil)
	bind("gcp:binding/acme-prod/roles/editor/eeee5555", "service_account", map[string]any{"google_managed": true})
	bind("gcp:binding/acme-prod/roles/viewer/ffff6666", "user", map[string]any{"is_admin": false})
	g.Node(graph.Node{ID: "person:1234567890abcdef", Kind: graph.KindPerson, Attrs: map[string]any{"systems": []any{"gcp"}}, SeenAt: now})
	g.Edge(graph.Edge{From: "person:1234567890abcdef", To: "gcp:binding/acme-prod/roles/owner/aaaa1111", Kind: graph.EdgeSamePerson})
	g.Edge(graph.Edge{From: "person:1234567890abcdef", To: "gcp:binding/acme-prod/roles/owner/bbbb2222", Kind: graph.EdgeViaGroup})
	g.Edge(graph.Edge{From: "config-owner:ci@acme-prod.iam.gserviceaccount.com", To: "gcp:binding/acme-prod/roles/owner/cccc3333", Kind: graph.EdgeOwns})
	g.Node(graph.Node{ID: "google:group/9999aaaa8888bbbb", Kind: graph.KindGoogleGroup, Attrs: map[string]any{"members_known": true}, SeenAt: now})
	e := graph.NewEstate()
	e.Merge(graph.TakeSnapshot(g, now))
	b, err := Build(tag.Store{Root: t.TempDir()}, e, nil, now, run.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Unowned) != 1 || b.Unowned[0].ID != "gcp:binding/acme-prod/roles/owner/dddd4444" ||
		b.Unowned[0].Name != "roles/owner for a service account (dddd4444) in acme-prod" {
		t.Fatalf("%+v", b.Unowned)
	}
	for _, it := range b.Items {
		if it.ID == "google:group/9999aaaa8888bbbb" && it.Name != "Google group 9999aaaa" {
			t.Fatalf("a group shows by a short hashed ID: %q", it.Name)
		}
	}
	if got := displayName(&graph.EstateItem{ID: "person:1234567890abcdef", Kind: graph.KindPerson}); got != "person 12345678" {
		t.Fatal(got)
	}
}
