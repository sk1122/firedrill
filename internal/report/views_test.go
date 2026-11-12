package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

var viewSalt = graph.NewHasher("salt")

// The fakes a page must never show: addresses, logins and a token value.
// They live only in Private, as connectors keep them.
const fakeToken = "ghp_" + "Zx8mQ2pL9vT4rW7yB1nC6dF3Zx8mQ2pL9vT4"

var fakes = []string{"ana@acme.example", "bo@acme.example", "dee@acme.example", "Ana-Dev", "ghost-owner", fakeToken}

func pid(email string) graph.ID { return graph.ID("person:" + viewSalt.Email(email)) }

// mixedSnapshot is a run over acme as the connectors and link step write it:
// ana is a Workspace super admin and GitHub org owner who can bypass review on
// acme/api, which deploys to production, and holds Owner on acme-prod; bo has
// only a Workspace account; dee left and is still active; ghost-owner owns the
// org and maps to nobody; a service account holds Editor with no owner; and
// the agent config in acme/api can read Ana's token.
func mixedSnapshot(t *testing.T) graph.Snapshot {
	t.Helper()
	g := graph.New()
	n := func(id graph.ID, kind string, attrs map[string]any, private map[string]any) {
		g.Node(graph.Node{ID: id, Kind: kind, Attrs: attrs, Private: private, SeenAt: now, Source: "fixture"})
	}
	e := func(from, to graph.ID, kind string) { g.Edge(graph.Edge{From: from, To: to, Kind: kind}) }
	graph.WriteScan(g, "google", "google_users", "", 3, "", now)
	n(graph.ScanID("github_people", "acme"), graph.KindScan, map[string]any{"scanner": "github_people", "scope": "acme", "inspected": int64(2)}, nil)
	person := func(email string, kind string, systems ...any) graph.ID {
		attrs := map[string]any{"systems": systems, "external": false}
		if kind == graph.KindLeaver {
			attrs["leave_date"] = "2026-10-01"
		}
		n(pid(email), kind, attrs, map[string]any{"email": email})
		return pid(email)
	}
	guser := func(p graph.ID, email string, admin bool) {
		id := graph.ID("google:user/" + viewSalt.Email(email))
		n(id, graph.KindIdentityUser, map[string]any{"is_admin": admin, "is_delegated_admin": false, "suspended": false}, map[string]any{"email": email})
		e(p, id, graph.EdgeSamePerson)
	}
	ghuser := func(login string) graph.ID {
		id := graph.ID("github:user/" + viewSalt.Sum(strings.ToLower(login)))
		n(id, graph.KindGitHubUser, map[string]any{"org": "acme", "org_role": "admin", "type": "user"}, map[string]any{"login": login})
		return id
	}
	ana := person("ana@acme.example", graph.KindPerson, "gcp", "github", "google")
	bo := person("bo@acme.example", graph.KindPerson, "google")
	dee := person("dee@acme.example", graph.KindLeaver, "google")
	guser(ana, "ana@acme.example", true)
	guser(bo, "bo@acme.example", false)
	guser(dee, "dee@acme.example", false)
	anaGH := ghuser("Ana-Dev")
	e(ana, anaGH, graph.EdgeSamePerson)
	ghuser("ghost-owner")
	n("github:repo/acme/api", graph.KindGitHubRepo, map[string]any{"name": "acme/api", "private": true, "plan": "team", "protection_available": true}, nil)
	n("github:env/acme/api/production", graph.KindEnvironment, map[string]any{"required_reviewers": []any{}}, nil)
	e("github:repo/acme/api", "github:env/acme/api/production", graph.EdgeDeploysTo)
	n("github:branch-rule/acme/api/default", graph.KindBranchRule, map[string]any{"bypass": "allowed", "bypass_actors_known": true}, nil)
	e(anaGH, "github:repo/acme/api", graph.EdgeCanBypass)
	e(anaGH, "github:repo/acme/api", graph.EdgeAdminOf)
	n("gcp:project/acme-prod", graph.KindGCPProject, map[string]any{"name": "acme-prod", "production": true}, nil)
	bind := func(role, member string, admin, destructive bool) graph.ID {
		id := graph.ID("gcp:binding/acme-prod/" + role + "/" + viewSalt.Sum(member))
		kind := "user"
		if strings.HasPrefix(member, "serviceAccount:") {
			kind = "service_account"
		}
		n(id, graph.KindGCPBinding, map[string]any{"project": "acme-prod", "role": role, "member_type": kind, "is_admin": admin,
			"destructive": destructive, "power_known": true, "production": true, "google_managed": false, "conditional": false},
			map[string]any{"email": strings.TrimPrefix(member, "user:")})
		e("gcp:project/acme-prod", id, graph.EdgeOwns)
		return id
	}
	e(ana, bind("roles/owner", "user:ana@acme.example", true, true), graph.EdgeSamePerson)
	bind("roles/editor", "serviceAccount:deployer@acme-prod.iam.gserviceaccount.com", true, true)
	n("agent:acme/api/.claude/settings.json", graph.KindAgentConfig, map[string]any{"repo": "acme/api", "tool": "claude-code", "scope": "repo",
		"file": ".claude/settings.json", "unguarded_destructive": []any{"rm -rf"}, "mcp_servers": []any{
			map[string]any{"name": "fs", "transport": "stdio", "host": "", "host_known": false, "command": "npx", "package": "@acme/mcp-fs",
				"version": "", "pinned": false, "package_known": true}},
		"egress": "partial", "egress_hosts": []any{"github.com", "registry.npmjs.org"}, "egress_unbounded": false}, nil)
	hash := viewSalt.Sum(fakeToken)
	n(graph.ID("secret:"+hash+"@acme/api/.claude/settings.local.json:2"), graph.KindSecretSeen, map[string]any{"repo": "acme/api",
		"kind": "github_token", "file": ".claude/settings.local.json", "hash": hash, "agent_readable": true}, map[string]any{"value": fakeToken})
	n(graph.ID("secret:"+hash), graph.KindSecret, nil, nil)
	e(graph.ID("secret:"+hash), "file:acme/api/.claude/settings.local.json", graph.EdgeFoundIn)
	e(graph.ID("secret:"+hash), "file:acme/web/.env", graph.EdgeFoundIn)
	// Through JSON, as a stored snapshot is read back.
	b, err := json.Marshal(graph.TakeSnapshot(g, now))
	if err != nil {
		t.Fatal(err)
	}
	var s graph.Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func buildViews(t *testing.T, snap *graph.Snapshot, diff *run.DiffRecord) (string, *Board) {
	t.Helper()
	s := tag.Store{Root: t.TempDir()}
	tg := &tag.Tag{Header: tag.Header{DrillID: "paths/no-single-person-code-to-prod-data", Target: "acme/api", Verdict: tag.Fail, State: tag.Open,
		Time: now, Severity: "critical"}, Evidence: tag.Evidence{Read: []string{"github:repo/acme/api", "gcp:project/acme-prod"}}}
	if _, err := s.Write(tg); err != nil {
		t.Fatal(err)
	}
	var est *graph.Estate
	if snap != nil {
		est = graph.NewEstate()
		est.Merge(*snap)
	}
	b, err := Build(s, est, nil, now, run.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	AddViews(b, snap, diff, now)
	dir := t.TempDir()
	if _, err := Write(dir, b); err != nil {
		t.Fatal(err)
	}
	return dir, b
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

var hrefRe = regexp.MustCompile(`href="([^"]*)"`)
var idRe = regexp.MustCompile(`id="([^"]*)"`)

// checkLinks resolves every relative link in every page to a file, and an
// anchor to an id on that page.
func checkLinks(t *testing.T, dir string) int {
	t.Helper()
	ids := map[string]map[string]bool{}
	pages := map[string]string{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".html") {
			pages[p] = read(t, p)
			ids[p] = map[string]bool{}
			for _, m := range idRe.FindAllStringSubmatch(pages[p], -1) {
				ids[p][m[1]] = true
			}
		}
		return err
	})
	links := 0
	for p, body := range pages {
		for _, m := range hrefRe.FindAllStringSubmatch(body, -1) {
			h := strings.ReplaceAll(m[1], "&amp;", "&")
			if strings.HasPrefix(h, "data:") || strings.HasPrefix(h, "http") || strings.HasPrefix(h, "#") {
				continue
			}
			file, anchor, _ := strings.Cut(h, "#")
			target := filepath.Clean(filepath.Join(filepath.Dir(p), file))
			if _, err := os.Stat(target); err != nil {
				t.Errorf("%s links to %s, which does not exist", p, h)
				continue
			}
			if anchor != "" && strings.HasSuffix(target, ".html") && !ids[target][anchor] {
				t.Errorf("%s links to %s, which has no id %s", p, file, anchor)
			}
			links++
		}
	}
	return links
}

// svgOf returns the drawing on a graph page and checks it is well-formed XML.
func svgOf(t *testing.T, page string) string {
	t.Helper()
	start, end := strings.Index(page, "<svg"), strings.LastIndex(page, "</svg>")
	if start < 0 || end < 0 {
		t.Fatalf("no drawing:\n%s", page)
	}
	svg := page[start : end+len("</svg>")]
	dec := xml.NewDecoder(strings.NewReader(svg))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("the drawing is not well-formed XML: %v\n%s", err, svg)
		}
	}
	return svg
}

func TestPeopleAgentsAndGraphPages(t *testing.T) {
	snap := mixedSnapshot(t)
	newEdge := graph.Edge{From: graph.ID("github:user/" + viewSalt.Sum("ana-dev")), To: "github:repo/acme/api", Kind: graph.EdgeCanBypass}
	diff := &run.DiffRecord{DiffResult: graph.DiffResult{From: now.AddDate(0, 0, -7), To: now, Changes: []graph.Change{
		{Type: graph.ChangeBypassActor, Summary: "a GitHub user can now bypass review on acme/api", Subject: newEdge.From, Edge: &newEdge, System: "github", Weakening: true}}}}
	dir, b := buildViews(t, &snap, diff)
	ana, dee, bo := shortOf(string(pid("ana@acme.example"))), shortOf(string(pid("dee@acme.example"))), shortOf(string(pid("bo@acme.example")))
	for _, f := range []string{"people.html", "people-github.html", "people-gcp.html", "people-google.html", "agents.html", "fonts.css",
		"graph/production.html", "graph/changes.html", "graph/person-" + ana + ".html", "graph/person-" + dee + ".html"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "graph/person-"+bo+".html")); err == nil {
		t.Error("bo holds no power, so has no page")
	}
	if n := checkLinks(t, dir); n < 20 {
		t.Fatalf("only %d links checked", n)
	}
	// Nothing a person is known by, and no secret value, reaches any page.
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			body := read(t, p)
			for _, f := range fakes {
				if strings.Contains(body, f) {
					t.Errorf("%s shows %s", p, f)
				}
			}
		}
		return err
	})

	people := read(t, filepath.Join(dir, "people.html"))
	for _, want := range []string{`id="person-` + ana + `"`, "cut point", `href="graph/person-` + ana + `.html"`, "<summary>1</summary>",
		"a service account with power and no entry in owners.yaml", "GitHub user ", `href="people-gcp.html">GCP (1)</a>`,
		`<b>All (3)</b>`, `class="box"`, "no total and no ranking"} {
		if !strings.Contains(people, want) {
			t.Errorf("people page lacks %q", want)
		}
	}
	// Sorted by ID, never by power.
	var order []string
	for _, m := range regexp.MustCompile(`<tr id="person-([0-9a-f]{8})"`).FindAllStringSubmatch(people, -1) {
		order = append(order, m[1])
	}
	for i := 1; i < len(order); i++ {
		if order[i-1] > order[i] {
			t.Fatalf("rows not sorted by ID: %v", order)
		}
	}
	if gh := read(t, filepath.Join(dir, "people-github.html")); strings.Contains(gh, `id="person-`+bo+`"`) || !strings.Contains(gh, `id="person-`+ana+`"`) {
		t.Error("the GitHub filter lists only people with a GitHub account")
	}

	agents := read(t, filepath.Join(dir, "agents.html"))
	for _, want := range []string{"claude-code", "@acme/mcp-fs", "unpinned", "secret:" + viewSalt.Sum(fakeToken)[:12], "rm -rf", "yes, 1 person", "what can it touch?",
		"Outbound access", `<span class="warn">partial</span>`, "2 hosts", "registry.npmjs.org"} {
		if !strings.Contains(agents, want) {
			t.Errorf("agents page lacks %q", want)
		}
	}

	prod := read(t, filepath.Join(dir, "graph/production.html"))
	svg := svgOf(t, prod)
	if !strings.Contains(svg, `stroke-dasharray`) || !strings.Contains(svg, "a cut point: can bypass review on acme/api") {
		t.Error("the cut-point person is outlined")
	}
	if !strings.Contains(svg, `stroke="#D3261A" stroke-width="3"`) {
		t.Error("a node a failing critical drill read carries a red ring")
	}
	if !strings.Contains(svg, "<title>can_bypass</title>") || !strings.Contains(svg, "<title>deploys_to</title>") {
		t.Error("edges carry their kind as a title")
	}
	if !strings.Contains(svg, `href="../people.html#person-`+ana+`"`) {
		t.Error("a person node links to their row")
	}
	if strings.Contains(svg, "person "+bo) {
		t.Error("bo cannot reach production")
	}
	page := b.Views.Graphs[0]
	t.Logf("production graph: %d nodes, %d edges; zones %+v", page.Nodes, page.Edges, page.Zones)
	if page.Zones[1].Nodes != 1 || page.Zones[2].Nodes != 3 || page.Zones[3].Nodes != 3 {
		t.Errorf("ana; her GitHub user and two roles; repo, environment and project: %+v", page.Zones)
	}

	agentPage := ""
	for _, g := range b.Views.Graphs {
		if strings.HasPrefix(g.File, "agent-") {
			agentPage = read(t, filepath.Join(dir, "graph", g.File))
		}
	}
	asvg := svgOf(t, agentPage)
	for _, want := range []string{"can read", "acme/web/.env", "secret " + viewSalt.Sum(fakeToken)[:12], `href="../agents.html#agent-`} {
		if !strings.Contains(asvg, want) {
			t.Errorf("agent drawing lacks %q", want)
		}
	}
	changes := svgOf(t, read(t, filepath.Join(dir, "graph/changes.html")))
	if strings.Count(changes, `class="edge new"`) != 1 || !strings.Contains(changes, `class="edge"`) {
		t.Errorf("one new edge in the accent colour over the old ones:\n%s", changes)
	}
	index := read(t, filepath.Join(dir, "index.html"))
	for _, want := range []string{`href="people.html"`, `href="agents.html"`, `href="graph/production.html">Who can reach production data alone?`} {
		if !strings.Contains(index, want) {
			t.Errorf("the board lacks %q", want)
		}
	}
}

func TestGraphDrawsAtMostSixtyNodes(t *testing.T) {
	snap := mixedSnapshot(t)
	gh := graph.ID("github:user/" + viewSalt.Sum("ana-dev"))
	for i := range 90 {
		repo := graph.ID(fmt.Sprintf("github:repo/acme/r%02d", i))
		snap.Nodes = append(snap.Nodes, graph.Node{ID: repo, Kind: graph.KindGitHubRepo, Attrs: map[string]any{"name": string(repo)[12:]}})
		snap.Edges = append(snap.Edges, graph.Edge{From: gh, To: repo, Kind: graph.EdgeWritesTo})
	}
	dir, b := buildViews(t, &snap, nil)
	ana := shortOf(string(pid("ana@acme.example")))
	page := read(t, filepath.Join(dir, "graph/person-"+ana+".html"))
	svg := svgOf(t, page)
	if n := strings.Count(svg, "<rect"); n != MaxDrawn {
		t.Fatalf("drew %d nodes", n)
	}
	if !strings.Contains(page, "more not drawn") || !strings.Contains(page, `href="../people.html#person-`+ana+`"`) {
		t.Fatal("the page says what it left out and links to the rows")
	}
	// The person and their accounts are nearest, so they are always drawn.
	if !strings.Contains(svg, "person "+ana) {
		t.Fatal("the start node is drawn")
	}
	for _, g := range b.Views.Graphs {
		if g.Nodes > MaxDrawn {
			t.Fatalf("%s drew %d", g.File, g.Nodes)
		}
	}
}

func TestViewsEmptyStates(t *testing.T) {
	dir, _ := buildViews(t, nil, nil)
	if p := read(t, filepath.Join(dir, "people.html")); !strings.Contains(p, "No people were read — connect Google Workspace, GCP or GitHub.") {
		t.Fatalf("%s", p)
	}
	if p := read(t, filepath.Join(dir, "agents.html")); !strings.Contains(p, "No agent config was read yet") {
		t.Fatalf("%s", p)
	}
	// A snapshot with no people system read says the same.
	g := graph.New()
	g.Node(graph.Node{ID: "github:repo/acme/api", Kind: graph.KindGitHubRepo, Attrs: map[string]any{"name": "acme/api"}})
	snap := graph.TakeSnapshot(g, now)
	dir, b := buildViews(t, &snap, nil)
	if p := read(t, filepath.Join(dir, "people.html")); !strings.Contains(p, "No people were read — connect Google Workspace, GCP or GitHub.") {
		t.Fatalf("%s", p)
	}
	if p := read(t, filepath.Join(dir, "graph/production.html")); !strings.Contains(p, "Nothing to draw") {
		t.Fatalf("%s", p)
	}
	if p := read(t, filepath.Join(dir, "agents.html")); !strings.Contains(p, "No agent config was read.") {
		t.Fatalf("%s", p)
	}
	checkLinks(t, dir)
	if len(b.Views.Graphs) != 2 {
		t.Fatalf("production and changes only: %d", len(b.Views.Graphs))
	}
}

// A few hundred people build in a sane time and size: graph pages share one
// font file, and per-person pages are bounded.
func TestViewsScaleToHundredsOfPeople(t *testing.T) {
	g := graph.New()
	graph.WriteScan(g, "google", "google_users", "", 300, "", now)
	g.Node(graph.Node{ID: graph.ScanID("github_people", "acme"), Kind: graph.KindScan, Attrs: map[string]any{"scanner": "github_people", "scope": "acme"}})
	g.Node(graph.Node{ID: "gcp:project/acme-prod", Kind: graph.KindGCPProject, Attrs: map[string]any{"name": "acme-prod", "production": true}})
	for r := range 40 {
		g.Node(graph.Node{ID: graph.ID(fmt.Sprintf("github:repo/acme/r%02d", r)), Kind: graph.KindGitHubRepo, Attrs: map[string]any{"name": fmt.Sprintf("acme/r%02d", r)}})
	}
	for i := range 300 {
		email := fmt.Sprintf("p%03d@acme.example", i)
		p := pid(email)
		g.Node(graph.Node{ID: p, Kind: graph.KindPerson, Attrs: map[string]any{"systems": []any{"gcp", "github", "google"}, "external": false}})
		u := graph.ID("google:user/" + viewSalt.Email(email))
		g.Node(graph.Node{ID: u, Kind: graph.KindIdentityUser, Attrs: map[string]any{"is_admin": false, "suspended": false}})
		g.Edge(graph.Edge{From: p, To: u, Kind: graph.EdgeSamePerson})
		gh := graph.ID("github:user/" + viewSalt.Sum(email))
		g.Node(graph.Node{ID: gh, Kind: graph.KindGitHubUser, Attrs: map[string]any{"org": "acme", "org_role": "member", "type": "user"}})
		g.Edge(graph.Edge{From: p, To: gh, Kind: graph.EdgeSamePerson})
		for r := range 5 {
			g.Edge(graph.Edge{From: gh, To: graph.ID(fmt.Sprintf("github:repo/acme/r%02d", (i+r)%40)), Kind: graph.EdgeWritesTo})
		}
		if i%3 == 0 {
			b := graph.ID(fmt.Sprintf("gcp:binding/acme-prod/roles/editor/%03d", i))
			g.Node(graph.Node{ID: b, Kind: graph.KindGCPBinding, Attrs: map[string]any{"project": "acme-prod", "role": "roles/editor",
				"member_type": "user", "is_admin": true, "destructive": true, "power_known": true, "production": true}})
			g.Edge(graph.Edge{From: "gcp:project/acme-prod", To: b, Kind: graph.EdgeOwns})
			g.Edge(graph.Edge{From: p, To: b, Kind: graph.EdgeSamePerson})
		}
	}
	snap := graph.TakeSnapshot(g, now)
	start := time.Now()
	dir, b := buildViews(t, &snap, nil)
	took := time.Since(start)
	// Item pages are left out: each carries the fonts, as before this step.
	var size, items int64
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, err := d.Info(); err == nil {
				if strings.Contains(p, string(filepath.Separator)+"items"+string(filepath.Separator)) {
					items += info.Size()
				} else {
					size += info.Size()
				}
			}
		}
		return err
	})
	t.Logf("300 people: %d pages drawn, %d KB of People, Agents and graph pages (item pages %d KB) in %s", len(b.Views.Graphs), size/1024, items/1024, took)
	if len(b.Views.People) != 300 || len(b.Views.Graphs) != 102 {
		t.Fatalf("100 people with power get a page, plus production and changes: %d people, %d pages", len(b.Views.People), len(b.Views.Graphs))
	}
	if took > 20*time.Second || size > 8<<20 {
		t.Fatalf("took %s and %d bytes", took, size)
	}
}
