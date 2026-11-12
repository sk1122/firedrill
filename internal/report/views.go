package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

// The People, Agents and Graph screens are built from the latest snapshot,
// which holds no address, login or secret value: people show by a short
// hashed ID, and secrets by fingerprint.

// MaxPersonPages bounds the per-person graph pages. Only people with admin,
// destructive or bypass power, or a leaver who still holds anything, get one,
// in ID order, up to this many; the People page says when the bound cut some.
const MaxPersonPages = 500

// MaxAgentPages bounds the per-agent-config graph pages.
const MaxAgentPages = 500

// Views holds the People, Agents and Graph pages.
type Views struct {
	Present     bool   // a snapshot was read
	Taken       string // when the snapshot was taken
	SystemsRead []string
	PeopleNote  string // why no people are listed, when none are
	People      []PersonRow
	Unlinked    []PrincipalRow
	Orphans     []PrincipalRow
	Cuts        []CutRow
	Basis       string // production_basis, when nothing is marked production
	PagesCut    int    // people with power left without a page by the bound
	Agents      []AgentRow
	AgentNote   string
	Graphs      []GraphPage
	// SecretPagesCut counts secrets left without a page by MaxSecretPages.
	SecretPagesCut int
}

// PersonRow is one person's power across systems. It is never a score.
type PersonRow struct {
	ID, Short, Anchor                     string
	Systems                               []string
	External, Leaver                      bool
	GitHubRole                            string
	Repos, AdminRepos, Bypass             []string
	GCPRoles, GCPAdmin, GCPDestructive    []string
	ProdDestructive                       []string
	PowerKnown                            bool
	GooglePresent, GoogleActive, GoogleAd bool
	Cut                                   []string
	GraphHref                             string
	ItemHref                              string
}

// PrincipalRow is an account or principal no person answers for.
type PrincipalRow struct {
	System, Kind, Name, Role, Reason, Href string
	Admin                                  bool
}

// CutRow is a cut-point person, linked to their row.
type CutRow struct {
	Short, Href, Subject, Why string
}

// AgentRow is one agent config and what it can reach.
type AgentRow struct {
	Anchor, Tool, Repo, File, Scope string
	Servers                         []ServerRow
	Secrets                         []SecretRow
	Unguarded                       []string
	Bypass                          string
	GraphHref                       string
	// Egress is how far committed settings limit outbound access, with the
	// hosts allowed.
	Egress      string
	EgressHosts []string
	Unbounded   bool
	// Keys are the keys behind the secrets it can read, and what each can do.
	Keys []KeyRow
}

// ServerRow is one MCP server in an agent config.
type ServerRow struct {
	Name, Where   string
	Pinned, Known bool
}

// SecretRow is a secret an agent can read, by fingerprint only.
type SecretRow struct {
	Fingerprint, File string
	Href              string // its "what does this secret open?" page
}

// GraphPage is one drawn question.
type GraphPage struct {
	File     string // under graph/
	Title    string
	Question string
	Lead     string
	SVG      template.HTML
	Zones    [4]ZoneCount
	Nodes    int
	Edges    int
	Hidden   int
	RowsHref string // the rows behind what is not drawn
	Notes    []GraphNote
	Fonts    template.CSS
}

// ZoneCount is how many nodes a zone holds on one drawing.
type ZoneCount struct {
	Name  string
	Nodes int
}

// GraphNote is a line under a drawing, linked to its row.
type GraphNote struct {
	Text, Href string
}

// AddViews builds the People, Agents and Graph pages from the latest snapshot
// and the latest diff. A nil snapshot leaves each page saying so. Call it
// after Build, so items and failing drills are known.
func AddViews(b *Board, snap *graph.Snapshot, diff *run.DiffRecord, now time.Time) {
	v := &Views{}
	b.Views = v
	if snap == nil {
		v.PeopleNote = "No people were read — connect Google Workspace, GCP or GitHub."
		v.AgentNote = "No agent config was read yet. Run firedrill run on a repo."
		return
	}
	v.Present = true
	v.Taken = snap.Time.UTC().Format("2006-01-02 15:04 UTC")
	g := graph.FromSnapshot(*snap)
	items := map[graph.ID]string{}
	for _, it := range b.Items {
		items[graph.ID(it.ID)] = "items/" + it.Slug + ".html"
	}
	ctx := &viewCtx{b: b, v: v, g: g, adj: graph.NewAdjacency(g), items: items, now: now, people: map[graph.ID]string{}, agents: map[graph.ID]string{}}
	ctx.people_()
	ctx.secretPages()
	ctx.agents_()
	ctx.graphs(diff)
}

type viewCtx struct {
	b      *Board
	v      *Views
	g      *graph.Graph
	adj    *graph.Adjacency
	items  map[graph.ID]string
	now    time.Time
	people map[graph.ID]string // person ID to its row anchor
	agents map[graph.ID]string // agent config ID to its row anchor
	cut    map[graph.ID]bool
	power  map[graph.ID]bool // people who get a graph page
	// secrets indexes every fingerprint; secretHref links those with a page.
	secrets    map[string]*secretInfo
	secretHref map[string]string
}

func shortOf(id string) string {
	h := id[strings.LastIndexAny(id, ":/")+1:]
	return h[:min(8, len(h))]
}

func factData(g graph.Reader, name string, now time.Time) (map[string]any, string) {
	def, ok := facts.Lookup(name)
	if !ok {
		return nil, "unknown fact " + name
	}
	r, err := def.Fn(g, facts.Args{Now: now})
	if err != nil {
		return nil, err.Error()
	}
	m, _ := r.Data.(map[string]any)
	return m, ""
}

func rowsOf(m map[string]any) []map[string]any {
	var out []map[string]any
	l, _ := m["found"].([]any)
	for _, x := range l {
		if r, ok := x.(map[string]any); ok {
			out = append(out, r)
		}
	}
	return out
}

func strs(v any) []string {
	l, _ := v.([]any)
	out := []string{}
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func (c *viewCtx) people_() {
	v := c.v
	powers, why := factData(c.g, "people.powers", c.now)
	if powers == nil {
		v.PeopleNote = "No people were read — connect Google Workspace, GCP or GitHub."
		if !strings.Contains(why, "no accounts were read") {
			v.PeopleNote = "People could not be read from the latest snapshot: " + why
		}
		return
	}
	v.SystemsRead = strs(powers["systems_read"])
	if basis, _ := powers["production_basis"].(string); basis != "" {
		v.Basis = basis
	}
	c.cut = map[graph.ID]bool{}
	cutWhy := map[string][]string{}
	for _, cp := range run.CutPoints(c.g, c.now) {
		c.cut[graph.ID(cp.Person)] = true
		cutWhy[cp.Person] = append(cutWhy[cp.Person], cp.Why)
	}
	c.power = map[graph.ID]bool{}
	pages := 0
	for _, p := range rowsOf(powers) {
		id, _ := p["id"].(string)
		row := PersonRow{ID: id, Short: shortOf(id), Anchor: "person-" + shortOf(id), Systems: strs(p["systems"]),
			External: p["external"] == true, Leaver: p["leaver"] == true, GitHubRole: fmt.Sprint(p["github_org_role"]),
			Repos: strs(p["github_repos"]), AdminRepos: strs(p["github_admin_repos"]), Bypass: strs(p["github_bypass"]),
			GCPRoles: strs(p["gcp_roles"]), GCPAdmin: strs(p["gcp_admin"]), GCPDestructive: strs(p["gcp_destructive"]),
			ProdDestructive: strs(p["prod_destructive"]), PowerKnown: p["gcp_power_known"] == true,
			GooglePresent: p["google_present"] == true, GoogleActive: p["google_active"] == true, GoogleAd: p["google_admin"] == true,
			Cut: cutWhy[id], ItemHref: c.items[graph.ID(id)]}
		holds := len(row.Repos) > 0 || len(row.GCPRoles) > 0 || row.GoogleActive || row.GitHubRole == "admin" || row.GitHubRole == "member"
		powerful := len(row.AdminRepos) > 0 || len(row.Bypass) > 0 || len(row.GCPAdmin) > 0 || len(row.GCPDestructive) > 0 ||
			row.GoogleAd || row.GitHubRole == "admin" || !row.PowerKnown || (row.Leaver && holds)
		if powerful {
			if pages < MaxPersonPages {
				pages++
				c.power[graph.ID(id)] = true
				row.GraphHref = "graph/person-" + shortOf(id) + ".html"
			} else {
				v.PagesCut++
			}
		}
		c.people[graph.ID(id)] = row.Anchor
		v.People = append(v.People, row)
	}
	sort.SliceStable(v.People, func(i, j int) bool { return v.People[i].ID < v.People[j].ID })
	if len(v.People) == 0 {
		v.PeopleNote = "No people were read — connect Google Workspace, GCP or GitHub."
	}
	for _, cp := range run.CutPoints(c.g, c.now) {
		v.Cuts = append(v.Cuts, CutRow{Short: shortOf(cp.Person), Href: "people.html#person-" + shortOf(cp.Person), Subject: cp.Subject, Why: cp.Why})
	}
	if un, _ := factData(c.g, "people.unlinked", c.now); un != nil {
		for _, u := range rowsOf(un) {
			id := fmt.Sprint(u["id"])
			v.Unlinked = append(v.Unlinked, PrincipalRow{System: fmt.Sprint(u["system"]), Kind: fmt.Sprint(u["kind"]),
				Name: nameOf(c.g, graph.ID(id)), Reason: fmt.Sprint(u["reason"]), Admin: u["is_admin"] == true, Href: c.items[graph.ID(id)]})
		}
	}
	for _, o := range run.Orphans(c.g, c.now) {
		v.Orphans = append(v.Orphans, PrincipalRow{System: o.System, Kind: o.Kind, Name: nameOf(c.g, graph.ID(o.ID)), Role: o.Role,
			Reason: o.Reason, Href: c.items[graph.ID(o.ID)]})
	}
}

// nameOf names a node as the board does.
func nameOf(g graph.Reader, id graph.ID) string {
	n, ok := g.Get(id)
	if !ok {
		s := string(id)
		if f, ok := strings.CutPrefix(s, "file:"); ok {
			return f
		}
		return s
	}
	return displayName(&graph.EstateItem{ID: n.ID, Kind: n.Kind, Attrs: n.Attrs})
}

func (c *viewCtx) agents_() {
	v := c.v
	readable := map[string]map[string]SecretRow{}
	for _, n := range c.g.Nodes(graph.KindSecretSeen) {
		if n.Attrs["agent_readable"] != true {
			continue
		}
		repo, _ := n.Attrs["repo"].(string)
		hash, _ := n.Attrs["hash"].(string)
		file, _ := n.Attrs["file"].(string)
		if readable[repo] == nil {
			readable[repo] = map[string]SecretRow{}
		}
		key := hash + "@" + file
		readable[repo][key] = SecretRow{Fingerprint: "secret:" + hash[:min(12, len(hash))], File: file, Href: c.secretHref[hash]}
	}
	bypassers := map[string]int{}
	for _, e := range c.g.Edges(graph.EdgeCanBypass) {
		if strings.HasPrefix(string(e.From), "github:user/") {
			bypassers[strings.TrimPrefix(string(e.To), "github:repo/")]++
		}
	}
	pages := 0
	for _, n := range c.g.Nodes(graph.KindAgentConfig) {
		repo, _ := n.Attrs["repo"].(string)
		anchor := "agent-" + tag.Slug(string(n.ID))
		row := AgentRow{Anchor: anchor, Tool: str(n, "tool"), Repo: repo, File: str(n, "file"), Scope: str(n, "scope"),
			Unguarded: strs(n.Attrs["unguarded_destructive"]), Egress: str(n, "egress"), EgressHosts: strs(n.Attrs["egress_hosts"])}
		row.Unbounded, _ = n.Attrs["egress_unbounded"].(bool)
		if row.Egress == "" {
			row.Egress = "not read"
		}
		servers, _ := n.Attrs["mcp_servers"].([]any)
		for _, s := range servers {
			m, _ := s.(map[string]any)
			where := fmt.Sprint(m["host"])
			if where == "" || where == "<nil>" {
				where = strings.TrimSpace(fmt.Sprint(m["package"]))
				if ver, _ := m["version"].(string); ver != "" && where != "" {
					where += "@" + ver
				}
				if where == "" || where == "<nil>" {
					where = fmt.Sprint(m["command"])
				}
			}
			known := m["host_known"] == true
			if m["transport"] != "http" && m["transport"] != "sse" {
				known = m["package_known"] == true
			}
			row.Servers = append(row.Servers, ServerRow{Name: fmt.Sprint(m["name"]), Where: where, Pinned: m["pinned"] == true, Known: known})
		}
		keys := make([]string, 0, len(readable[repo]))
		for k := range readable[repo] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			row.Secrets = append(row.Secrets, readable[repo][k])
		}
		row.Keys = c.agentKeys(repo)
		rule, ok := c.g.Get(graph.ID("github:branch-rule/" + repo + "/default"))
		switch {
		case !ok:
			row.Bypass = "not read"
		case rule.Attrs["bypass_actors_known"] != true:
			row.Bypass = "unknown"
		case bypassers[repo] > 0:
			row.Bypass = fmt.Sprintf("yes, %d %s", bypassers[repo], plural(bypassers[repo], "person", "people"))
		default:
			row.Bypass = "no"
		}
		if pages < MaxAgentPages {
			pages++
			row.GraphHref = "graph/" + anchor + ".html"
		}
		c.agents[n.ID] = anchor
		v.Agents = append(v.Agents, row)
	}
	if len(v.Agents) == 0 {
		v.AgentNote = "No agent config was read. Agent configs are read from repo files: .claude/, .cursor/, .gemini/ and .mcp.json."
	}
}

func str(n graph.Node, k string) string {
	s, _ := n.Attrs[k].(string)
	return s
}

// peopleFilters are the People page's filters, each its own page, so they
// work with scripts off.
var peopleFilters = []struct{ System, File, Label string }{
	{"", "people.html", "All"}, {"github", "people-github.html", "GitHub"}, {"gcp", "people-gcp.html", "GCP"}, {"google", "people-google.html", "Google Workspace"},
}

// FilterLink is one filter on the People page.
type FilterLink struct {
	Label, File string
	Current     bool
	Count       int
}

// writeViews writes the People pages, the Agents page and the graph pages.
// Graph pages link one shared font file rather than each carrying the fonts.
func writeViews(dir string, tmpl *template.Template, b *Board) error {
	v := b.Views
	write := func(path, name string, data any) error {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		err = tmpl.ExecuteTemplate(f, name, data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		return err
	}
	for _, flt := range peopleFilters {
		var rows []PersonRow
		var links []FilterLink
		for _, other := range peopleFilters {
			n := 0
			for _, p := range v.People {
				if other.System == "" || slices.Contains(p.Systems, other.System) {
					n++
				}
			}
			links = append(links, FilterLink{Label: other.Label, File: other.File, Current: other.File == flt.File, Count: n})
		}
		for _, p := range v.People {
			if flt.System == "" || slices.Contains(p.Systems, flt.System) {
				rows = append(rows, p)
			}
		}
		data := struct {
			V       *Views
			Rows    []PersonRow
			Filters []FilterLink
			Label   string
			All     bool
			Fonts   template.CSS
			Max     int
		}{v, rows, links, flt.Label, flt.System == "", b.Fonts, MaxPersonPages}
		if err := write(filepath.Join(dir, flt.File), "people.html", data); err != nil {
			return err
		}
	}
	if err := write(filepath.Join(dir, "agents.html"), "agents.html", struct {
		V     *Views
		Fonts template.CSS
	}{v, b.Fonts}); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "graph"), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fonts.css"), []byte(b.Fonts), 0o644); err != nil {
		return err
	}
	for _, g := range v.Graphs {
		if err := write(filepath.Join(dir, "graph", g.File), "graph.html", g); err != nil {
			return err
		}
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
