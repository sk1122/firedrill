package report

import (
	"fmt"
	"html"
	"html/template"
	"sort"
	"strings"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
)

// MaxDrawn caps the nodes on one drawing. Past it the page says how many were
// left out and links to their rows.
const MaxDrawn = 60

// zoneNames are the four zones a drawing runs through, left to right.
var zoneNames = [4]string{"Outside", "People and agents", "Credentials", "Production"}

// zoneOf places a node in a zone by its kind. A file a secret sits in is a
// credential's place, so it is drawn with credentials.
func zoneOf(n graph.Node) int {
	switch n.Kind {
	case graph.KindHost, graph.KindWebResponse, graph.KindSourceMap, graph.KindAPIDoc, graph.KindOAuthApp, graph.KindCNAME,
		graph.KindDNSRecord, graph.KindConfigHost, graph.KindConfigDomain:
		return 0
	case graph.KindPerson, graph.KindLeaver, graph.KindAgentConfig, "mcp_server", graph.KindConfigOwner:
		return 1
	case graph.KindIdentityUser, graph.KindGitHubUser, graph.KindGitHubTeam, graph.KindGitHubApp, graph.KindDeployKey,
		graph.KindGoogleGroup, graph.KindGCPBinding, graph.KindSecret, graph.KindSecretSeen, graph.KindAWSKey,
		graph.KindAWSPrincipal, graph.KindGCPKey, graph.KindAIKey, "":
		return 2
	}
	return 3
}

// systemColours colour nodes by system, from colours the board already uses.
var systemColours = map[string]string{
	"github": "#F4F2EA", "gcp": "#3cc986", "google": "#E8A317", "files": "#B9B6AB", "web": "#8A877C",
	"person": "#d9d6cb", "aws": "#ff6a5e", "config": "#55565b",
}

// systemOf names the system a node belongs to, from its ID.
func systemOf(id graph.ID) string {
	prefix, _, _ := strings.Cut(string(id), ":")
	switch prefix {
	case "github", "gcp", "google", "aws":
		return prefix
	case "person":
		return "person"
	case "agent", "secret", "file", "mcp", "repo", "manifest", "tf", "codeowners":
		return "files"
	case "host", "dns", "dns-cname", "web", "source-map", "api-doc", "domain":
		return "web"
	}
	return "config"
}

var severityRing = map[string]string{"critical": "#D3261A", "high": "#D3261A", "medium": "#E8A317", "low": "#8A877C"}

// drawing is what one picture is asked to show.
type drawing struct {
	sub    graph.Sub
	start  []graph.ID
	accent map[graph.Edge]bool // edges drawn in the accent colour
	marked map[graph.ID]string // nodes outlined, with why
	labels map[string]string   // drawn-only edge kinds and their words
}

// layout geometry.
const (
	colW   = 236
	boxW   = 196
	boxH   = 26
	rowH   = 34
	padTop = 44
	padX   = 16
)

// render draws a subgraph as SVG: four zone columns, left to right. It keeps
// the start nodes and those nearest them, up to MaxDrawn, and returns how
// many it left out.
func (c *viewCtx) render(d drawing, page *GraphPage) {
	dist := distances(d.sub, d.start)
	nodes := append([]graph.Node{}, d.sub.Nodes...)
	sort.SliceStable(nodes, func(i, j int) bool {
		if dist[nodes[i].ID] != dist[nodes[j].ID] {
			return dist[nodes[i].ID] < dist[nodes[j].ID]
		}
		return nodes[i].ID < nodes[j].ID
	})
	if len(nodes) > MaxDrawn {
		page.Hidden = len(nodes) - MaxDrawn
		nodes = nodes[:MaxDrawn]
	}
	cols := [4][]graph.Node{}
	for _, n := range nodes {
		z := zoneOf(n)
		cols[z] = append(cols[z], n)
	}
	pos := map[graph.ID][2]int{}
	rows := 1
	for z := range cols {
		sort.SliceStable(cols[z], func(i, j int) bool {
			if cols[z][i].Kind != cols[z][j].Kind {
				return cols[z][i].Kind < cols[z][j].Kind
			}
			return cols[z][i].ID < cols[z][j].ID
		})
		for i, n := range cols[z] {
			pos[n.ID] = [2]int{padX + z*colW, padTop + i*rowH}
		}
		rows = max(rows, len(cols[z]))
		page.Zones[z] = ZoneCount{Name: zoneNames[z], Nodes: len(cols[z])}
	}
	width := padX*2 + 3*colW + boxW
	height := padTop + rows*rowH + 8
	var sb strings.Builder
	fmt.Fprintf(&sb, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" role="img" aria-label="%s">`,
		width, height, width, height, html.EscapeString(page.Question))
	sb.WriteString(`<defs><marker id="arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0L8 4L0 8z" fill="#8A877C"/></marker>` +
		`<marker id="arrow-new" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto"><path d="M0 0L8 4L0 8z" fill="#D3261A"/></marker></defs>`)
	for z, name := range zoneNames {
		fmt.Fprintf(&sb, `<text class="zone" x="%d" y="22">%s</text>`, padX+z*colW, html.EscapeString(name))
	}
	drawn := 0
	for _, e := range d.sub.Edges {
		a, okA := pos[e.From]
		b, okB := pos[e.To]
		if !okA || !okB {
			continue
		}
		drawn++
		x1, y1 := a[0]+boxW, a[1]+boxH/2
		x2, y2 := b[0], b[1]+boxH/2
		var path string
		switch {
		case a[0] == b[0]:
			// Same zone: an arc out to the right and back.
			x1, x2 = a[0]+boxW, b[0]+boxW
			path = fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, y1, x1+30, y1, x2+30, y2, x2, y2)
		case a[0] > b[0]:
			x1, x2 = a[0], b[0]+boxW
			mid := (x1 + x2) / 2
			path = fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, y1, mid, y1, mid, y2, x2, y2)
		default:
			mid := (x1 + x2) / 2
			path = fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, y1, mid, y1, mid, y2, x2, y2)
		}
		class, marker := "edge", "arrow"
		if d.accent[e] {
			class, marker = "edge new", "arrow-new"
		}
		words := e.Kind
		if w, ok := d.labels[e.Kind]; ok {
			words = w
		}
		if d.accent[e] {
			words = "new since the last run: " + words
		}
		fmt.Fprintf(&sb, `<path class="%s" d="%s" marker-end="url(#%s)"><title>%s</title></path>`, class, path, marker, html.EscapeString(words))
	}
	page.Edges = drawn
	for z := range cols {
		for _, n := range cols[z] {
			p := pos[n.ID]
			fill := systemColours[systemOf(n.ID)]
			stroke, sw := "#16161A", 1
			if sev := c.b.failing[string(n.ID)]; sev != "" {
				stroke, sw = severityRing[sev], 3
			}
			label := truncate(c.nodeLabel(n), 30)
			title := c.nodeLabel(n) + " · " + kindWords(n)
			if sev := c.b.failing[string(n.ID)]; sev != "" {
				title += " · read by a failing " + sev + " drill"
			}
			dash := ""
			if why, ok := d.marked[n.ID]; ok {
				dash = ` stroke-dasharray="4 3"`
				stroke, sw = "#ff6a5e", 3
				title += " · " + why
			}
			href := c.hrefOf(n.ID)
			if href != "" {
				fmt.Fprintf(&sb, `<a href="../%s">`, html.EscapeString(href))
			}
			fmt.Fprintf(&sb, `<g class="node"><title>%s</title><rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" stroke="%s" stroke-width="%d"%s/>`+
				`<text x="%d" y="%d">%s</text></g>`, html.EscapeString(title), p[0], p[1], boxW, boxH, fill, stroke, sw, dash, p[0]+8, p[1]+17, html.EscapeString(label))
			if href != "" {
				sb.WriteString(`</a>`)
			}
		}
	}
	sb.WriteString(`</svg>`)
	page.Nodes = len(nodes)
	page.SVG = template.HTML(sb.String()) // #nosec G203 -- every value above is escaped
}

// distances counts hops from the start nodes over the drawing's edges, either
// way. A node it cannot reach sorts last.
func distances(s graph.Sub, start []graph.ID) map[graph.ID]int {
	adj := map[graph.ID][]graph.ID{}
	for _, e := range s.Edges {
		adj[e.From] = append(adj[e.From], e.To)
		adj[e.To] = append(adj[e.To], e.From)
	}
	out := map[graph.ID]int{}
	for _, n := range s.Nodes {
		out[n.ID] = 1 << 20
	}
	queue := []graph.ID{}
	for _, id := range start {
		out[id] = 0
		queue = append(queue, id)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		for _, nb := range adj[id] {
			if out[nb] > out[id]+1 {
				out[nb] = out[id] + 1
				queue = append(queue, nb)
			}
		}
	}
	return out
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func kindWords(n graph.Node) string {
	if n.Kind == "" {
		return "file"
	}
	return strings.ReplaceAll(n.Kind, "_", " ")
}

// nodeLabel names a node on a drawing. People and accounts show by short ID.
func (c *viewCtx) nodeLabel(n graph.Node) string {
	if n.Kind == "" {
		return nameOf(c.g, n.ID)
	}
	if n.Kind == graph.KindAgentConfig {
		return str(n, "tool") + " " + str(n, "file")
	}
	if n.Kind == graph.KindSecretSeen || n.Kind == graph.KindSecret {
		h := str(n, "hash")
		if h == "" {
			h = strings.TrimPrefix(string(n.ID), "secret:")
		}
		return "secret " + h[:min(12, len(h))]
	}
	if n.Kind == graph.KindEnvironment {
		rest := strings.TrimPrefix(string(n.ID), "github:env/")
		i := strings.LastIndex(rest, "/")
		return rest[:i] + " env " + rest[i+1:]
	}
	if n.Kind == graph.KindLeaver {
		return "leaver " + shortOf(string(n.ID))
	}
	return displayName(&graph.EstateItem{ID: n.ID, Kind: n.Kind, Attrs: n.Attrs})
}

// hrefOf links a node to its row on the People or Agents page, or its item
// page. The link is relative to the report's root.
func (c *viewCtx) hrefOf(id graph.ID) string {
	if a, ok := c.people[id]; ok {
		return "people.html#" + a
	}
	if a, ok := c.agents[id]; ok {
		return "agents.html#" + a
	}
	return c.items[id]
}

var cutMark = "a cut point: " // prefix of a cut-point outline's words

// graphs builds the drawn questions, in priority order.
func (c *viewCtx) graphs(diff *run.DiffRecord) {
	c.productionGraph()
	for _, p := range c.v.People {
		if p.GraphHref != "" {
			c.personGraph(p)
		}
	}
	for _, a := range c.v.Agents {
		if a.GraphHref != "" {
			c.agentGraph(a)
		}
	}
	c.changesGraph(diff)
}

func (c *viewCtx) add(page GraphPage, d drawing) {
	c.render(d, &page)
	c.v.Graphs = append(c.v.Graphs, page)
}

// productionGraph answers who can reach production data alone: from each
// production environment back through repos to the people who can bypass
// review, and from each production GCP project through roles that can delete
// or administer to the people who hold them.
func (c *viewCtx) productionGraph() {
	var envs, projects []graph.ID
	for _, n := range c.g.Nodes(graph.KindEnvironment) {
		if strings.HasSuffix(string(n.ID), "/production") {
			envs = append(envs, n.ID)
		}
	}
	marked := false
	for _, n := range c.g.Nodes(graph.KindGCPProject) {
		marked = marked || n.Attrs["production"] == true
	}
	for _, n := range c.g.Nodes(graph.KindGCPProject) {
		if !marked || n.Attrs["production"] == true {
			projects = append(projects, n.ID)
		}
	}
	sub := c.adj.Subgraph(graph.Query{Start: envs, Kinds: []string{graph.EdgeDeploysTo, graph.EdgeCanBypass, graph.EdgeSamePerson}, Dir: graph.In, Hops: 3})
	// Only roles that can delete or administer reach production data.
	roles := c.adj.Subgraph(graph.Query{Start: projects, Kinds: []string{graph.EdgeOwns}, Dir: graph.Out, Hops: 1})
	var strong []graph.ID
	keep := graph.Sub{}
	for _, n := range roles.Nodes {
		if n.Kind == graph.KindGCPBinding && (n.Attrs["destructive"] == true || n.Attrs["is_admin"] == true) {
			strong = append(strong, n.ID)
			keep.Nodes = append(keep.Nodes, n)
		}
		if n.Kind == graph.KindGCPProject {
			keep.Nodes = append(keep.Nodes, n)
		}
	}
	for _, e := range roles.Edges {
		for _, id := range strong {
			if e.To == id {
				keep.Edges = append(keep.Edges, e)
			}
		}
	}
	sub.Merge(keep)
	sub.Merge(c.adj.Subgraph(graph.Query{Start: strong, Kinds: []string{graph.EdgeSamePerson, graph.EdgeViaGroup}, Dir: graph.In, Hops: 1}))
	marks := map[graph.ID]string{}
	page := GraphPage{File: "production.html", Title: "Production", Question: "Who can reach production data alone?",
		Lead:     "From each production environment and project back to the people who can reach it. Outlined people are cut points.",
		RowsHref: "../people.html"}
	prodRepos := run.ProductionRepos(c.g)
	for _, cp := range run.CutPoints(c.g, c.now) {
		// Only the cut points on a path to production belong on this drawing.
		if _, ok := c.people[graph.ID(cp.Person)]; ok && prodRepos[cp.Subject] {
			marks[graph.ID(cp.Person)] = cutMark + cp.Why
			page.Notes = append(page.Notes, GraphNote{Text: "person " + shortOf(cp.Person) + ": " + cp.Why, Href: "../people.html#person-" + shortOf(cp.Person)})
		}
	}
	if len(envs) == 0 && len(projects) == 0 {
		page.Lead = "No production environment in GitHub and no GCP project was read, so there is nothing to draw."
	}
	if c.v.Basis != "" {
		page.Lead += " " + strings.ToUpper(c.v.Basis[:1]) + c.v.Basis[1:] + "."
	}
	c.add(page, drawing{sub: sub, start: append(envs, projects...), marked: marks})
}

// personGraph answers what one person can do: their accounts, and what each
// reaches.
func (c *viewCtx) personGraph(p PersonRow) {
	id := graph.ID(p.ID)
	sub := c.adj.Subgraph(graph.Query{Start: []graph.ID{id}, Kinds: []string{graph.EdgeSamePerson, graph.EdgeViaGroup}, Dir: graph.Out, Hops: 1})
	accounts := sub.IDs()
	reach := c.adj.Subgraph(graph.Query{Start: accounts, Kinds: []string{graph.EdgeAdminOf, graph.EdgeWritesTo, graph.EdgeCanBypass, graph.EdgeMemberOf},
		Dir: graph.Out, Hops: 1})
	sub.Merge(reach)
	sub.Merge(c.adj.Subgraph(graph.Query{Start: reach.IDs(), Kinds: []string{graph.EdgeDeploysTo, graph.EdgeAdminOf, graph.EdgeWritesTo}, Dir: graph.Out, Hops: 1}))
	sub.Merge(c.adj.Subgraph(graph.Query{Start: accounts, Kinds: []string{graph.EdgeOwns}, Dir: graph.In, Hops: 1}))
	marks := map[graph.ID]string{}
	if len(p.Cut) > 0 {
		marks[id] = cutMark + strings.Join(p.Cut, "; ")
	}
	page := GraphPage{File: "person-" + p.Short + ".html", Title: "Person " + p.Short, Question: "What can person " + p.Short + " do?",
		Lead: "Their accounts, and what each account can reach.", RowsHref: "../people.html#" + p.Anchor}
	for _, w := range p.Cut {
		page.Notes = append(page.Notes, GraphNote{Text: "Cut point: " + w, Href: "../people.html#" + p.Anchor})
	}
	c.add(page, drawing{sub: sub, start: []graph.ID{id}, marked: marks})
}

// agentGraph answers what an agent config can touch: the secrets in files it
// can read, everywhere else each was seen, and who can bypass review on its
// repo. The can_read and works_in edges are worked out for the drawing.
func (c *viewCtx) agentGraph(a AgentRow) {
	var id graph.ID
	for gid, anchor := range c.agents {
		if anchor == a.Anchor {
			id = gid
		}
	}
	files := map[graph.ID]bool{}
	for _, n := range c.g.Nodes(graph.KindSecretSeen) {
		if n.Attrs["agent_readable"] == true && str(n, "repo") == a.Repo {
			files[graph.ID("file:"+a.Repo+"/"+str(n, "file"))] = true
		}
	}
	extra := graph.NewAdjacency(c.g)
	var start []graph.ID
	for f := range files {
		extra.Add(graph.Edge{From: id, To: f, Kind: "can_read"})
		start = append(start, f)
	}
	repo := graph.ID("github:repo/" + a.Repo)
	if _, ok := c.g.Get(repo); ok {
		extra.Add(graph.Edge{From: id, To: repo, Kind: "works_in"})
	}
	sub := extra.Subgraph(graph.Query{Start: []graph.ID{id}, Kinds: []string{"can_read", "works_in"}, Dir: graph.Out, Hops: 1})
	secrets := extra.Subgraph(graph.Query{Start: start, Kinds: []string{graph.EdgeFoundIn}, Dir: graph.In, Hops: 1})
	sub.Merge(secrets)
	sub.Merge(extra.Subgraph(graph.Query{Start: secrets.IDs(), Kinds: []string{graph.EdgeFoundIn}, Dir: graph.Out, Hops: 1}))
	sub.Merge(extra.Subgraph(graph.Query{Start: []graph.ID{repo}, Kinds: []string{graph.EdgeCanBypass, graph.EdgeSamePerson, graph.EdgeDeploysTo}, Dir: graph.Both, Hops: 2}))
	page := GraphPage{File: a.Anchor + ".html", Title: "Agent " + a.Tool, Question: "What can " + a.Tool + " in " + a.Repo + " (" + a.File + ") touch?",
		Lead:     "Secrets in files it can read, every other place each was seen, and who can skip review where it works. Secrets show by fingerprint only.",
		RowsHref: "../agents.html#" + a.Anchor}
	c.add(page, drawing{sub: sub, start: []graph.ID{id},
		labels: map[string]string{"can_read": "can read (worked out from the agent's deny list)", "works_in": "works in this repo"}})
}

// changesGraph answers what changed: the latest diff's new edges in the
// accent colour, over the edges already there between the same nodes in grey.
func (c *viewCtx) changesGraph(diff *run.DiffRecord) {
	page := GraphPage{File: "changes.html", Title: "What changed", Question: "What changed since the last run?",
		Lead: "New edges in red over the edges already there in grey.", RowsHref: "../changes.html"}
	if diff == nil {
		page.Lead = "No two runs to compare yet."
		c.add(page, drawing{})
		return
	}
	present := map[graph.Edge]bool{}
	for _, e := range c.g.Edges("") {
		present[e] = true
	}
	accent := map[graph.Edge]bool{}
	ends := map[graph.ID]bool{}
	var start []graph.ID
	for _, ch := range diff.Changes {
		if ch.Edge == nil || !present[*ch.Edge] {
			continue
		}
		accent[*ch.Edge] = true
		for _, id := range []graph.ID{ch.Edge.From, ch.Edge.To} {
			if !ends[id] {
				ends[id] = true
				start = append(start, id)
			}
		}
	}
	sub := graph.Sub{}
	for id := range ends {
		n, ok := c.g.Get(id)
		if !ok {
			n = graph.Node{ID: id}
		}
		sub.Nodes = append(sub.Nodes, n)
	}
	for e := range present {
		if ends[e.From] && ends[e.To] {
			sub.Edges = append(sub.Edges, e)
		}
	}
	sub.Merge(graph.Sub{})
	if len(accent) == 0 {
		page.Lead = "No new edge since the last run."
	}
	sort.Slice(start, func(i, j int) bool { return start[i] < start[j] })
	c.add(page, drawing{sub: sub, start: start, accent: accent})
}
