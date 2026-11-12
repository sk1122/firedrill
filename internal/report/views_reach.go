package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
)

// MaxSecretPages bounds the per-secret graph pages, like the person pages.
// Only a secret seen in more than one place, readable by an agent, or in a
// public bundle gets one, in fingerprint order.
const MaxSecretPages = 500

// OutsideHops is how far the outside drawing follows a path to production.
const OutsideHops = 3

// internet stands for anyone on the internet, the start of a public grant.
const internet = graph.ID("outside:internet")

// secretInfo is everything read about one secret fingerprint. Values are
// never read: a secret is its HMAC fingerprint and where it was seen.
type secretInfo struct {
	hash     string
	files    map[graph.ID]bool // file:<repo>/<path> it was found in
	public   []graph.ID        // public_secret nodes, one per place served
	readable map[string]bool   // repo/path an agent config can read
	keyIDs   map[string]bool
	mcp      []graph.ID // MCP servers given it as a credential
	agents   []graph.ID // agent configs given it, or that can read a file holding it
}

func (s *secretInfo) places() int { return len(s.files) + len(s.public) }

func fp(hash string) string { return hash[:min(12, len(hash))] }

// secretsIndex gathers each secret fingerprint from repo files, public
// bundles and MCP server credentials.
func (c *viewCtx) secretsIndex() map[string]*secretInfo {
	out := map[string]*secretInfo{}
	get := func(hash string) *secretInfo {
		s := out[hash]
		if s == nil {
			s = &secretInfo{hash: hash, files: map[graph.ID]bool{}, readable: map[string]bool{}, keyIDs: map[string]bool{}}
			out[hash] = s
		}
		return s
	}
	for _, e := range c.g.Edges(graph.EdgeFoundIn) {
		if h, ok := strings.CutPrefix(string(e.From), "secret:"); ok && h != "" {
			get(h).files[e.To] = true
		}
	}
	for _, n := range c.g.Nodes(graph.KindSecretSeen) {
		h := str(n, "hash")
		if h == "" {
			continue
		}
		s := get(h)
		file := graph.ID("file:" + str(n, "repo") + "/" + str(n, "file"))
		s.files[file] = true
		if n.Attrs["agent_readable"] == true {
			s.readable[str(n, "repo")+"/"+str(n, "file")] = true
		}
		if k := str(n, "key_id"); k != "" {
			s.keyIDs[k] = true
		}
	}
	for _, n := range c.g.Nodes(graph.KindPublicSecret) {
		h := str(n, "hash")
		if h == "" {
			continue
		}
		s := get(h)
		s.public = append(s.public, n.ID)
		if k := str(n, "key_id"); k != "" {
			s.keyIDs[k] = true
		}
	}
	for _, n := range c.g.Nodes(graph.KindAgentConfig) {
		repo := str(n, "repo")
		servers, _ := n.Attrs["mcp_servers"].([]any)
		for _, sv := range servers {
			m, _ := sv.(map[string]any)
			for _, cred := range strs(m["credentials"]) {
				if h, ok := strings.CutPrefix(cred, "secret:"); ok {
					s := get(h)
					s.mcp = append(s.mcp, graph.ID("mcp:"+repo+"/"+fmt.Sprint(m["name"])))
					s.agents = append(s.agents, n.ID)
				}
			}
		}
		for _, sec := range out {
			for f := range sec.readable {
				if strings.HasPrefix(f, repo+"/") && !containsID(sec.agents, n.ID) {
					sec.agents = append(sec.agents, n.ID)
				}
			}
		}
	}
	return out
}

func containsID(list []graph.ID, id graph.ID) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

// secretPages picks the secrets that get a page and records each page's link.
func (c *viewCtx) secretPages() {
	c.secrets = c.secretsIndex()
	c.secretHref = map[string]string{}
	hashes := make([]string, 0, len(c.secrets))
	for h, s := range c.secrets {
		if s.places() > 1 || len(s.readable) > 0 || len(s.public) > 0 || len(s.mcp) > 0 {
			hashes = append(hashes, h)
		}
	}
	sort.Strings(hashes)
	for _, h := range hashes {
		if len(c.secretHref) >= MaxSecretPages {
			c.v.SecretPagesCut++
			continue
		}
		c.secretHref[h] = "graph/secret-" + fp(h) + ".html"
	}
	// Item pages of secrets link to their page.
	for i, it := range c.b.Items {
		if it.Kind != graph.KindPublicSecret {
			continue
		}
		n, ok := c.g.Get(graph.ID(it.ID))
		if !ok {
			continue
		}
		if href := c.secretHref[str(n, "hash")]; href != "" {
			c.b.Items[i].SecretHref = "../" + href
		}
	}
}

// KeyRow is a key behind a secret an agent can read, and what it can do.
type KeyRow struct {
	Fingerprint, SecretHref string
	Provider, Where         string
	Known, Admin            bool
	Destructive             []string
	Note                    string
}

// gcpKeyPower finds a Google Cloud service account key by key ID and what the
// account's bindings let it do, classified by the link step's role power.
func gcpKeyPower(g graph.Reader, keyID string) (graph.Node, []graph.Node, bool) {
	for _, k := range g.Nodes(graph.KindGCPKey) {
		if str(k, "key_id") != keyID {
			continue
		}
		sa := strings.ToLower(str(k, "service_account"))
		var binds []graph.Node
		for _, b := range g.Nodes(graph.KindGCPBinding) {
			if str(b, "member_type") == "service_account" && strings.ToLower(str(b, "member")) == sa {
				binds = append(binds, b)
			}
		}
		return k, binds, true
	}
	return graph.Node{}, nil, false
}

// saLabel names a service account without its address: its name and project.
func saLabel(email string) string {
	local, domain, _ := strings.Cut(strings.ToLower(email), "@")
	project, _, _ := strings.Cut(domain, ".")
	return "service account " + local + " in " + project
}

// agentKeys lists, for one repo, the keys behind agent-readable secrets: AWS
// keys from aws.agent_keys as it already returns them, and Google Cloud
// service account keys matched by key ID with their roles' power.
func (c *viewCtx) agentKeys(repo string) []KeyRow {
	aws := map[string]map[string]any{}
	if def, ok := facts.Lookup("aws.agent_keys"); ok {
		if r, err := def.Fn(c.g, facts.Args{Now: c.now}); err == nil {
			rows, _ := r.Data.([]any)
			for _, x := range rows {
				if m, ok := x.(map[string]any); ok {
					aws[fmt.Sprint(m["key_id"])] = m
				}
			}
		}
	}
	var out []KeyRow
	seen := map[string]bool{}
	for _, n := range c.g.Nodes(graph.KindSecretSeen) {
		keyID, hash := str(n, "key_id"), str(n, "hash")
		if n.Attrs["agent_readable"] != true || str(n, "repo") != repo || keyID == "" || seen[hash] {
			continue
		}
		seen[hash] = true
		row := KeyRow{Fingerprint: "secret:" + fp(hash), SecretHref: c.secretHref[hash]}
		if k, binds, ok := gcpKeyPower(c.g, keyID); ok {
			row.Provider, row.Known = "GCP", true
			row.Where = saLabel(str(k, "service_account"))
			if k.Attrs["disabled"] == true {
				row.Note = "key disabled"
			}
			known := true
			for _, b := range binds {
				row.Admin = row.Admin || b.Attrs["is_admin"] == true
				if b.Attrs["destructive"] == true {
					row.Destructive = append(row.Destructive, str(b, "role")+" on "+str(b, "project"))
				}
				known = known && b.Attrs["power_known"] != false
			}
			if len(binds) == 0 {
				row.Note = strings.TrimPrefix(row.Note+"; no role binding read for this account", "; ")
			} else if !known {
				row.Note = strings.TrimPrefix(row.Note+"; the power of a custom role is unknown", "; ")
			}
		} else if m, ok := aws[keyID]; ok && m["unknown_account"] != true {
			row.Provider, row.Known = "AWS", true
			row.Where = "account " + fmt.Sprint(m["account"]) + ", IAM user " + fmt.Sprint(m["user"])
			row.Admin = m["is_admin"] == true
			row.Destructive = strs(m["destructive_actions"])
		} else {
			row.Provider, row.Note = "unknown", "the key is not in the GCP or AWS inventory read, so what it can do is not known"
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Fingerprint < out[j].Fingerprint })
	return out
}

// secretGraph answers what one secret opens: every place it was seen, the
// agent configs that can read it, and what accepts it where that is known.
func (c *viewCtx) secretGraph(hash string) {
	s := c.secrets[hash]
	id := graph.ID("secret:" + hash)
	extra := graph.NewAdjacency(c.g)
	start := []graph.ID{id}
	for _, p := range s.public {
		extra.Add(graph.Edge{From: id, To: p, Kind: "served_publicly"})
	}
	for f := range s.readable {
		for _, a := range s.agents {
			if n, ok := c.g.Get(a); ok && strings.HasPrefix(f, str(n, "repo")+"/") {
				extra.Add(graph.Edge{From: a, To: graph.ID("file:" + f), Kind: "can_read"})
			}
		}
	}
	for _, m := range s.mcp {
		extra.Add(graph.Edge{From: id, To: m, Kind: "credential_of"})
	}
	var notes []GraphNote
	keyIDs := make([]string, 0, len(s.keyIDs))
	for k := range s.keyIDs {
		keyIDs = append(keyIDs, k)
	}
	sort.Strings(keyIDs)
	accepts := 0
	for _, k := range keyIDs {
		if key, binds, ok := gcpKeyPower(c.g, k); ok {
			accepts++
			extra.Add(graph.Edge{From: id, To: key.ID, Kind: "is_key"})
			for _, b := range binds {
				extra.Add(graph.Edge{From: key.ID, To: b.ID, Kind: "acts_as"})
			}
			notes = append(notes, GraphNote{Text: "accepted by Google Cloud as a key of " + saLabel(str(key, "service_account")), Href: "../" + c.items[key.ID]})
		}
		if n, ok := c.g.Get(graph.ID("aws:key/" + k)); ok {
			accepts++
			extra.Add(graph.Edge{From: id, To: n.ID, Kind: "is_key"})
			notes = append(notes, GraphNote{Text: "accepted by AWS as an access key in account " + str(n, "account"), Href: "../" + c.items[n.ID]})
		}
	}
	for _, m := range s.mcp {
		notes = append(notes, GraphNote{Text: "given to MCP server " + strings.TrimPrefix(string(m), "mcp:") + " as a credential"})
	}
	kinds := []string{graph.EdgeFoundIn, "served_publicly", "credential_of", "is_key"}
	sub := extra.Subgraph(graph.Query{Start: start, Kinds: kinds, Dir: graph.Out, Hops: 1})
	sub.Merge(extra.Subgraph(graph.Query{Start: sub.IDs(), Kinds: []string{"can_read"}, Dir: graph.In, Hops: 1}))
	sub.Merge(extra.Subgraph(graph.Query{Start: sub.IDs(), Kinds: []string{"acts_as"}, Dir: graph.Out, Hops: 1}))
	sub.Merge(extra.Subgraph(graph.Query{Start: sub.IDs(), Kinds: []string{graph.EdgeOwns, graph.EdgeHolds}, Dir: graph.In, Hops: 1}))
	// The secret itself, when no secret node was written (a public bundle only).
	for i, n := range sub.Nodes {
		if n.ID == id && n.Kind == "" {
			sub.Nodes[i] = graph.Node{ID: id, Kind: graph.KindSecret, Attrs: map[string]any{"hash": hash}}
		}
	}
	for f := range s.files {
		notes = append(notes, GraphNote{Text: "seen in " + strings.TrimPrefix(string(f), "file:")})
	}
	for _, p := range s.public {
		if n, ok := c.g.Get(p); ok {
			notes = append(notes, GraphNote{Text: "served publicly at " + str(n, "host") + str(n, "path"), Href: "../" + c.items[p]})
		}
	}
	for _, a := range s.agents {
		if anchor, ok := c.agents[a]; ok {
			notes = append(notes, GraphNote{Text: "readable by an agent config", Href: "../agents.html#" + anchor})
		}
	}
	sort.SliceStable(notes, func(i, j int) bool { return notes[i].Text < notes[j].Text })
	for i := range notes {
		if notes[i].Href == "../" {
			notes[i].Href = ""
		}
	}
	lead := fmt.Sprintf("Seen in %d %s.", s.places(), plural(s.places(), "place", "places"))
	if accepts == 0 {
		lead += " What accepts it is not known: only a Google Cloud service account key, matched by key ID, an AWS access key already in the inventory, and an MCP server given it as a credential are drawn."
	}
	page := GraphPage{File: "secret-" + fp(hash) + ".html", Title: "Secret " + fp(hash), Question: "What does secret " + fp(hash) + " open?",
		Lead: lead + " Shown by fingerprint only.", RowsHref: "../agents.html", Notes: notes}
	c.add(page, drawing{sub: sub, start: start, labels: map[string]string{
		"served_publicly": "served in a public bundle or source map", "can_read": "can read (worked out from the agent's deny list)",
		"credential_of": "given as a credential", "is_key": "is this key (matched by key ID)", "acts_as": "acts as this service account's role"}})
}

// reach is one step the outside drawing may take, and how it is drawn.
type reach struct {
	edge graph.Edge // as drawn
	to   graph.ID   // where the step lands
}

// outsideGraph answers what is reachable from outside: paths of three hops or
// fewer from the Outside zone to the Production zone. Public grants start from
// anyone on the internet; resolving hosts, source maps, API docs, credentials
// in public bundles, third-party apps with sensitive scopes, external scripts
// without integrity, outside collaborators and groups with members outside
// the domain start from themselves. Edges marked worked out are joined here
// from attributes the connectors read; nothing is called.
func (c *viewCtx) outsideGraph() {
	next := map[graph.ID][]reach{}
	step := func(from, to graph.ID, kind string, drawn graph.Edge) {
		if drawn.From == "" {
			drawn = graph.Edge{From: from, To: to, Kind: kind}
		}
		next[from] = append(next[from], reach{edge: drawn, to: to})
	}
	var starts []graph.ID
	start := func(id graph.ID) {
		if !containsID(starts, id) {
			starts = append(starts, id)
		}
	}
	// Real edges, followed toward production.
	for _, k := range []string{graph.EdgeGrantedTo, graph.EdgeSamePerson, graph.EdgeViaGroup, graph.EdgeAdminOf, graph.EdgeWritesTo,
		graph.EdgeCanBypass, graph.EdgeDeploysTo, graph.EdgeBoundTo} {
		for _, e := range c.g.Edges(k) {
			step(e.From, e.To, "", e)
		}
	}
	// A binding reaches the project that owns it.
	for _, e := range c.g.Edges(graph.EdgeOwns) {
		if strings.HasPrefix(string(e.To), "gcp:binding/") {
			step(e.To, e.From, "", e)
		}
	}
	public := false
	for _, n := range c.g.Nodes(graph.KindGCPBucket) {
		if len(strs(n.Attrs["public_grants"])) > 0 {
			step(internet, n.ID, "public_grant", graph.Edge{})
			public = true
		}
	}
	for _, n := range c.g.Nodes(graph.KindTFBucket) {
		if n.Attrs["public_acl"] == true || n.Attrs["public_policy"] == true {
			step(internet, n.ID, "public_grant", graph.Edge{})
			public = true
		}
	}
	if public {
		start(internet)
	}
	for _, n := range c.g.Nodes(graph.KindHost) {
		if d, ok := c.g.Get(graph.ID("dns:" + str(n, "host"))); ok && d.Attrs["resolves"] == false {
			continue
		}
		start(n.ID)
	}
	hostID := func(host string) graph.ID { return graph.ID("host:" + host) }
	for _, kind := range []string{graph.KindSourceMap, graph.KindAPIDoc} {
		for _, n := range c.g.Nodes(kind) {
			start(n.ID)
			step(hostID(str(n, "host")), n.ID, "serves", graph.Edge{})
		}
	}
	saKeys := map[string]graph.ID{}
	for _, k := range c.g.Nodes(graph.KindGCPKey) {
		saKeys[str(k, "key_id")] = k.ID
		sa := strings.ToLower(str(k, "service_account"))
		for _, b := range c.g.Nodes(graph.KindGCPBinding) {
			if str(b, "member_type") == "service_account" && strings.ToLower(str(b, "member")) == sa {
				step(k.ID, b.ID, "acts_as", graph.Edge{})
			}
		}
	}
	for _, n := range c.g.Nodes(graph.KindPublicSecret) {
		start(n.ID)
		step(hostID(str(n, "host")), n.ID, "serves", graph.Edge{})
		if k, ok := saKeys[str(n, "key_id")]; ok && str(n, "key_id") != "" {
			step(n.ID, k, "is_key", graph.Edge{})
		}
	}
	for _, n := range c.g.Nodes(graph.KindOAuthApp) {
		if len(strs(n.Attrs["sensitive_scopes"])) > 0 {
			start(n.ID)
		}
	}
	for _, n := range c.g.Nodes(graph.KindPageScript) {
		if n.Attrs["has_integrity"] != true && n.Attrs["owned"] != true {
			start(n.ID)
			step(n.ID, hostID(str(n, "host")), "runs_on", graph.Edge{})
		}
	}
	for _, n := range c.g.Nodes(graph.KindGitHubUser) {
		if str(n, "org_role") == "outside" {
			start(n.ID)
		}
	}
	for _, n := range c.g.Nodes(graph.KindGoogleGroup) {
		if n.Attrs["external_members"] == true {
			start(n.ID)
		}
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i] < starts[j] })

	// Breadth first from every start, keeping each node's shortest parents.
	dist := map[graph.ID]int{}
	parents := map[graph.ID][]graph.Edge{}
	queue := []graph.ID{}
	for _, s := range starts {
		dist[s] = 0
		queue = append(queue, s)
	}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		if dist[id] == OutsideHops {
			continue
		}
		for _, r := range next[id] {
			d, seen := dist[r.to]
			switch {
			case !seen:
				dist[r.to] = dist[id] + 1
				parents[r.to] = []graph.Edge{r.edge}
				queue = append(queue, r.to)
			case d == dist[id]+1:
				parents[r.to] = append(parents[r.to], r.edge)
			}
		}
	}
	nodeOf := func(id graph.ID) graph.Node {
		if id == internet {
			return graph.Node{ID: internet, Kind: "outside", Attrs: map[string]any{"name": "anyone on the internet"}}
		}
		if n, ok := c.g.Get(id); ok {
			return n
		}
		return graph.Node{ID: id}
	}
	keepN := map[graph.ID]bool{}
	keepE := map[graph.Edge]bool{}
	var walk func(id graph.ID)
	walk = func(id graph.ID) {
		if keepN[id] {
			return
		}
		keepN[id] = true
		for _, e := range parents[id] {
			keepE[e] = true
			other := e.From
			if other == id {
				other = e.To
			}
			walk(other)
		}
	}
	targets := 0
	reached := map[graph.ID]bool{}
	for id, d := range dist {
		if d == 0 || zoneOf(nodeOf(id)) != 3 {
			continue
		}
		targets++
		walk(id)
	}
	for _, s := range starts {
		if keepN[s] {
			reached[s] = true
		}
	}
	sub := graph.Sub{}
	for id := range keepN {
		sub.Nodes = append(sub.Nodes, nodeOf(id))
	}
	for e := range keepE {
		sub.Edges = append(sub.Edges, e)
	}
	sub.Merge(graph.Sub{})
	page := GraphPage{File: "outside.html", Title: "Outside", Question: "What's reachable from outside?",
		Lead: fmt.Sprintf("Paths of %d hops or fewer from the Outside zone to the Production zone. %d of %d outside starting points reach %d production %s.",
			OutsideHops, len(reached), len(starts), targets, plural(targets, "item", "items")),
		RowsHref: "../index.html"}
	if targets == 0 {
		page.Lead = fmt.Sprintf("Nothing outside reaches production within %d hops (%d outside starting points read).", OutsideHops, len(starts))
	}
	var drawnStarts []graph.ID
	for _, s := range starts {
		if reached[s] {
			drawnStarts = append(drawnStarts, s)
			page.Notes = append(page.Notes, GraphNote{Text: "from " + c.nodeLabel(nodeOf(s)) + " · " + kindWords(nodeOf(s)), Href: c.noteHref(s)})
		}
	}
	c.add(page, drawing{sub: sub, start: drawnStarts, labels: map[string]string{
		"public_grant": "public grant (anyone on the internet)", "serves": "serves (worked out from the host it was read on)",
		"is_key": "is this key (matched by key ID)", "acts_as": "acts as this service account's role", "runs_on": "runs on this owned page"}})
}

// noteHref links a note to a node's row, relative to a graph page, or nothing.
func (c *viewCtx) noteHref(id graph.ID) string {
	if h := c.hrefOf(id); h != "" {
		return "../" + h
	}
	return ""
}
