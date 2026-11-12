package run

import (
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

// linked is one person as the link step builds them.
type linked struct {
	email    string
	systems  map[string]bool
	inDomain bool
	seen     time.Time
}

// link makes one person node per human and joins them to the accounts they
// hold, by email: a Google user by primary address or alias, a GCP binding
// whose member is that user, and a GitHub user through people.yaml. Nothing
// is guessed: a GitHub login with no people.yaml entry stays unlinked. A GCP
// binding whose member is a Google group gives a via_group edge to each person
// in the group, nested groups included. A service account named in owners.yaml
// gets an owns edge from that entry to each of its bindings.
//
// A leaver from the HR file already has the person ID; their node keeps its
// kind and leave date and gains the person's attributes, so hr.leavers still
// sees them.
func link(g *graph.Graph, h graph.Hasher, p *config.Project) {
	domains := map[string]bool{}
	if p != nil {
		for _, d := range append([]string{p.Config.Google.Domain}, p.Config.GCP.MemberDomains...) {
			if d != "" {
				domains[strings.ToLower(d)] = true
			}
		}
	}
	people := map[string]*linked{}
	// alias maps the hash of any address of a Workspace user to the hash of
	// their primary address, which names the person.
	alias := map[string]string{}
	users := g.Nodes(graph.KindIdentityUser)
	for _, n := range users {
		email, _ := n.Private["email"].(string)
		if email == "" {
			continue
		}
		primary := h.Email(email)
		alias[primary] = primary
		aliases, _ := n.Private["aliases"].([]string)
		for _, a := range aliases {
			alias[h.Email(a)] = primary
		}
	}
	resolve := func(hash string) string {
		if p, ok := alias[hash]; ok {
			return p
		}
		return hash
	}
	person := func(hash, email string, at time.Time) graph.ID {
		l := people[hash]
		if l == nil {
			l = &linked{systems: map[string]bool{}, seen: at}
			people[hash] = l
		}
		if l.email == "" {
			l.email = strings.ToLower(email)
		}
		if _, d, _ := strings.Cut(l.email, "@"); domains[d] {
			l.inDomain = true
		}
		return graph.ID("person:" + hash)
	}
	hold := func(hash, email, system string, account graph.ID, at time.Time) {
		id := person(hash, email, at)
		people[hash].systems[system] = true
		g.Edge(graph.Edge{From: id, To: account, Kind: graph.EdgeSamePerson, Source: "link"})
	}

	for _, n := range users {
		email, _ := n.Private["email"].(string)
		if email == "" {
			continue
		}
		hash := h.Email(email)
		hold(hash, email, "google", n.ID, n.SeenAt)
		people[hash].inDomain = true
	}
	bindings := g.Nodes(graph.KindGCPBinding)
	for _, n := range bindings {
		email, _ := n.Private["email"].(string)
		if t, _ := n.Attrs["member_type"].(string); t != "user" || email == "" {
			continue
		}
		hold(resolve(h.Email(email)), email, "gcp", n.ID, n.SeenAt)
	}
	if p != nil {
		for _, n := range g.Nodes(graph.KindGitHubUser) {
			login, _ := n.Private["login"].(string)
			if t, _ := n.Attrs["type"].(string); t != "user" || login == "" {
				continue
			}
			if email := p.PersonOf(login); email != "" {
				hold(resolve(h.Email(email)), email, "github", n.ID, n.SeenAt)
			}
		}
	}

	linkGroups(g, h, bindings, users, alias, person)
	linkOwners(g, bindings)

	for hash, l := range people {
		id := graph.ID("person:" + hash)
		attrs := map[string]any{"systems": sortedSet(l.systems), "external": !l.inDomain}
		kind := graph.KindPerson
		if prev, ok := g.Get(id); ok && prev.Kind == graph.KindLeaver {
			kind = prev.Kind
			for k, v := range prev.Attrs {
				attrs[k] = v
			}
			if l.email == "" {
				l.email, _ = prev.Private["email"].(string)
			}
		}
		g.Node(graph.Node{ID: id, Kind: kind, Source: "link", SeenAt: l.seen, Attrs: attrs,
			Private: map[string]any{"email": l.email}})
	}
	// A leaver who holds no account still says what they hold: nothing.
	for _, n := range g.Nodes(graph.KindLeaver) {
		if _, ok := n.Attrs["systems"]; ok {
			continue
		}
		attrs := map[string]any{"systems": []any{}, "external": false}
		for k, v := range n.Attrs {
			attrs[k] = v
		}
		n.Attrs = attrs
		g.Node(n)
	}
}

// linkGroups writes a bound_to edge from each group a binding names to the
// binding, and a via_group edge from each person in the group to it. A group
// is resolved through nested groups, once each, so a cycle ends. A group the
// Google connector did not read, or could not, leaves its people unknown: the
// facts read that from the group node, never from an absence of edges.
func linkGroups(g *graph.Graph, h graph.Hasher, bindings, users []graph.Node, alias map[string]string,
	person func(hash, email string, at time.Time) graph.ID) {
	// Each address of a read group, by hash, names its node.
	groupOf := map[string]graph.ID{}
	emails := map[string]string{} // member hash to address, from every group read
	for _, n := range g.Nodes(graph.KindGoogleGroup) {
		if e, _ := n.Private["email"].(string); e != "" {
			groupOf[h.Email(e)] = n.ID
		}
		aliases, _ := n.Private["aliases"].([]string)
		for _, a := range aliases {
			groupOf[h.Email(a)] = n.ID
		}
		m, _ := n.Private["member_emails"].(map[string]any)
		for k, v := range m {
			emails[k], _ = v.(string)
		}
	}
	into := map[graph.ID][]graph.ID{}
	for _, e := range g.Edges(graph.EdgeMemberOf) {
		if e.Source == "google" {
			into[e.To] = append(into[e.To], e.From)
		}
	}
	members := func(root graph.ID) map[string]bool {
		out := map[string]bool{}
		seen := map[graph.ID]bool{}
		stack := []graph.ID{root}
		for len(stack) > 0 {
			gid := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[gid] {
				continue
			}
			seen[gid] = true
			if n, ok := g.Get(gid); ok && isTrue(n.Attrs["all_users"]) {
				for _, u := range users {
					out[strings.TrimPrefix(string(u.ID), "google:user/")] = true
				}
			}
			for _, m := range into[gid] {
				if hash, ok := strings.CutPrefix(string(m), "google:user/"); ok {
					out[hash] = true
				} else if strings.HasPrefix(string(m), "google:group/") {
					stack = append(stack, m)
				}
			}
		}
		return out
	}
	cache := map[graph.ID]map[string]bool{}
	for _, b := range bindings {
		email, _ := b.Private["email"].(string)
		if t, _ := b.Attrs["member_type"].(string); t != "group" || email == "" {
			continue
		}
		hash := h.Email(email)
		gid, ok := groupOf[hash]
		if !ok {
			gid = graph.ID("google:group/" + hash)
		}
		g.Edge(graph.Edge{From: gid, To: b.ID, Kind: graph.EdgeBoundTo, Source: "link"})
		if _, ok := cache[gid]; !ok {
			cache[gid] = members(gid)
		}
		for m := range cache[gid] {
			hash := m
			if p, ok := alias[m]; ok {
				hash = p
			}
			id := person(hash, emails[m], b.SeenAt)
			g.Edge(graph.Edge{From: id, To: b.ID, Kind: graph.EdgeViaGroup, Source: "link"})
		}
	}
}

// linkOwners joins each service account named in owners.yaml to its bindings.
// The config connector wrote the entry; the bindings exist only once GCP is
// read.
func linkOwners(g *graph.Graph, bindings []graph.Node) {
	owners := map[string]graph.ID{}
	for _, n := range g.Nodes(graph.KindConfigOwner) {
		if pr, _ := n.Attrs["principal"].(string); strings.Contains(pr, "@") {
			owners[strings.ToLower(pr)] = n.ID
		}
	}
	if len(owners) == 0 {
		return
	}
	for _, b := range bindings {
		member, _ := b.Attrs["member"].(string)
		if id, ok := owners[strings.ToLower(member)]; ok && member != "" {
			g.Edge(graph.Edge{From: id, To: b.ID, Kind: graph.EdgeOwns, Source: "link"})
		}
	}
}

func sortedSet(m map[string]bool) []any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

func isTrue(v any) bool {
	b, _ := v.(bool)
	return b
}
