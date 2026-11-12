package graph

import "sort"

// Direction says which way a subgraph query follows edges.
type Direction int

// Directions an edge can be followed in.
const (
	Out Direction = iota
	In
	Both
)

// Query asks for the part of the graph within Hops of Start, following only
// edges of the given kinds (any kind when empty) in one direction.
type Query struct {
	Start []ID
	Kinds []string
	Dir   Direction
	Hops  int
}

// Sub is a slice of the graph: the nodes reached and the edges followed.
// A node an edge names that the graph does not hold, such as a file a secret
// was found in, is kept with only its ID.
type Sub struct {
	Nodes []Node
	Edges []Edge
}

// Adjacency indexes a graph's edges both ways, so many queries over one
// graph each cost only what they reach.
type Adjacency struct {
	r       Reader
	out, in map[ID][]Edge
	seen    map[Edge]bool
}

// NewAdjacency indexes every edge of r.
func NewAdjacency(r Reader) *Adjacency {
	a := &Adjacency{r: r, out: map[ID][]Edge{}, in: map[ID][]Edge{}, seen: map[Edge]bool{}}
	for _, e := range r.Edges("") {
		a.Add(e)
	}
	return a
}

// Add indexes one more edge, such as one a view works out for drawing.
func (a *Adjacency) Add(e Edge) {
	if a.seen[e] {
		return
	}
	a.seen[e] = true
	a.out[e.From] = append(a.out[e.From], e)
	a.in[e.To] = append(a.in[e.To], e)
}

// Subgraph answers a query breadth first. Nodes come back sorted by ID, and
// edges in a stable order.
func (a *Adjacency) Subgraph(q Query) Sub {
	kinds := map[string]bool{}
	for _, k := range q.Kinds {
		kinds[k] = true
	}
	nodes := map[ID]bool{}
	edges := map[Edge]bool{}
	frontier := []ID{}
	for _, id := range q.Start {
		if !nodes[id] {
			nodes[id] = true
			frontier = append(frontier, id)
		}
	}
	for hop := 0; hop < q.Hops && len(frontier) > 0; hop++ {
		var next []ID
		step := func(e Edge, other ID) {
			if len(kinds) > 0 && !kinds[e.Kind] {
				return
			}
			edges[e] = true
			if !nodes[other] {
				nodes[other] = true
				next = append(next, other)
			}
		}
		for _, id := range frontier {
			if q.Dir == Out || q.Dir == Both {
				for _, e := range a.out[id] {
					step(e, e.To)
				}
			}
			if q.Dir == In || q.Dir == Both {
				for _, e := range a.in[id] {
					step(e, e.From)
				}
			}
		}
		frontier = next
	}
	var s Sub
	for id := range nodes {
		n, ok := a.r.Get(id)
		if !ok {
			n = Node{ID: id}
		}
		s.Nodes = append(s.Nodes, n)
	}
	for e := range edges {
		s.Edges = append(s.Edges, e)
	}
	s.sort()
	return s
}

// Merge adds another slice's nodes and edges, each once.
func (s *Sub) Merge(o Sub) {
	have := map[ID]bool{}
	for _, n := range s.Nodes {
		have[n.ID] = true
	}
	for _, n := range o.Nodes {
		if !have[n.ID] {
			have[n.ID] = true
			s.Nodes = append(s.Nodes, n)
		}
	}
	seen := map[Edge]bool{}
	for _, e := range s.Edges {
		seen[e] = true
	}
	for _, e := range o.Edges {
		if !seen[e] {
			seen[e] = true
			s.Edges = append(s.Edges, e)
		}
	}
	s.sort()
}

// IDs lists the slice's node IDs.
func (s Sub) IDs() []ID {
	out := make([]ID, len(s.Nodes))
	for i, n := range s.Nodes {
		out[i] = n.ID
	}
	return out
}

func (s *Sub) sort() {
	sort.Slice(s.Nodes, func(i, j int) bool { return s.Nodes[i].ID < s.Nodes[j].ID })
	sort.Slice(s.Edges, func(i, j int) bool {
		a, b := s.Edges[i], s.Edges[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Kind < b.Kind
	})
}
