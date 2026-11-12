package graph

import (
	"slices"
	"testing"
)

func TestSubgraphFollowsKindsDirectionAndHops(t *testing.T) {
	g := New()
	for _, id := range []ID{"person:a", "github:user/a", "github:repo/acme/api", "github:env/acme/api/production", "github:user/b"} {
		g.Node(Node{ID: id, Kind: "k"})
	}
	g.Edge(Edge{From: "person:a", To: "github:user/a", Kind: EdgeSamePerson})
	g.Edge(Edge{From: "github:user/a", To: "github:repo/acme/api", Kind: EdgeCanBypass})
	g.Edge(Edge{From: "github:user/b", To: "github:repo/acme/api", Kind: EdgeWritesTo})
	g.Edge(Edge{From: "github:repo/acme/api", To: "github:env/acme/api/production", Kind: EdgeDeploysTo})
	g.Edge(Edge{From: "secret:x", To: "file:acme/api/.env", Kind: EdgeFoundIn})
	a := NewAdjacency(g)

	ids := func(s Sub) []ID { return s.IDs() }
	out := a.Subgraph(Query{Start: []ID{"person:a"}, Dir: Out, Hops: 3})
	if !slices.Equal(ids(out), []ID{"github:env/acme/api/production", "github:repo/acme/api", "github:user/a", "person:a"}) || len(out.Edges) != 3 {
		t.Fatalf("out: %+v", out)
	}
	if two := a.Subgraph(Query{Start: []ID{"person:a"}, Dir: Out, Hops: 2}); len(two.Nodes) != 3 {
		t.Fatalf("the hop limit holds: %+v", two)
	}
	back := a.Subgraph(Query{Start: []ID{"github:env/acme/api/production"}, Kinds: []string{EdgeDeploysTo, EdgeCanBypass, EdgeSamePerson}, Dir: In, Hops: 5})
	if !slices.Equal(ids(back), []ID{"github:env/acme/api/production", "github:repo/acme/api", "github:user/a", "person:a"}) {
		t.Fatalf("writes_to is not followed: %+v", back)
	}
	both := a.Subgraph(Query{Start: []ID{"github:user/a"}, Dir: Both, Hops: 1})
	if !slices.Equal(ids(both), []ID{"github:repo/acme/api", "github:user/a", "person:a"}) {
		t.Fatalf("both ways: %+v", both)
	}
	f := a.Subgraph(Query{Start: []ID{"secret:x"}, Dir: Out, Hops: 1})
	if len(f.Nodes) != 2 || f.Nodes[0].ID != "file:acme/api/.env" || f.Nodes[0].Kind != "" {
		t.Fatalf("a node the graph does not hold keeps its ID: %+v", f)
	}
	a.Add(Edge{From: "person:a", To: "secret:x", Kind: "can_read"})
	more := a.Subgraph(Query{Start: []ID{"person:a"}, Kinds: []string{"can_read", EdgeFoundIn}, Dir: Out, Hops: 2})
	more.Merge(out)
	if len(more.Nodes) != 6 || len(more.Edges) != 5 {
		t.Fatalf("merged: %+v", more)
	}
}
