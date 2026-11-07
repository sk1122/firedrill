package graph

import (
	"testing"
	"time"
)

func TestHasherIsStableAndSaltDependent(t *testing.T) {
	a, b := NewHasher("salt-a"), NewHasher("salt-b")
	if a.Email("Ravi@Acme.com ") != a.Email("ravi@acme.com") {
		t.Error("email hash must normalize case and spaces")
	}
	if a.Sum("x") == b.Sum("x") {
		t.Error("different salts must give different hashes")
	}
	if a.Sum("x") != NewHasher("salt-a").Sum("x") {
		t.Error("same salt must give the same hash")
	}
	if a.Fingerprint() == b.Fingerprint() {
		t.Error("fingerprints must differ by salt")
	}
}

func TestGraphOrderAndReplace(t *testing.T) {
	g := New()
	now := time.Now()
	g.Node(Node{ID: "b", Kind: "k", SeenAt: now})
	g.Node(Node{ID: "a", Kind: "k", SeenAt: now})
	g.Node(Node{ID: "a", Kind: "k", Attrs: map[string]any{"x": 1}, SeenAt: now})
	g.Node(Node{ID: "c", Kind: "other", SeenAt: now})
	nodes := g.Nodes("k")
	if len(nodes) != 2 || nodes[0].ID != "a" || nodes[0].Attrs["x"] != 1 {
		t.Fatalf("got %+v", nodes)
	}
	if len(g.Nodes("")) != 3 {
		t.Fatal("empty kind should return all nodes")
	}
	g.Edge(Edge{From: "a", To: "b", Kind: EdgeHolds})
	g.Edge(Edge{From: "a", To: "b", Kind: EdgeHolds})
	if len(g.Edges(EdgeHolds)) != 1 {
		t.Fatal("edges must deduplicate")
	}
}
