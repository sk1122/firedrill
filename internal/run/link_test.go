package run

import (
	"testing"

	"github.com/sk1122/firedrill/internal/graph"
)

// A binding may name a group by an alias, and a group may hold every user in
// the account.
func TestLinkResolvesGroupAliasesAndWholeAccountGroups(t *testing.T) {
	h := salt
	g := graph.New()
	for _, email := range []string{"ana@acme.example", "bo@acme.example"} {
		g.Node(graph.Node{ID: graph.ID("google:user/" + h.Email(email)), Kind: graph.KindIdentityUser, Source: "google",
			Attrs: map[string]any{}, Private: map[string]any{"email": email}})
	}
	all := graph.ID("google:group/" + h.Email("everyone@acme.example"))
	g.Node(graph.Node{ID: all, Kind: graph.KindGoogleGroup, Source: "google",
		Attrs:   map[string]any{"members_known": true, "all_users": true},
		Private: map[string]any{"email": "everyone@acme.example", "aliases": []string{"all@acme.example"}}})
	b := graph.ID("gcp:binding/acme-prod/roles/editor/x")
	g.Node(graph.Node{ID: b, Kind: graph.KindGCPBinding, Source: "gcp",
		Attrs: map[string]any{"member_type": "group", "role": "roles/editor"}, Private: map[string]any{"email": "all@acme.example"}})
	link(g, h, peopleProject())

	want := map[graph.Edge]bool{
		{From: all, To: b, Kind: graph.EdgeBoundTo, Source: "link"}:                           true,
		{From: personID("ana@acme.example"), To: b, Kind: graph.EdgeViaGroup, Source: "link"}: true,
		{From: personID("bo@acme.example"), To: b, Kind: graph.EdgeViaGroup, Source: "link"}:  true,
	}
	for _, kind := range []string{graph.EdgeBoundTo, graph.EdgeViaGroup} {
		for _, e := range g.Edges(kind) {
			if !want[e] {
				t.Fatalf("unexpected %+v", e)
			}
			delete(want, e)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing %+v", want)
	}
	p, _ := g.Get(personID("bo@acme.example"))
	if p.Kind != graph.KindPerson || p.Attrs["external"] != false || p.Private["email"] != "bo@acme.example" {
		t.Fatalf("%+v", p)
	}
}
