package google

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// groupFake is the token exchange and the Admin SDK's groups and members
// lists. admins (g1, alias team-admins) holds cy and ops (g2); ops holds a
// partner, every user in the account, and admins again, a cycle. readers (g3)
// cannot be read, and unbound (g4) is named by no binding.
type groupFake struct {
	t         *testing.T
	denyScope bool
	mu        sync.Mutex
	paths     []string
}

func (f *groupFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.Header.Get("X-Original-Host")+r.URL.RequestURI())
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Header.Get("X-Original-Host") {
	case "oauth2.googleapis.com":
		if !strings.Contains(scopeOf(r), "admin.directory.group.readonly") {
			f.t.Errorf("groups use only the read-only group scope: %s", scopeOf(r))
		}
		if f.denyScope {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"unauthorized_client","error_description":"Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested."}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"grp","token_type":"Bearer","expires_in":3600}`)
	case "admin.googleapis.com":
		if r.Method != http.MethodGet {
			f.t.Errorf("admin call: %s", r.Method)
		}
		q := r.URL.Query()
		switch r.URL.Path {
		case "/admin/directory/v1/groups":
			if q.Get("customer") != "my_customer" || q.Get("maxResults") != "200" {
				f.t.Errorf("groups.list query: %s", r.URL.RawQuery)
			}
			if q.Get("pageToken") == "" {
				_, _ = io.WriteString(w, `{"groups":[{"id":"g1","email":"Admins@acme.com","aliases":["team-admins@acme.com"],"directMembersCount":"2"}],"nextPageToken":"p2"}`)
				return
			}
			_, _ = io.WriteString(w, `{"groups":[{"id":"g2","email":"ops@acme.com"},{"id":"g3","email":"readers@acme.com"},{"id":"g4","email":"unbound@acme.com"}]}`)
		case "/admin/directory/v1/groups/g1/members":
			if q.Get("pageToken") == "" {
				_, _ = io.WriteString(w, `{"members":[{"id":"u1","email":"Cy@acme.com","type":"USER","role":"MEMBER"}],"nextPageToken":"m2"}`)
				return
			}
			_, _ = io.WriteString(w, `{"members":[{"id":"g2","email":"ops@acme.com","type":"GROUP","role":"MEMBER"}]}`)
		case "/admin/directory/v1/groups/g2/members":
			_, _ = io.WriteString(w, `{"members":[{"id":"u9","email":"ext@partner.example","type":"USER"},{"id":"C0123","type":"CUSTOMER"},
				{"id":"g1","email":"admins@acme.com","type":"GROUP"}]}`)
		case "/admin/directory/v1/groups/g3/members":
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":403,"message":"Not Authorized to access this resource/api"}}`)
		default:
			f.t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	default:
		f.t.Errorf("unexpected host %s", r.Header.Get("X-Original-Host"))
	}
}

func groupsCollection(c *Connector) connector.Collection {
	for _, col := range c.Collections() {
		if col.Name == CollectionGroups {
			return col
		}
	}
	panic("no groups collection")
}

// boundGraph holds GCP bindings as the GCP connector writes them: one names a
// group by its alias, one a group that cannot be read, one a group outside
// the account, and one a user.
func boundGraph(h graph.Hasher) *graph.Graph {
	g := graph.New()
	for i, m := range []string{"group:team-admins@acme.com", "group:readers@acme.com", "group:outside@other.example", "user:cy@acme.com"} {
		kind, email, _ := strings.Cut(m, ":")
		g.Node(graph.Node{ID: graph.ID("gcp:binding/acme-prod/roles/owner/" + h.Sum(m)), Kind: graph.KindGCPBinding, Source: "gcp",
			Attrs: map[string]any{"member_type": kind, "role": "roles/owner", "n": i}, Private: map[string]any{"email": email}})
	}
	return g
}

func TestCollectGroupsBoundToGCP(t *testing.T) {
	f := &groupFake{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	s := scope(t, keyFile(t))
	g := boundGraph(s.Hasher)
	if err := c.Collect(context.Background(), groupsCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	for _, p := range f.paths {
		if strings.Contains(p, "/g4/") {
			t.Fatalf("a group no binding names was read: %s", p)
		}
	}
	h := s.Hasher
	admins, _ := g.Get(GroupID(h, "admins@acme.com"))
	ops, _ := g.Get(GroupID(h, "ops@acme.com"))
	readers, _ := g.Get(GroupID(h, "readers@acme.com"))
	outside, _ := g.Get(GroupID(h, "outside@other.example"))
	if admins.Attrs["members_known"] != true || admins.Attrs["member_count"] != int64(2) || admins.Attrs["external_members"] != false {
		t.Fatalf("admins, read over two pages: %+v", admins.Attrs)
	}
	if a, _ := admins.Private["aliases"].([]string); len(a) != 1 || a[0] != "team-admins@acme.com" {
		t.Fatalf("the alias a binding names is kept for the link step: %+v", admins.Private)
	}
	if ops.Attrs["external_members"] != true || ops.Attrs["all_users"] != true || ops.Attrs["members_known"] != true {
		t.Fatalf("ops, nested in admins: %+v", ops.Attrs)
	}
	if readers.Attrs["members_known"] != false || outside.Attrs["members_known"] != false {
		t.Fatalf("an unreadable group and one outside the account are unknown: %+v %+v", readers.Attrs, outside.Attrs)
	}
	want := map[graph.Edge]bool{
		{From: UserID(h, "cy@acme.com"), To: admins.ID, Kind: graph.EdgeMemberOf, Source: "google"}:      true,
		{From: ops.ID, To: admins.ID, Kind: graph.EdgeMemberOf, Source: "google"}:                        true,
		{From: UserID(h, "ext@partner.example"), To: ops.ID, Kind: graph.EdgeMemberOf, Source: "google"}: true,
		{From: admins.ID, To: ops.ID, Kind: graph.EdgeMemberOf, Source: "google"}:                        true,
	}
	edges := g.Edges(graph.EdgeMemberOf)
	if len(edges) != len(want) {
		t.Fatalf("%+v", edges)
	}
	for _, e := range edges {
		if !want[e] {
			t.Fatalf("unexpected %+v", e)
		}
	}
	scan, _ := g.Get(graph.ScanID(GroupScanner, ""))
	if p, _ := scan.Attrs["partial"].(string); !strings.Contains(p, "2 of 4 groups") || scan.Attrs["inspected"] != int64(2) || scan.Attrs["error"] != nil {
		t.Fatalf("%+v", scan.Attrs)
	}
	for _, n := range g.Nodes("") {
		b, _ := json.Marshal(n.Attrs)
		if strings.Contains(string(b), "@") {
			t.Fatalf("an address reached node attributes: %s", b)
		}
	}
	for _, call := range s.Log.Calls() {
		if strings.Contains(call.Endpoint, "@") {
			t.Fatalf("an address reached the call log: %s", call.Endpoint)
		}
	}
}

func TestGroupsReadNothingWhenNoBindingNamesAGroup(t *testing.T) {
	f := &groupFake{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	s := scope(t, keyFile(t))
	g := graph.New()
	if err := c.Collect(context.Background(), groupsCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	if len(f.paths) != 0 {
		t.Fatalf("no call when no group holds a role: %v", f.paths)
	}
	if scan, ok := g.Get(graph.ScanID(GroupScanner, "")); !ok || scan.Attrs["inspected"] != int64(0) || scan.Attrs["error"] != nil {
		t.Fatalf("%+v", scan)
	}
}

func TestMissingGroupsScopeIsAnErrorOnThisCollectionOnly(t *testing.T) {
	f := &groupFake{t: t, denyScope: true}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	s := scope(t, keyFile(t))
	g := boundGraph(s.Hasher)
	if err := c.Collect(context.Background(), groupsCollection(c), s, g); err != nil {
		t.Fatalf("a missing scope must not fail the connector: %v", err)
	}
	scan, _ := g.Get(graph.ScanID(GroupScanner, ""))
	if e, _ := scan.Attrs["error"].(string); !strings.Contains(e, GroupsScope) || !strings.Contains(e, "domain-wide delegation") {
		t.Fatalf("%+v", scan.Attrs)
	}
	if len(g.Nodes(graph.KindGoogleGroup)) != 0 {
		t.Fatal("no group is written when none could be read")
	}
}

func TestGroupReadsAreGetOnly(t *testing.T) {
	tr := &connector.Transport{Policy: connector.GooglePolicy(), Log: &connector.CallLog{}, Connector: "google"}
	for _, m := range []string{http.MethodPost, http.MethodDelete, http.MethodPatch, http.MethodPut} {
		req, _ := http.NewRequest(m, "https://admin.googleapis.com/admin/directory/v1/groups/g1/members", nil)
		if _, err := tr.RoundTrip(req); !errors.Is(err, connector.ErrBlocked) {
			t.Fatalf("%s on members must be refused: %v", m, err)
		}
	}
}
