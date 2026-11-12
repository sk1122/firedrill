package google

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// tokenFake is the token exchange and the Admin SDK: three users over two
// pages, each with their own grants.
type tokenFake struct {
	t          *testing.T
	denyScope  bool // the delegation lacks the tokens scope
	api403     bool // the API refuses tokens.list
	mu         sync.Mutex
	tokenCalls int
	paths      []string
}

func scopeOf(r *http.Request) string {
	body, _ := io.ReadAll(r.Body)
	q, _ := url.ParseQuery(string(body))
	parts := strings.Split(q.Get("assertion"), ".")
	if len(parts) < 2 {
		return ""
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Scope string `json:"scope"`
	}
	_ = json.Unmarshal(raw, &claims)
	return claims.Scope
}

func (f *tokenFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.Header.Get("X-Original-Host")+r.URL.Path)
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.Header.Get("X-Original-Host") {
	case "oauth2.googleapis.com":
		scope := scopeOf(r)
		if strings.Contains(scope, "user.security") {
			f.mu.Lock()
			f.tokenCalls++
			f.mu.Unlock()
			if f.denyScope {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = io.WriteString(w, `{"error":"unauthorized_client","error_description":"Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested."}`)
				return
			}
			_, _ = io.WriteString(w, `{"access_token":"sec","token_type":"Bearer","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"ro","token_type":"Bearer","expires_in":3600}`)
	case "admin.googleapis.com":
		if r.Method != http.MethodGet {
			f.t.Errorf("admin call: %s", r.Method)
		}
		switch {
		case r.URL.Path == "/admin/directory/v1/users":
			if r.Header.Get("Authorization") != "Bearer ro" {
				f.t.Error("the users list uses the read-only scope's token")
			}
			if r.URL.Query().Get("pageToken") == "" {
				_, _ = io.WriteString(w, `{"users":[{"id":"101","primaryEmail":"Ravi@acme.com"},{"id":"102","primaryEmail":"mei@acme.com"}],"nextPageToken":"p2"}`)
				return
			}
			_, _ = io.WriteString(w, `{"users":[{"id":"103","primaryEmail":"gone@acme.com"}]}`)
		case strings.HasSuffix(r.URL.Path, "/tokens"):
			if r.Header.Get("Authorization") != "Bearer sec" {
				f.t.Error("tokens.list uses the security scope's token")
			}
			if f.api403 {
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"error":{"code":403,"message":"Not Authorized to access this resource/api"}}`)
				return
			}
			switch r.URL.Path {
			case "/admin/directory/v1/users/101/tokens":
				_, _ = io.WriteString(w, `{"items":[{"clientId":"1234-notes.apps.googleusercontent.com","displayText":"Acme Notes AI",
					"scopes":["https://www.googleapis.com/auth/drive","https://mail.google.com/","openid"],"nativeApp":false,"anonymous":false}]}`)
			case "/admin/directory/v1/users/102/tokens":
				_, _ = io.WriteString(w, `{"items":[{"clientId":"1234-notes.apps.googleusercontent.com","displayText":"Acme Notes AI","scopes":["https://www.googleapis.com/auth/userinfo.email"]},
					{"clientId":"5678-sched.apps.googleusercontent.com","displayText":"Acme Scheduler","scopes":["https://www.googleapis.com/auth/drive.file","https://www.googleapis.com/auth/calendar.events"],"nativeApp":true}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":{"code":404,"message":"Resource Not Found: userKey"}}`)
			}
		default:
			f.t.Errorf("unexpected path %s", r.URL.Path)
		}
	default:
		f.t.Errorf("unexpected host %s", r.Header.Get("X-Original-Host"))
	}
}

func tokensCollection(c *Connector) connector.Collection {
	for _, col := range c.Collections() {
		if col.Name == CollectionTokens {
			return col
		}
	}
	panic("no tokens collection")
}

func TestCollectOAuthGrants(t *testing.T) {
	f := &tokenFake{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	s := scope(t, keyFile(t))
	g := graph.New()
	if err := c.Collect(context.Background(), tokensCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	apps := g.Nodes(graph.KindOAuthApp)
	if len(apps) != 2 {
		t.Fatalf("%+v", apps)
	}
	notes, _ := g.Get("google:oauth-app/1234-notes.apps.googleusercontent.com")
	a := notes.Attrs
	if a["high_risk"] != true || a["user_count"] != int64(2) || a["name"] != "Acme Notes AI" || a["native"] != false {
		t.Fatalf("%+v", a)
	}
	if got := a["sensitive_scopes"].([]any); len(got) != 2 || got[0] != "https://mail.google.com/" || got[1] != "https://www.googleapis.com/auth/drive" {
		t.Fatalf("sensitive scopes, sorted: %v", got)
	}
	if got := a["scopes"].([]any); len(got) != 4 {
		t.Fatalf("scopes are the union across users: %v", got)
	}
	sched, _ := g.Get("google:oauth-app/5678-sched.apps.googleusercontent.com")
	if sched.Attrs["high_risk"] != false || sched.Attrs["native"] != true || len(sched.Attrs["sensitive_scopes"].([]any)) != 0 {
		t.Fatalf("drive.file reaches only the app's own files: %+v", sched.Attrs)
	}
	edges := g.Edges(graph.EdgeGrantedTo)
	if len(edges) != 3 {
		t.Fatalf("%+v", edges)
	}
	want := graph.ID("person:" + s.Hasher.Email("ravi@acme.com"))
	found := false
	for _, e := range edges {
		if strings.Contains(string(e.To), "@") {
			t.Fatalf("an edge names a person by email: %+v", e)
		}
		found = found || e.To == want
	}
	if !found {
		t.Fatal("grants link to the hashed person, as the link step names them")
	}
	scan, _ := g.Get(graph.ScanID(TokenScanner, ""))
	if p, _ := scan.Attrs["partial"].(string); !strings.Contains(p, "1 of 3 users") || scan.Attrs["inspected"] != int64(2) || scan.Attrs["error"] != nil {
		t.Fatalf("a user whose grants cannot be read makes the result partial: %+v", scan.Attrs)
	}
	for _, n := range g.Nodes("") {
		b, _ := json.Marshal(n.Attrs)
		if strings.Contains(string(b), "@acme.com") {
			t.Fatalf("an email reached node attributes: %s", b)
		}
	}
	for _, call := range s.Log.Calls() {
		if strings.Contains(call.Endpoint, "@") {
			t.Fatalf("an email reached the call log: %s", call.Endpoint)
		}
	}
}

func TestMissingTokensScopeIsAnErrorOnThisCollectionOnly(t *testing.T) {
	for _, c := range []struct {
		name string
		f    *tokenFake
	}{{"token exchange refuses the scope", &tokenFake{denyScope: true}}, {"the API answers 403", &tokenFake{api403: true}}} {
		t.Run(c.name, func(t *testing.T) {
			c.f.t = t
			srv := httptest.NewServer(c.f)
			defer srv.Close()
			conn := New()
			conn.Next = rewrite{srv}
			s := scope(t, keyFile(t))
			g := graph.New()
			if err := conn.Collect(context.Background(), conn.Collections()[0], s, g); err != nil {
				t.Fatalf("users still read: %v", err)
			}
			if err := conn.Collect(context.Background(), tokensCollection(conn), s, g); err != nil {
				t.Fatalf("a missing scope must not fail the connector: %v", err)
			}
			if len(g.Nodes(graph.KindIdentityUser)) != 3 {
				t.Fatal("identity.users is untouched")
			}
			scan, _ := g.Get(graph.ScanID(TokenScanner, ""))
			if e, _ := scan.Attrs["error"].(string); !strings.Contains(e, TokensScope) || !strings.Contains(e, "domain-wide delegation") {
				t.Fatalf("%+v", scan.Attrs)
			}
			tokensCalls := 0
			for _, p := range c.f.paths {
				if strings.HasSuffix(p, "/tokens") {
					tokensCalls++
				}
			}
			if tokensCalls > 1 || c.f.tokenCalls > 2 {
				t.Fatalf("a missing scope stops after the first user: %v", c.f.paths)
			}
		})
	}
}

func TestSensitiveScopes(t *testing.T) {
	yes := map[string]string{
		"https://mail.google.com/":                                     "mail",
		"https://www.googleapis.com/auth/gmail.readonly":               "mail",
		"https://www.googleapis.com/auth/gmail.labels":                 "mail",
		"https://www.googleapis.com/auth/drive":                        "drive",
		"https://www.googleapis.com/auth/drive.readonly":               "drive",
		"https://www.googleapis.com/auth/drive.metadata.readonly":      "drive",
		"https://www.googleapis.com/auth/spreadsheets":                 "drive",
		"https://www.googleapis.com/auth/admin.directory.user":         "admin",
		"https://www.googleapis.com/auth/admin.reports.audit.readonly": "admin",
		"https://www.googleapis.com/auth/cloud-platform":               "cloud",
	}
	for sc, area := range yes {
		if got := SensitiveArea(sc); got != area {
			t.Errorf("%s: got %q, want %q", sc, got, area)
		}
	}
	for _, sc := range []string{"https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive.appdata",
		"https://www.googleapis.com/auth/drive.apps.readonly", "openid", "https://www.googleapis.com/auth/userinfo.email",
		"https://www.googleapis.com/auth/calendar.events", "https://www.googleapis.com/auth/drivex", "https://www.googleapis.com/auth/administrator"} {
		if got := SensitiveArea(sc); got != "" {
			t.Errorf("%s is not sensitive, got %s", sc, got)
		}
	}
}

func TestRevokingAGrantIsRefused(t *testing.T) {
	tr := &connector.Transport{Policy: connector.GooglePolicy(), Log: &connector.CallLog{}, Connector: "google"}
	req, _ := http.NewRequest(http.MethodDelete, "https://admin.googleapis.com/admin/directory/v1/users/101/tokens/1234-notes.apps.googleusercontent.com", nil)
	if _, err := tr.RoundTrip(req); !errors.Is(err, connector.ErrBlocked) {
		t.Fatalf("tokens.delete must be refused: %v", err)
	}
}
