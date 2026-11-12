package openai

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

// fakeKey is built by concatenation so no scanner mistakes this file for a leak.
var fakeKey = "sk-admin-" + "acmefake" + "-0000"

const fakeEmail = "ravi@acme.com"

type rewrite struct{ server *httptest.Server }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.server.URL)
	c := req.Clone(req.Context())
	c.Header.Set("X-Original-Host", req.URL.Host)
	c.URL.Scheme, c.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(c)
}

func scope(connected bool, key string) connector.Scope {
	p := &config.Project{}
	if connected {
		p.Config.Connected = []string{"openai"}
	}
	return connector.Scope{Project: p, Now: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Log: &connector.CallLog{},
		Hasher: graph.NewHasher("s"), Getenv: func(k string) string {
			if k == KeyEnv {
				return key
			}
			return ""
		}}
}

type fake struct {
	t        *testing.T
	refuse   int // status for every call
	orgLimit string
	paths    []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.paths = append(f.paths, r.Method+" "+r.URL.Path)
	if r.Header.Get("X-Original-Host") != "api.openai.com" || r.Method != http.MethodGet {
		f.t.Errorf("unexpected %s %s", r.Method, r.Header.Get("X-Original-Host"))
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeKey {
		f.t.Error("no admin key")
	}
	if f.refuse != 0 {
		w.WriteHeader(f.refuse)
		_, _ = io.WriteString(w, `{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/organization/spend_limit":
		if f.orgLimit == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, f.orgLimit)
	case "/v1/organization/projects":
		if r.URL.Query().Get("after") == "" {
			_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"proj_acmeprod","name":"acme-prod","status":"active"}],"has_more":true,"last_id":"proj_acmeprod"}`)
			return
		}
		_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"proj_acmelab","name":"acme-lab","status":"active"},{"id":"proj_acmeold","name":"old","status":"archived"},{"id":"proj_acmehidden","name":"hidden","status":"active"}],"has_more":false,"last_id":"proj_acmehidden"}`)
	case "/v1/organization/projects/proj_acmeprod/api_keys":
		if r.URL.Query().Get("owner_project_access") != "any" {
			f.t.Error("keys of owners without access must be listed too")
		}
		_, _ = io.WriteString(w, `{"object":"list","data":[
			{"object":"organization.project.api_key","id":"key_acmeloop","name":"overnight-agent","redacted_value":"sk-proj-abc...wxyz","created_at":1767225600,
			 "owner":{"type":"service_account","service_account":{"id":"svc_acct_acmebot","name":"bot"}}},
			{"object":"organization.project.api_key","id":"key_acmeravi","name":"ravi","redacted_value":"`+fakeKey+`","created_at":1767225600,"owner_project_access":"active",
			 "owner":{"type":"user","user":{"id":"user_acmeravi","email":"`+fakeEmail+`","name":"Ravi"}}},
			{"object":"organization.project.api_key","id":"key_acmeleft","name":"left","redacted_value":"sk-proj-def...abcd","created_at":1767225600,"owner_project_access":"inactive",
			 "owner":{"type":"user","user":{"id":"user_acmeleft","email":"left@acme.com"}}},
			{"object":"organization.project.api_key","id":"key_acmeexp","name":"expired","created_at":1767225600,"expires_at":1767225601,"owner":{}}],
			"has_more":false,"last_id":"key_acmeexp"}`)
	case "/v1/organization/projects/proj_acmeprod/spend_limit":
		_, _ = io.WriteString(w, `{"object":"project.spend_limit","currency":"USD","interval":"month","threshold_amount":50000,"enforcement":{"status":"inactive"}}`)
	case "/v1/organization/projects/proj_acmelab/api_keys":
		_, _ = io.WriteString(w, `{"object":"list","data":[{"id":"key_acmelab","name":"lab","created_at":1767225600,"owner":{"type":"user","user":{"id":"user_acmemei","email":"mei@acme.com"}}}],"has_more":false}`)
	case "/v1/organization/projects/proj_acmelab/spend_limit":
		_, _ = io.WriteString(w, `{"object":"project.spend_limit","currency":"USD","interval":"month","threshold_amount":0,"enforcement":{"status":"inactive"}}`)
	case "/v1/organization/projects/proj_acmehidden/api_keys":
		w.WriteHeader(http.StatusForbidden)
	default:
		f.t.Errorf("unexpected path %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func collect(t *testing.T, f *fake) (*graph.Graph, connector.Scope, error) {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c := New()
	c.Next = rewrite{srv}
	s := scope(true, fakeKey)
	g := graph.New()
	return g, s, c.Collect(context.Background(), c.Collections()[0], s, g)
}

func TestCollectKeysAndLimits(t *testing.T) {
	f := &fake{t: t}
	g, s, err := collect(t, f)
	if err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	if len(g.Nodes(graph.KindAIKey)) != 5 {
		t.Fatalf("archived projects are skipped: %+v", g.Nodes(graph.KindAIKey))
	}
	loop, _ := g.Get("openai:key/proj_acmeprod/key_acmeloop")
	a := loop.Attrs
	if a["capped"] != true || a["limit_scope"] != "project" || a["limit_readable"] != true || a["owner_kind"] != "service_account" ||
		a["has_owner"] != true || a["hint"] != "sk-proj-abc...wxyz" || a["project_name"] != "acme-prod" || a["status"] != "active" {
		t.Fatalf("%+v", a)
	}
	ravi, _ := g.Get("openai:key/proj_acmeprod/key_acmeravi")
	if ravi.Attrs["owner"] != "person:"+s.Hasher.Email(fakeEmail) || ravi.Attrs["hint"] != "" {
		t.Fatalf("the owner is the hashed person; a hint not shaped like one is dropped: %+v", ravi.Attrs)
	}
	left, _ := g.Get("openai:key/proj_acmeprod/key_acmeleft")
	if left.Attrs["has_owner"] != false {
		t.Fatal("an owner who lost access to the project is no owner")
	}
	exp, _ := g.Get("openai:key/proj_acmeprod/key_acmeexp")
	if exp.Attrs["status"] != "expired" || exp.Attrs["has_owner"] != false {
		t.Fatalf("%+v", exp.Attrs)
	}
	lab, _ := g.Get("openai:key/proj_acmelab/key_acmelab")
	if lab.Attrs["capped"] != false || lab.Attrs["limit_readable"] != false || lab.Attrs["limit_scope"] != "unknown" {
		t.Fatalf("no project cap and an unreadable organization limit is unknown, not uncapped: %+v", lab.Attrs)
	}
	scan, _ := g.Get(graph.ScanID(Scanner, "openai"))
	if p, _ := scan.Attrs["partial"].(string); !strings.Contains(p, "proj_acmehidden") {
		t.Fatalf("a project whose keys cannot be listed makes it partial: %+v", scan.Attrs)
	}
	b, _ := json.Marshal(g.Nodes(""))
	for _, secret := range []string{fakeKey, fakeEmail, "left@acme.com", "mei@acme.com"} {
		if strings.Contains(string(b), secret) {
			t.Fatalf("%s reached a node", secret)
		}
	}
	lb, _ := json.Marshal(s.Log.Calls())
	if strings.Contains(string(lb), fakeKey) {
		t.Fatal("the admin key reached the call log")
	}
}

func TestOrganizationCapCoversEveryKey(t *testing.T) {
	g, _, err := collect(t, &fake{t: t, orgLimit: `{"object":"organization.spend_limit","threshold_amount":100000,"currency":"USD","interval":"month","enforcement":{"status":"inactive"}}`})
	if err != nil {
		t.Fatal(err)
	}
	lab, _ := g.Get("openai:key/proj_acmelab/key_acmelab")
	if lab.Attrs["capped"] != true || lab.Attrs["limit_scope"] != "organization" {
		t.Fatalf("%+v", lab.Attrs)
	}
	g, _, _ = collect(t, &fake{t: t, orgLimit: `{"object":"organization.spend_limit","threshold_amount":0}`})
	lab, _ = g.Get("openai:key/proj_acmelab/key_acmelab")
	if lab.Attrs["capped"] != false || lab.Attrs["limit_readable"] != true || lab.Attrs["limit_scope"] != "none" {
		t.Fatalf("both limits read and neither set is uncapped: %+v", lab.Attrs)
	}
}

func TestRefusedKeyIsAnError(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		g, _, err := collect(t, &fake{t: t, refuse: code})
		if err == nil || !strings.Contains(err.Error(), "refused") || strings.Contains(err.Error(), fakeKey) {
			t.Fatalf("%d: %v", code, err)
		}
		if len(g.Nodes("")) != 0 {
			t.Fatal("nothing is written when the key is refused")
		}
	}
}

func TestGuardRefusesWritesAndInference(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	cl := c.HTTP(&connector.CallLog{})
	for _, r := range []struct{ method, path string }{
		{http.MethodPost, "/v1/organization/admin_api_keys"},
		{http.MethodPost, "/v1/organization/projects/proj_acmeprod/spend_limit"},
		{http.MethodDelete, "/v1/organization/projects/proj_acmeprod/api_keys/key_acmeloop"},
		{http.MethodPost, "/v1/chat/completions"},
		{http.MethodGet, "/v1/models"},
		{http.MethodGet, "/v1/organization/users"},
	} {
		req, _ := http.NewRequest(r.method, base+r.path, strings.NewReader("{}"))
		if _, err := cl.Do(req); !errors.Is(err, connector.ErrBlocked) {
			t.Errorf("%s %s must be refused: %v", r.method, r.path, err)
		}
	}
	if hit {
		t.Fatal("a refused call reached the server")
	}
}

func TestAvailableNeedsConnectAndKey(t *testing.T) {
	if ok, why := New().Available(scope(false, fakeKey)); ok || why != "connect openai" {
		t.Fatal("a key in the environment is not consent")
	}
	if ok, _ := New().Available(scope(true, "")); ok {
		t.Fatal("connected with no key")
	}
}
