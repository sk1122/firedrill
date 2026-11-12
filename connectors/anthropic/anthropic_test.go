package anthropic

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
var fakeKey = "sk-ant-admin01-" + "acmefake" + "-0000"

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
		p.Config.Connected = []string{"anthropic"}
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
	t      *testing.T
	status int
	paths  []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.paths = append(f.paths, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
	if r.Header.Get("X-Original-Host") != "api.anthropic.com" || r.Method != http.MethodGet {
		f.t.Errorf("unexpected %s %s", r.Method, r.Header.Get("X-Original-Host"))
	}
	if r.Header.Get("x-api-key") != fakeKey || r.Header.Get("anthropic-version") == "" {
		f.t.Errorf("headers: %v", r.Header)
	}
	if f.status != 0 {
		w.WriteHeader(f.status)
		_, _ = io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/v1/organizations/workspaces":
		_, _ = io.WriteString(w, `{"data":[{"id":"wrkspc_01AcmeProd","name":"acme-prod","type":"workspace"},{"id":"wrkspc_01AcmeDev","name":"acme-dev"}],"has_more":false,"last_id":"wrkspc_01AcmeDev"}`)
	case "/v1/organizations/api_keys":
		if r.URL.Query().Get("after_id") == "" {
			_, _ = io.WriteString(w, `{"data":[
				{"id":"apikey_01AcmeLoop","type":"api_key","name":"overnight-agent","status":"active","created_at":"2026-01-01T00:00:00Z",
				 "partial_key_hint":"sk-ant-api03-R2D...igAA","created_by":null,"principal":null,"scope":{"type":"workspace","workspace_id":"wrkspc_01AcmeProd"}},
				{"id":"apikey_01AcmeCI","type":"api_key","name":"ci","status":"active","created_at":"2026-10-01T00:00:00.123Z",
				 "partial_key_hint":"`+fakeKey+`","created_by":{"id":"user_01AcmeRavi","type":"user"},"scope":{"type":"workspace","workspace_id":"wrkspc_01AcmeDev"}}],
				"has_more":true,"last_id":"apikey_01AcmeCI"}`)
			return
		}
		_, _ = io.WriteString(w, `{"data":[{"id":"apikey_01AcmeOld","name":"old","status":"archived","created_at":"2025-01-01T00:00:00Z",
			"principal":{"type":"service_account_actor","service_account_id":"svac_01AcmeBot"},"workspace_id":"wrkspc_01AcmeProd"}],"has_more":false,"last_id":"apikey_01AcmeOld"}`)
	default:
		f.t.Errorf("unexpected path %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestCollectKeysWithPaging(t *testing.T) {
	f := &fake{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	s := scope(true, fakeKey)
	g := graph.New()
	if err := c.Collect(context.Background(), c.Collections()[0], s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	keys := g.Nodes(graph.KindAIKey)
	if len(keys) != 3 {
		t.Fatalf("%+v", keys)
	}
	loop, _ := g.Get("anthropic:key/apikey_01AcmeLoop")
	a := loop.Attrs
	if a["has_owner"] != false || a["owner_kind"] != "unknown" || a["limit_readable"] != false || a["capped"] != false ||
		a["workspace"] != "wrkspc_01AcmeProd" || a["workspace_name"] != "acme-prod" || a["hint"] != "sk-ant-api03-R2D...igAA" {
		t.Fatalf("%+v", a)
	}
	ci, _ := g.Get("anthropic:key/apikey_01AcmeCI")
	if ci.Attrs["owner"] != "anthropic:user/user_01AcmeRavi" || ci.Attrs["has_owner"] != true || ci.Attrs["created"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("%+v", ci.Attrs)
	}
	if ci.Attrs["hint"] != "" {
		t.Fatal("a hint not shaped like a redacted hint is never stored")
	}
	old, _ := g.Get("anthropic:key/apikey_01AcmeOld")
	if old.Attrs["status"] != "archived" || old.Attrs["owner_kind"] != "service_account" || old.Attrs["workspace"] != "wrkspc_01AcmeProd" {
		t.Fatalf("%+v", old.Attrs)
	}
	b, _ := json.Marshal(g.Nodes(""))
	if strings.Contains(string(b), fakeKey) {
		t.Fatal("the admin key reached a node")
	}
	lb, _ := json.Marshal(s.Log.Calls())
	if strings.Contains(string(lb), fakeKey) || strings.Contains(string(lb), "after_id") {
		t.Fatalf("the call log holds only endpoints: %s", lb)
	}
}

func TestRefusedKeyIsAnError(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		f := &fake{t: t, status: code}
		srv := httptest.NewServer(f)
		c := New()
		c.Next = rewrite{srv}
		s := scope(true, fakeKey)
		g := graph.New()
		err := c.Collect(context.Background(), c.Collections()[0], s, g)
		srv.Close()
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
	log := &connector.CallLog{}
	cl := c.HTTP(log)
	for _, r := range []struct{ method, path string }{
		{http.MethodPost, "/v1/organizations/api_keys/apikey_01AcmeLoop"},
		{http.MethodPost, "/v1/messages"},
		{http.MethodGet, "/v1/models"},
		{http.MethodGet, "/v1/organizations/users"},
		{http.MethodDelete, "/v1/organizations/workspaces"},
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
	if ok, why := New().Available(scope(false, fakeKey)); ok || why != "connect anthropic" {
		t.Fatal("a key in the environment is not consent")
	}
	if ok, _ := New().Available(scope(true, "")); ok {
		t.Fatal("connected with no key")
	}
	if ok, _ := New().Available(scope(true, fakeKey)); !ok {
		t.Fatal("connected with a key")
	}
}
