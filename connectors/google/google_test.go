package google

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

type rewrite struct{ server *httptest.Server }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.server.URL)
	c := req.Clone(req.Context())
	c.Header.Set("X-Original-Host", req.URL.Host)
	c.URL.Scheme, c.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(c)
}

func keyFile(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "fd@x.iam.gserviceaccount.com", "private_key_id": "1",
		"private_key": string(pemKey), "token_uri": "https://oauth2.googleapis.com/token",
	})
	p := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func scope(t *testing.T, key string) connector.Scope {
	p := &config.Project{}
	p.Config.Google.Domain = "acme.com"
	p.Config.Google.AdminEmail = "admin@acme.com"
	return connector.Scope{Project: p, Now: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Log: &connector.CallLog{},
		Hasher: graph.NewHasher("s"), Getenv: func(k string) string {
			if k == CredentialsEnv {
				return key
			}
			return ""
		}}
}

func TestCollectUsersThroughGuardWithPaging(t *testing.T) {
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Original-Host") {
		case "oauth2.googleapis.com":
			if r.Method != http.MethodPost || r.URL.Path != "/token" {
				t.Errorf("token call: %s %s", r.Method, r.URL.Path)
			}
			_, _ = io.WriteString(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
		case "admin.googleapis.com":
			if r.Method != http.MethodGet {
				t.Errorf("admin call: %s", r.Method)
			}
			if r.URL.Query().Get("domain") != "acme.com" {
				t.Errorf("query: %s", r.URL.RawQuery)
			}
			pages++
			if r.URL.Query().Get("pageToken") == "" {
				_, _ = io.WriteString(w, `{"users":[{"primaryEmail":"Ravi@acme.com","aliases":["rk@acme.com"],"nonEditableAliases":["Ravi.Old@acme.com"],"isAdmin":true,"isEnforcedIn2Sv":true,"isEnrolledIn2Sv":true,"lastLoginTime":"2026-10-01T00:00:00.000Z","creationTime":"2020-01-01T00:00:00.000Z"}],"nextPageToken":"p2"}`)
				return
			}
			_, _ = io.WriteString(w, `{"users":[{"primaryEmail":"new@acme.com","suspended":true,"lastLoginTime":"1970-01-01T00:00:00.000Z","creationTime":"2026-11-01T00:00:00.000Z"}]}`)
		default:
			t.Errorf("unexpected host %s", r.Header.Get("X-Original-Host"))
		}
	}))
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	s := scope(t, keyFile(t))
	g := graph.New()
	if err := c.Collect(context.Background(), c.Collections()[0], s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	if pages != 2 {
		t.Fatalf("pages: %d", pages)
	}
	users := g.Nodes(graph.KindIdentityUser)
	if len(users) != 2 {
		t.Fatal(users)
	}
	byEmail := map[string]graph.Node{}
	for _, u := range users {
		if strings.Contains(string(u.ID), "@") || u.Attrs["email"] != nil {
			t.Fatalf("emails stay out of IDs and attributes: %+v", u)
		}
		byEmail[u.Private["email"].(string)] = u
	}
	ravi := byEmail["ravi@acme.com"]
	if ravi.Attrs["is_admin"] != true || ravi.Attrs["mfa_enforced"] != true || ravi.Attrs["last_login"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("%+v", ravi.Attrs)
	}
	if al, _ := ravi.Private["aliases"].([]string); len(al) != 2 || al[0] != "rk@acme.com" || al[1] != "ravi.old@acme.com" {
		t.Fatalf("aliases are kept, lowercased, for the link step: %+v", ravi.Private)
	}
	for _, u := range users {
		for k, v := range u.Attrs {
			if strings.Contains(strings.ToLower(k+toStr(v)), "alias") || strings.Contains(toStr(v), "@") {
				t.Fatalf("aliases stay out of attributes: %+v", u.Attrs)
			}
		}
	}
	if byEmail["new@acme.com"].Attrs["last_login"] != "" {
		t.Fatal("Google's zero time means never")
	}
}

func TestAvailable(t *testing.T) {
	if ok, why := New().Available(scope(t, "k")); ok || why != "connect google" {
		t.Fatal("a key and config are not enough before connect google")
	}
	s := scope(t, "k")
	s.Project.Config.Connected = []string{"google"}
	if ok, _ := New().Available(s); !ok {
		t.Fatal("all set")
	}
	if ok, why := New().Available(scope(t, "")); ok || why != "connect google" {
		t.Fatal(why)
	}
}

func TestBadKeyDoesNotEchoContent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "k.json")
	if err := os.WriteFile(p, []byte("private-material"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := New()
	err := c.Collect(context.Background(), c.Collections()[0], scope(t, p), graph.New())
	if err == nil || strings.Contains(err.Error(), "private-material") {
		t.Fatalf("%v", err)
	}
}

func toStr(v any) string { b, _ := json.Marshal(v); return string(b) }
