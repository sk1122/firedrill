package run

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
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/connectors/google"
	"github.com/sk1122/firedrill/internal/graph"
)

type googleRewrite struct{ server *httptest.Server }

func (r googleRewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.server.URL)
	c := req.Clone(req.Context())
	c.Header.Set("X-Original-Host", req.URL.Host)
	c.URL.Scheme, c.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(c)
}

// A GCP binding that names a user by an alias address links to the same
// person as their primary address. The user node comes from the real Google
// connector, not a hand-built node, so this fails if the connector stops
// keeping aliases.
func TestLinkResolvesUserAliasFromGoogleConnector(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Original-Host") == "oauth2.googleapis.com" {
			_, _ = io.WriteString(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
			return
		}
		_, _ = io.WriteString(w, `{"users":[{"primaryEmail":"ana@acme.example","aliases":["ana.s@acme.example"],"nonEditableAliases":["ana.old@acme.example"]}]}`)
	}))
	defer srv.Close()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	kb, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "fd@x.iam.gserviceaccount.com", "private_key_id": "1",
		"private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "token_uri": "https://oauth2.googleapis.com/token"})
	key := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(key, kb, 0o600); err != nil {
		t.Fatal(err)
	}

	h := salt
	p := peopleProject()
	p.Config.Google.AdminEmail = "admin@acme.example"
	s := connector.Scope{Project: p, Now: testNow, Log: &connector.CallLog{}, Hasher: h,
		Getenv: func(string) string { return key }}
	g := graph.New()
	c := google.New()
	c.Next = googleRewrite{srv}
	if err := c.Collect(context.Background(), c.Collections()[0], s, g); err != nil {
		t.Fatal(err)
	}
	for _, email := range []string{"ana.s@acme.example", "ana.old@acme.example"} {
		b := graph.ID("gcp:binding/acme-prod/roles/owner/" + h.Sum("user:"+email))
		g.Node(graph.Node{ID: b, Kind: graph.KindGCPBinding, Source: "gcp", SeenAt: testNow,
			Attrs:   map[string]any{"member_type": "user", "role": "roles/owner"},
			Private: map[string]any{"email": email}})
	}
	link(g, h, p)

	want := personID("ana@acme.example")
	if _, ok := g.Get(personID("ana.s@acme.example")); ok {
		t.Fatal("an alias must not become a person of its own")
	}
	n := 0
	for _, e := range g.Edges(graph.EdgeSamePerson) {
		if e.From == want {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("the user and both alias bindings belong to ana: %d same_person edges", n)
	}
}
