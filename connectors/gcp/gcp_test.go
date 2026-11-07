package gcp

import (
	"context"
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

type rewrite struct{ server *httptest.Server }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.server.URL)
	c := req.Clone(req.Context())
	c.Header.Set("X-Original-Host", req.URL.Host)
	c.URL.Scheme, c.URL.Host = u.Scheme, u.Host
	return http.DefaultTransport.RoundTrip(c)
}

const userCreds = `{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r","quota_project_id":"acme-quota"}`

func scope(projects ...string) connector.Scope {
	p := &config.Project{}
	p.Config.GCP.Projects = projects
	p.Config.Google.Domain = "Acme.com"
	return connector.Scope{Project: p, Now: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Log: &connector.CallLog{},
		Hasher: graph.NewHasher("s"), Getenv: func(k string) string {
			if k == CredentialsEnv {
				return "/creds.json"
			}
			return ""
		}}
}

func newConn(srv *httptest.Server) *Connector {
	c := New()
	c.Next = rewrite{srv}
	c.ReadFile = func(string) ([]byte, error) { return []byte(userCreds), nil }
	return c
}

type fake struct {
	t            *testing.T
	analyzerCode int
	calls        []string
}

func (f *fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Original-Host")
	f.calls = append(f.calls, r.Method+" "+host+r.URL.Path)
	if host != "oauth2.googleapis.com" && r.Header.Get("Authorization") != "Bearer tok" {
		f.t.Errorf("no bearer token on %s", r.URL.Path)
	}
	if host != "oauth2.googleapis.com" && r.Header.Get("X-Goog-User-Project") != "acme-quota" {
		f.t.Errorf("no quota project on %s", r.URL.Path)
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case host == "oauth2.googleapis.com" && r.Method == http.MethodPost && r.URL.Path == "/token":
		_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
	case host == crmHost && r.Method == http.MethodPost && r.URL.Path == "/v3/projects/acme-prod:getIamPolicy":
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), `"requestedPolicyVersion":3`) {
			f.t.Errorf("policy version not requested: %s", b)
		}
		_, _ = io.WriteString(w, `{"bindings":[
			{"role":"roles/owner","members":["user:Ravi@Acme.com","user:friend@gmail.com"]},
			{"role":"roles/editor","members":["serviceAccount:123-compute@developer.gserviceaccount.com","serviceAccount:123@cloudservices.gserviceaccount.com","deleted:user:old@contractor.io?uid=9"]},
			{"role":"roles/viewer","members":["allUsers","domain:acme.com"],"condition":{"expression":"true"}}]}`)
	case host == iamHost && r.Method == http.MethodGet && r.URL.Path == "/v1/projects/acme-prod/serviceAccounts":
		if r.URL.Query().Get("pageToken") == "" {
			_, _ = io.WriteString(w, `{"accounts":[{"email":"ci@acme-prod.iam.gserviceaccount.com"}],"nextPageToken":"p2"}`)
			return
		}
		_, _ = io.WriteString(w, `{"accounts":[{"email":"web@acme-prod.iam.gserviceaccount.com"}]}`)
	case host == iamHost && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys"):
		if r.URL.Query().Get("keyTypes") != "USER_MANAGED" {
			f.t.Errorf("keys must be user-managed only")
		}
		if strings.Contains(r.URL.Path, "ci@") {
			_, _ = io.WriteString(w, `{"keys":[{"name":"projects/acme-prod/serviceAccounts/ci@acme-prod.iam.gserviceaccount.com/keys/k1","validAfterTime":"2025-01-02T03:04:05.123Z","keyType":"USER_MANAGED"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	case host == analyzerHost && r.Method == http.MethodGet:
		if f.analyzerCode != 0 {
			w.WriteHeader(f.analyzerCode)
			_, _ = io.WriteString(w, `{"error":{"code":403,"message":"Policy Analyzer API has not been used","status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED"}]}}`)
			return
		}
		_, _ = io.WriteString(w, `{"activities":[{"fullResourceName":"//iam.googleapis.com/projects/acme-prod/serviceAccounts/1/keys/k1","activity":{"lastAuthenticatedTime":"2026-11-01T00:00:00Z"}}]}`)
	case host == storageHost && r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b":
		if r.URL.Query().Get("project") != "acme-prod" {
			f.t.Errorf("bucket list without project")
		}
		_, _ = io.WriteString(w, `{"items":[{"name":"site","iamConfiguration":{"uniformBucketLevelAccess":{"enabled":true}}},
			{"name":"logs","iamConfiguration":{"publicAccessPrevention":"enforced"}}]}`)
	case host == storageHost && r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b/site/iam":
		_, _ = io.WriteString(w, `{"bindings":[{"role":"roles/storage.objectViewer","members":["allUsers","projectViewer:acme-prod"]}]}`)
	case host == storageHost && r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b/logs/iam":
		_, _ = io.WriteString(w, `{"bindings":[{"role":"roles/storage.objectViewer","members":["projectViewer:acme-prod"]}]}`)
	default:
		f.t.Errorf("unexpected call %s %s%s", r.Method, host, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func collect(t *testing.T, f *fake, s connector.Scope) *graph.Graph {
	t.Helper()
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := newConn(srv)
	g := graph.New()
	if err := c.Collect(context.Background(), c.Collections()[0], s, g); err != nil {
		t.Fatal(err)
	}
	return g
}

func TestCollectReadsBindingsKeysAndBuckets(t *testing.T) {
	f := &fake{t: t}
	s := scope("acme-prod")
	g := collect(t, f, s)

	proj, ok := g.Get("gcp:project/acme-prod")
	if !ok || proj.Attrs["number"] != "123" {
		t.Fatalf("project: %+v", proj)
	}
	if d := proj.Attrs["member_domains"].([]any); len(d) != 1 || d[0] != "acme.com" {
		t.Fatalf("member domains default to google.domain, lowercased: %v", d)
	}
	byMember := map[string]graph.Node{}
	for _, n := range g.Nodes(graph.KindGCPBinding) {
		key := n.Attrs["role"].(string) + " " + n.Attrs["member_type"].(string) + " " + n.Attrs["member_domain"].(string)
		byMember[key] = n
		if n.Attrs["member_type"] == "user" && n.Attrs["member"] != "" {
			t.Fatalf("a user's address must not be a public attribute: %+v", n.Attrs)
		}
	}
	if n, ok := byMember["roles/owner user acme.com"]; !ok || n.Private["email"] != "ravi@acme.com" {
		t.Fatalf("own owner, email private and lowercased: %+v", byMember)
	}
	if _, ok := byMember["roles/owner user gmail.com"]; !ok {
		t.Fatal("outside owner missing")
	}
	if _, ok := byMember["roles/editor deleted_user contractor.io"]; !ok {
		t.Fatal("deleted outside editor missing")
	}
	if n := byMember["roles/editor service_account developer.gserviceaccount.com"]; n.Attrs["default_account"] != true || n.Attrs["google_managed"] != false {
		t.Fatalf("default compute account: %+v", n.Attrs)
	}
	if n := byMember["roles/editor service_account cloudservices.gserviceaccount.com"]; n.Attrs["google_managed"] != true {
		t.Fatalf("Google APIs service agent: %+v", n.Attrs)
	}
	if n := byMember["roles/viewer allUsers "]; n.Attrs["conditional"] != true {
		t.Fatalf("conditional binding: %+v", n.Attrs)
	}

	k, ok := g.Get("gcp:key/acme-prod/k1")
	if !ok || k.Attrs["created"] != "2025-01-02T03:04:05Z" || k.Attrs["last_used"] != "2026-11-01T00:00:00Z" || k.Attrs["last_use_known"] != true {
		t.Fatalf("key: %+v", k)
	}
	site, _ := g.Get("gcp:bucket/site")
	if p := site.Attrs["public_grants"].([]any); len(p) != 1 || p[0] != "allUsers roles/storage.objectViewer" || site.Attrs["public_access_prevention"] != "inherited" {
		t.Fatalf("site bucket: %+v", site.Attrs)
	}
	logs, _ := g.Get("gcp:bucket/logs")
	if len(logs.Attrs["public_grants"].([]any)) != 0 || logs.Attrs["public_access_prevention"] != "enforced" {
		t.Fatalf("logs bucket: %+v", logs.Attrs)
	}
	for _, c := range s.Log.Calls() {
		if c.Blocked {
			t.Fatalf("blocked: %+v", c)
		}
		if c.Method != http.MethodGet && c.Endpoint != tokenURL && c.Endpoint != getIamPolicyURL("acme-prod") {
			t.Fatalf("only GET, the token exchange and getIamPolicy may be called: %+v", c)
		}
	}
}

func TestNoPolicyAnalyzerLeavesLastUseUnknown(t *testing.T) {
	f := &fake{t: t, analyzerCode: http.StatusForbidden}
	g := collect(t, f, scope("acme-prod"))
	k, ok := g.Get("gcp:key/acme-prod/k1")
	if !ok || k.Attrs["last_use_known"] != false || k.Attrs["last_used"] != "" {
		t.Fatalf("key: %+v", k)
	}
	proj, _ := g.Get("gcp:project/acme-prod")
	if p := proj.Attrs["partial"].([]any); len(p) != 1 {
		t.Fatalf("partial read recorded: %v", proj.Attrs["partial"])
	}
}

func TestGuardRefusesWritesAndUnlistedProjects(t *testing.T) {
	p := Policy([]string{"acme-prod"})
	log := &connector.CallLog{}
	tr := &connector.Transport{Policy: p, Log: log, Connector: "gcp", Next: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})}
	try := func(method, u string) error {
		req, _ := http.NewRequest(method, u, nil)
		resp, err := tr.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	allowed := [][2]string{
		{http.MethodPost, "https://cloudresourcemanager.googleapis.com/v3/projects/acme-prod:getIamPolicy"},
		{http.MethodGet, "https://iam.googleapis.com/v1/projects/acme-prod/serviceAccounts"},
		{http.MethodPost, "https://oauth2.googleapis.com/token"},
	}
	for _, a := range allowed {
		if err := try(a[0], a[1]); err != nil {
			t.Errorf("%s %s should pass: %v", a[0], a[1], err)
		}
	}
	refused := [][2]string{
		{http.MethodPost, "https://cloudresourcemanager.googleapis.com/v3/projects/other:getIamPolicy"},
		{http.MethodPost, "https://cloudresourcemanager.googleapis.com/v3/projects/acme-prod:setIamPolicy"},
		{http.MethodDelete, "https://iam.googleapis.com/v1/projects/acme-prod/serviceAccounts/x/keys/k1"},
		{http.MethodPost, "https://iam.googleapis.com/v1/projects/acme-prod/serviceAccounts/x/keys"},
		{http.MethodPut, "https://storage.googleapis.com/storage/v1/b/site/iam"},
		{http.MethodGet, "https://secretmanager.googleapis.com/v1/projects/acme-prod/secrets"},
	}
	for _, r := range refused {
		if err := try(r[0], r[1]); !errors.Is(err, connector.ErrBlocked) {
			t.Errorf("%s %s should be blocked, got %v", r[0], r[1], err)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAvailableNeedsProjectsAndCredentials(t *testing.T) {
	c := New()
	c.ReadFile = func(string) ([]byte, error) { return []byte(userCreds), nil }
	if ok, _ := c.Available(scope()); ok {
		t.Fatal("no projects listed")
	}
	if ok, why := c.Available(scope("acme-prod")); !ok {
		t.Fatalf("listed and credentials present: %s", why)
	}
	c.ReadFile = func(string) ([]byte, error) { return nil, errors.New("missing") }
	if ok, _ := c.Available(scope("acme-prod")); ok {
		t.Fatal("missing credentials file")
	}
}

func TestCredentialsPathDefaultsToGcloud(t *testing.T) {
	s := scope("p")
	s.Getenv = func(k string) string {
		if k == "CLOUDSDK_CONFIG" {
			return "/cfg"
		}
		return ""
	}
	if got := credentialsPath(s); got != "/cfg/application_default_credentials.json" {
		t.Fatal(got)
	}
}

func TestParseMember(t *testing.T) {
	cases := map[string]member{
		"user:A@Acme.com":    {kind: "user", domain: "acme.com", email: "a@acme.com"},
		"group:eng@acme.com": {kind: "group", domain: "acme.com", email: "eng@acme.com"},
		"domain:acme.com":    {kind: "domain", domain: "acme.com", public: "acme.com"},
		"serviceAccount:ci@p.iam.gserviceaccount.com":  {kind: "service_account", domain: "p.iam.gserviceaccount.com", public: "ci@p.iam.gserviceaccount.com"},
		"serviceAccount:p@appspot.gserviceaccount.com": {kind: "service_account", domain: "appspot.gserviceaccount.com", public: "p@appspot.gserviceaccount.com", defaultAccount: true},
		"serviceAccount:service-1@gcp-sa-pubsub.iam.gserviceaccount.com": {kind: "service_account", domain: "gcp-sa-pubsub.iam.gserviceaccount.com",
			public: "service-1@gcp-sa-pubsub.iam.gserviceaccount.com", googleManaged: true},
		"allUsers": {kind: "allUsers", public: "allUsers"},
		"deleted:serviceAccount:x@p.iam.gserviceaccount.com?uid=1": {kind: "deleted_service_account", domain: "p.iam.gserviceaccount.com", public: "x@p.iam.gserviceaccount.com"},
	}
	for in, want := range cases {
		if got := parseMember(in, "p"); got != want {
			t.Errorf("%s: got %+v, want %+v", in, got, want)
		}
	}
}
