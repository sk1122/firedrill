package connectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/connectors/anthropic"
	"github.com/sk1122/firedrill/connectors/aws"
	"github.com/sk1122/firedrill/connectors/configsrc"
	"github.com/sk1122/firedrill/connectors/files"
	"github.com/sk1122/firedrill/connectors/gcp"
	"github.com/sk1122/firedrill/connectors/github"
	"github.com/sk1122/firedrill/connectors/google"
	"github.com/sk1122/firedrill/connectors/openai"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/packs"
)

// counter stands in for the network: it counts every request that would have
// left the machine and answers each with an error status.
type counter struct {
	mu    sync.Mutex
	n     map[string]int
	paths []string
}

func (c *counter) for_(name string) http.RoundTripper {
	return rtFunc(func(r *http.Request) (*http.Response, error) {
		c.mu.Lock()
		c.n[name]++
		c.paths = append(c.paths, r.URL.Path)
		c.mu.Unlock()
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}, Request: r}, nil
	})
}

func (c *counter) get(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[name]
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func allStarterDrills(t *testing.T) []*drill.Drill {
	t.Helper()
	var out []*drill.Drill
	err := fs.WalkDir(packs.FS, ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || !strings.HasSuffix(p, ".drill.yaml") {
			return err
		}
		out = append(out, drillOf(t, strings.TrimSuffix(p, ".drill.yaml")))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Ambient admin keys, built by concatenation, present in the environment of
// every consent run.
var (
	ambientAnthropic = "sk-ant-admin01-" + "ambient" + "-0000"
	ambientOpenAI    = "sk-admin-" + "ambient" + "-0000"
)

// consentRun runs every starter drill with every network connector configured
// and ambient credentials present: a GitHub token, an AWS profile, Google
// Cloud and Workspace credential files, and Anthropic and OpenAI admin keys.
// Only the connected list differs.
func consentRun(t *testing.T, dir string) (*counter, *connector.CallLog, *run.Result) {
	t.Helper()
	net := &counter{n: map[string]int{}}
	awsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		net.mu.Lock()
		net.n["aws"]++
		net.mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(awsSrv.Close)

	gh := github.New()
	gh.Next, gh.Limit, gh.Burst = net.for_("github"), 10000, 10000
	a := aws.New()
	a.ReportWait = 0
	a.Load = func(context.Context, string) (awssdk.Config, error) {
		return awssdk.Config{Region: "us-east-1", BaseEndpoint: awssdk.String(awsSrv.URL), RetryMaxAttempts: 1,
			Credentials: credentials.NewStaticCredentialsProvider("ambient", "ambient", "")}, nil
	}
	gc := gcp.New()
	gc.Next, gc.Limit, gc.Burst = net.for_("gcp"), 10000, 10000
	gc.ReadFile = func(string) ([]byte, error) {
		return []byte(`{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"}`), nil
	}
	gw := google.New()
	gw.Next, gw.Limit, gw.Burst = net.for_("google"), 10000, 10000
	an := anthropic.New()
	an.Next, an.Limit, an.Burst = net.for_("anthropic"), 10000, 10000
	oa := openai.New()
	oa.Next, oa.Limit, oa.Burst = net.for_("openai"), 10000, 10000

	p, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(key, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	log := &connector.CallLog{}
	scope := connector.Scope{
		Project: p, Now: now, Log: log, Hasher: graph.NewHasher("s"), Token: "ambient-gh-token",
		Getenv: func(k string) string {
			switch k {
			case gcp.CredentialsEnv:
				return "/acme/gcp.json"
			case google.CredentialsEnv:
				return key
			case anthropic.KeyEnv:
				return ambientAnthropic
			case openai.KeyEnv:
				return ambientOpenAI
			}
			return ""
		},
	}
	// prepare in cmd/firedrill hands the files connector a tarball reader only
	// once GitHub is connected; its own test covers that.
	if p.Config.IsConnected("github") {
		scope.Tarball = gh.Tarball(scope)
	}
	records := t.TempDir()
	res, err := run.Run(context.Background(), run.Config{
		Project: p, Drills: allStarterDrills(t), Stream: "local", Records: records, WriteRecords: true, Scope: scope,
		Connectors: []connector.Connector{configsrc.New(), files.New(), gh, a, gc, gw, an, oa},
	})
	if err != nil {
		t.Fatal(err)
	}
	// No credential reaches a record or the call log, connected or not.
	_ = filepath.WalkDir(records, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, secret := range []string{ambientAnthropic, ambientOpenAI, "ambient-gh-token"} {
			if strings.Contains(string(b), secret) {
				t.Errorf("%s holds an ambient credential", p)
			}
		}
		return nil
	})
	lb, _ := json.Marshal(log.Calls())
	if strings.Contains(string(lb), ambientAnthropic) || strings.Contains(string(lb), ambientOpenAI) {
		t.Error("an ambient credential reached the call log")
	}
	return net, log, res
}

const consentConfig = `github: {org: acme, repos: [api]}
aws: {accounts: [{profile: acme-prod}]}
gcp: {projects: [acme-prod]}
google: {domain: acme.com, admin_email: admin@acme.com}
`

func TestAmbientCredentialsAreNotConsent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(consentConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	systems := []string{"github", "aws", "gcp", "google", "anthropic", "openai"}

	net, log, res := consentRun(t, dir)
	for _, s := range systems {
		if res.Available[s] {
			t.Errorf("%s is available although it was never connected", s)
		}
		if n := net.get(s); n != 0 {
			t.Errorf("%s: %d requests left before connect", s, n)
		}
	}
	if calls := log.Calls(); len(calls) != 0 {
		t.Fatalf("no call may be logged before connect: %+v", calls)
	}
	// GitHub people are part of the github connector: no members, teams or
	// collaborators read leaves before connect github either.
	for _, p := range net.paths {
		if strings.Contains(p, "/members") || strings.Contains(p, "/teams") || strings.Contains(p, "/collaborators") || strings.Contains(p, "/outside_collaborators") {
			t.Errorf("a people call left before connect: %s", p)
		}
		// Nor Google groups, read for linking, or GCP custom roles.
		if strings.Contains(p, "/groups") || strings.Contains(p, "/roles/") {
			t.Errorf("a linking call left before connect: %s", p)
		}
		// Nor Cloud SQL operations, read for restores, or the Service Usage
		// read of whether the Cloud SQL Admin API is on.
		if strings.Contains(p, "/operations") || strings.Contains(p, "/services/sqladmin.googleapis.com") {
			t.Errorf("a Cloud SQL read left before connect: %s", p)
		}
		// Nor any audit read: GitHub's audit log, Google's Reports API or
		// Cloud Logging's entries.list.
		if strings.Contains(p, "/audit-log") || strings.Contains(p, "/admin/reports/") || strings.Contains(p, "entries:list") {
			t.Errorf("an audit read left before connect: %s", p)
		}
	}

	// What connect records after a successful access check.
	for _, s := range systems {
		if err := config.MarkConnected(dir, s); err != nil {
			t.Fatal(err)
		}
	}
	net, log, res = consentRun(t, dir)
	for _, s := range systems {
		if !res.Available[s] {
			t.Errorf("%s is not available after connect", s)
		}
	}
	logged := map[string]int{}
	for _, c := range log.Calls() {
		logged[c.Connector]++
	}
	for _, s := range []string{"github", "aws", "gcp", "anthropic", "openai"} {
		if net.get(s) == 0 || logged[s] == 0 {
			t.Errorf("%s: no calls after connect (sent %d, logged %d)", s, net.get(s), logged[s])
		}
	}
}

// No audit source answers before its system is connected on purpose, with
// ambient credentials present: each refuses without a request.
func TestAuditSourcesNeedConsent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(consentConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := config.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	net := &counter{n: map[string]int{}}
	gh := github.New()
	gh.Next = net.for_("github")
	gc := gcp.New()
	gc.Next = net.for_("gcp")
	gc.ReadFile = func(string) ([]byte, error) {
		return []byte(`{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"}`), nil
	}
	gw := google.New()
	gw.Next = net.for_("google")
	key := filepath.Join(t.TempDir(), "key.json")
	_ = os.WriteFile(key, []byte(`{}`), 0o600)
	log := &connector.CallLog{}
	s := connector.Scope{Project: p, Now: now, Log: log, Hasher: graph.NewHasher("s"), Token: "ambient-gh-token",
		Getenv: func(k string) string {
			switch k {
			case gcp.CredentialsEnv:
				return "/acme/gcp.json"
			case google.CredentialsEnv:
				return key
			}
			return ""
		}}
	q := connector.AuditQuery{Org: "acme", Repo: "acme/api", Action: "repository_ruleset", Application: "admin", Event: "GRANT_ADMIN_PRIVILEGE",
		Project: "acme-prod", Method: "SetIamPolicy", From: now.AddDate(0, 0, -7), To: now}
	for _, a := range []connector.Auditor{gh, gc, gw} {
		if a.AuditReady(s) {
			t.Errorf("%s is ready before connect", a.Name())
		}
		if _, err := a.Audit(context.Background(), s, q); !errors.Is(err, connector.ErrAuditUnreadable) {
			t.Errorf("%s: %v", a.Name(), err)
		}
	}
	for _, name := range []string{"github", "gcp", "google"} {
		if net.get(name) != 0 {
			t.Errorf("%s: a request left before connect", name)
		}
	}
	if len(log.Calls()) != 0 {
		t.Fatalf("%+v", log.Calls())
	}
}
