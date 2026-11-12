package gcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

func TestPredefinedPower(t *testing.T) {
	for role, want := range map[string]Power{
		"roles/owner":                           {Admin: true, Destructive: true, Known: true},
		"roles/editor":                          {Admin: true, Destructive: true, Known: true},
		"roles/viewer":                          {Known: true},
		"roles/storage.admin":                   {Admin: true, Destructive: true, Known: true},
		"roles/storage.objectAdmin":             {Admin: true, Destructive: true, Known: true},
		"roles/storage.objectViewer":            {Known: true},
		"roles/cloudsql.admin":                  {Admin: true, Destructive: true, Known: true},
		"roles/cloudsql.editor":                 {Known: true},
		"roles/bigquery.dataEditor":             {Destructive: true, Known: true},
		"roles/iam.securityAdmin":               {Admin: true, Known: true},
		"roles/iam.serviceAccountTokenCreator":  {Admin: true, Known: true},
		"roles/resourcemanager.projectIamAdmin": {Admin: true, Known: true},
		"roles/compute.instanceAdmin.v1":        {Admin: true, Destructive: true, Known: true},
		"roles/newservice.admin":                {Admin: true, Known: true},
		"roles/backupdr.admin":                  {Admin: true, Destructive: true, Known: true},
	} {
		if got := PredefinedPower(role); got != want {
			t.Errorf("%s: got %+v, want %+v", role, got, want)
		}
	}
	if p := PermissionsPower([]string{"storage.objects.get", "storage.objects.delete"}); p.Admin || !p.Destructive {
		t.Fatalf("%+v", p)
	}
	if p := PermissionsPower([]string{"resourcemanager.projects.setIamPolicy"}); !p.Admin || p.Destructive {
		t.Fatalf("%+v", p)
	}
	if p := PermissionsPower([]string{"iam.serviceAccounts.getAccessToken"}); !p.Admin {
		t.Fatalf("%+v", p)
	}
}

// roleFake serves one project whose policy names two custom roles: one
// readable, one the reader may not read.
type roleFake struct {
	t     *testing.T
	calls []string
}

func (f *roleFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Original-Host")
	f.calls = append(f.calls, r.Method+" "+host+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case host == "oauth2.googleapis.com":
		_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
	case host == crmHost && r.Method == http.MethodPost:
		_, _ = io.WriteString(w, `{"bindings":[
			{"role":"projects/acme-prod/roles/deployer","members":["user:cy@acme.com","serviceAccount:ci@acme-prod.iam.gserviceaccount.com"]},
			{"role":"organizations/42/roles/auditor","members":["user:cy@acme.com"]},
			{"role":"roles/storage.objectAdmin","members":["user:cy@acme.com"]}]}`)
	case host == iamHost && r.URL.Path == "/v1/projects/acme-prod/roles/deployer":
		if r.Method != http.MethodGet {
			f.t.Errorf("roles.get must be GET")
		}
		_, _ = io.WriteString(w, `{"name":"projects/acme-prod/roles/deployer","includedPermissions":["run.services.update","storage.objects.delete"]}`)
	case host == iamHost && r.URL.Path == "/v1/organizations/42/roles/auditor":
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"code":403,"message":"Permission iam.roles.get denied","status":"PERMISSION_DENIED"}}`)
	case host == iamHost && strings.HasSuffix(r.URL.Path, "/serviceAccounts"):
		_, _ = io.WriteString(w, `{}`)
	case host == analyzerHost, host == storageHost:
		_, _ = io.WriteString(w, `{}`)
	default:
		f.t.Errorf("unexpected call %s %s%s", r.Method, host, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func TestBindingsCarryPowerAndProduction(t *testing.T) {
	f := &roleFake{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := newConn(srv)
	s := scope("acme-prod")
	s.Project.Config.Production = []string{"acme-prod", "111122223333"}
	g := graph.New()
	if err := c.Collect(context.Background(), c.Collections()[0], s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	got := map[string]map[string]any{}
	for _, n := range g.Nodes(graph.KindGCPBinding) {
		got[n.Attrs["role"].(string)+" "+n.Attrs["member_type"].(string)] = n.Attrs
	}
	check := func(key string, admin, destructive, known bool) {
		t.Helper()
		a := got[key]
		if a == nil || a["is_admin"] != admin || a["destructive"] != destructive || a["power_known"] != known || a["production"] != true {
			t.Fatalf("%s: %+v", key, a)
		}
	}
	check("projects/acme-prod/roles/deployer user", false, true, true)
	check("projects/acme-prod/roles/deployer service_account", false, true, true)
	check("organizations/42/roles/auditor user", false, false, false)
	check("roles/storage.objectAdmin user", true, true, true)
	gets := 0
	for _, call := range f.calls {
		if strings.Contains(call, "/roles/deployer") {
			gets++
		}
	}
	if gets != 1 {
		t.Fatalf("a custom role is read once per run: %v", f.calls)
	}
	proj, _ := g.Get("gcp:project/acme-prod")
	if proj.Attrs["production"] != true {
		t.Fatalf("%+v", proj.Attrs)
	}
	partial := proj.Attrs["partial"].([]any)
	if len(partial) != 1 || !strings.Contains(partial[0].(string), "organizations/42/roles/auditor") {
		t.Fatalf("an unreadable custom role makes the project partial: %+v", partial)
	}
}

func TestRolesGetIsGetOnly(t *testing.T) {
	tr := &connector.Transport{Policy: Policy([]string{"acme-prod"}, ""), Log: &connector.CallLog{}, Connector: "gcp"}
	for _, m := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
		req, _ := http.NewRequest(m, "https://iam.googleapis.com/v1/projects/acme-prod/roles/deployer", nil)
		if _, err := tr.RoundTrip(req); !errors.Is(err, connector.ErrBlocked) {
			t.Fatalf("%s on a role must be refused: %v", m, err)
		}
	}
}
