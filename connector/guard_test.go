package connector

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestWriteMethodsAreBlocked(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	log := &CallLog{}
	c := Client("github", Policy{Hosts: map[string]bool{u.Host: true}}, log, nil)
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req, _ := http.NewRequest(m, srv.URL+"/repos/a/b", strings.NewReader("x"))
		_, err := c.Do(req)
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: want blocked, got %v", m, err)
		}
	}
	if hit {
		t.Fatal("a blocked call reached the server")
	}
	if len(log.Violations()) != 4 {
		t.Fatalf("violations: %v", log.Violations())
	}
	resp, err := c.Get(srv.URL + "/ok?token=abc")
	if err != nil || !hit {
		t.Fatalf("GET must pass: %v", err)
	}
	_ = resp.Body.Close()
	calls := log.Calls()
	if last := calls[len(calls)-1]; strings.Contains(last.Endpoint, "abc") {
		t.Fatal("the call log must drop the query string")
	}
}

func TestUnlistedHostIsBlockedIncludingRedirects(t *testing.T) {
	bad := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("reached an unlisted host") }))
	defer bad.Close()
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, bad.URL+"/steal", http.StatusFound)
	}))
	defer good.Close()
	u, _ := url.Parse(good.URL)
	log := &CallLog{}
	c := Client("web", Policy{Hosts: map[string]bool{u.Host: true}}, log, nil)
	if _, err := c.Get(good.URL); !errors.Is(err, ErrBlocked) {
		t.Fatalf("a redirect to an unlisted host must be blocked, got %v", err)
	}
	if _, err := c.Get(bad.URL); !errors.Is(err, ErrBlocked) {
		t.Fatalf("got %v", err)
	}
}

func TestGooglePostAllowedOnlyForTokenExchange(t *testing.T) {
	tr := &Transport{Policy: GooglePolicy(), Log: &CallLog{}, Connector: "google"}
	if err := tr.check("POST", "oauth2.googleapis.com", "oauth2.googleapis.com", "https://oauth2.googleapis.com/token"); err != nil {
		t.Fatal(err)
	}
	if err := tr.check("POST", "admin.googleapis.com", "admin.googleapis.com", "https://admin.googleapis.com/admin/directory/v1/users"); !errors.Is(err, ErrBlocked) {
		t.Fatal("a POST to the Admin SDK must be blocked")
	}
	if err := tr.check("POST", "oauth2.googleapis.com", "oauth2.googleapis.com", "https://oauth2.googleapis.com/revoke"); !errors.Is(err, ErrBlocked) {
		t.Fatal("another path on the token host must be blocked")
	}
}

func TestGitHubPolicyAllowsTarballRedirectHost(t *testing.T) {
	tr := &Transport{Policy: GitHubPolicy(), Log: &CallLog{}, Connector: "github"}
	if err := tr.check("GET", "codeload.github.com", "codeload.github.com", "https://codeload.github.com/a/b"); err != nil {
		t.Fatal(err)
	}
	if err := tr.check("GET", "evil.com", "evil.com", "https://evil.com/"); !errors.Is(err, ErrBlocked) {
		t.Fatal("other hosts must be blocked")
	}
}

func TestAWSActionList(t *testing.T) {
	log := &CallLog{}
	for a := range AWSActions {
		if err := CheckAWS(log, a); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []string{"secretsmanager:GetSecretValue", "s3:GetObject", "iam:DeleteUser", "iam:CreateAccessKey"} {
		if err := CheckAWS(log, a); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s must be refused", a)
		}
	}
	if len(log.Violations()) != 4 {
		t.Fatal(log.Violations())
	}
}

func TestUnderDomain(t *testing.T) {
	if !UnderDomain("a.acme.com", "acme.com") || !UnderDomain("ACME.com", "acme.com") {
		t.Fatal("subdomains and the domain itself match")
	}
	if UnderDomain("evilacme.com", "acme.com") || UnderDomain("acme.com.evil.io", "acme.com") {
		t.Fatal("lookalikes must not match")
	}
}

func TestPathLimitedPolicies(t *testing.T) {
	cases := []struct {
		name     string
		policy   Policy
		host     string
		allowed  []string
		refused  []string
		refusedM [][2]string // method, path
	}{
		{"anthropic", AnthropicPolicy(), "api.anthropic.com",
			[]string{"/v1/organizations/api_keys", "/v1/organizations/workspaces"},
			[]string{"/v1/messages", "/v1/organizations/users", "/v1/organizations/api_keys/apikey_01AcmeExample", "/v1/organizations/api_keys/x/../../messages", "/"},
			[][2]string{{"POST", "/v1/organizations/api_keys/apikey_01AcmeExample"}, {"POST", "/v1/messages"}, {"DELETE", "/v1/organizations/workspaces"}}},
		{"openai", OpenAIPolicy(), "api.openai.com",
			[]string{"/v1/organization/projects", "/v1/organization/projects/proj_acme/api_keys", "/v1/organization/projects/proj_acme/spend_limit", "/v1/organization/spend_limit"},
			[]string{"/v1/chat/completions", "/v1/organization/admin_api_keys", "/v1/organization/projects/proj_acme/service_accounts", "/v1/organization/projects/a/b/api_keys", "/v1/models"},
			[][2]string{{"POST", "/v1/organization/admin_api_keys"}, {"POST", "/v1/organization/projects/proj_acme/spend_limit"}, {"DELETE", "/v1/organization/projects/proj_acme/api_keys/key_acme"}}},
	}
	for _, c := range cases {
		tr := &Transport{Policy: c.policy, Log: &CallLog{}, Connector: c.name}
		for _, p := range c.allowed {
			if err := tr.check("GET", c.host, c.host, "https://"+c.host+p); err != nil {
				t.Errorf("%s GET %s: %v", c.name, p, err)
			}
		}
		for _, p := range c.refused {
			if err := tr.check("GET", c.host, c.host, "https://"+c.host+p); !errors.Is(err, ErrBlocked) {
				t.Errorf("%s GET %s must be refused", c.name, p)
			}
		}
		for _, mp := range c.refusedM {
			if err := tr.check(mp[0], c.host, c.host, "https://"+c.host+mp[1]); !errors.Is(err, ErrBlocked) {
				t.Errorf("%s %s %s must be refused", c.name, mp[0], mp[1])
			}
		}
		if err := tr.check("GET", "evil.example", "evil.example", "https://evil.example/v1/organization/projects"); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: another host must be refused", c.name)
		}
	}
}

func TestAWSWritesOnNewServicesAreRefused(t *testing.T) {
	log := &CallLog{}
	for _, a := range []string{"rds:DeleteDBInstance", "rds:ModifyDBInstance", "rds:DeleteDBClusterSnapshot", "rds:CopyDBSnapshot",
		"backup:DeleteRecoveryPoint", "backup:StartCopyJob", "backup:DeleteBackupVault", "backup:GetBackupVaultAccessPolicy"} {
		if err := CheckAWS(log, a); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s must be refused", a)
		}
	}
	for svc, prefix := range AWSServicePrefix {
		found := false
		for a := range AWSActions {
			if strings.HasPrefix(a, prefix+":") {
				found = true
			}
		}
		if !found {
			t.Errorf("service %s maps to %s, which has no allowed action", svc, prefix)
		}
	}
}
