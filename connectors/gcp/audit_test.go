package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
)

func logQuery(project string) connector.AuditQuery {
	return connector.AuditQuery{Source: connector.AuditGCP, Project: project, Method: "SetIamPolicy",
		From: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)}
}

func TestAuditLogEntriesListThroughTheGuard(t *testing.T) {
	var body map[string]any
	var asked []string
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Original-Host")
		asked = append(asked, r.Method+" "+host+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case host == "oauth2.googleapis.com":
			_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case host == "logging.googleapis.com" && r.Method == http.MethodPost && r.URL.Path == "/v2/entries:list":
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			w.WriteHeader(code)
			if code != http.StatusOK {
				_, _ = io.WriteString(w, `{"error":{"code":403,"status":"PERMISSION_DENIED","message":"no logging.logEntries.list"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"entries":[{"timestamp":"2026-11-05T10:00:00.123Z","logName":"projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity",
"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","methodName":"SetIamPolicy","authenticationInfo":{"principalEmail":"Ana@acme.com"},
"serviceData":{"policyDelta":{"bindingDeltas":[{"action":"ADD","role":"roles/owner","member":"user:bo@acme.com"},{"action":"REMOVE","role":"roles/viewer","member":"user:x@acme.com"}]}}}},
{"timestamp":"2026-11-06T10:00:00Z","protoPayload":{"methodName":"SetIamPolicy","authenticationInfo":{"principalEmail":"deployer@acme-prod.iam.gserviceaccount.com"}}}]}`)
		default:
			t.Errorf("unexpected %s %s%s", r.Method, host, r.URL.Path)
		}
	}))
	defer srv.Close()
	c := newConn(srv)
	s := scope("acme-prod")
	if _, err := c.Audit(context.Background(), s, logQuery("acme-prod")); !errors.Is(err, connector.ErrAuditUnreadable) || len(asked) != 0 {
		t.Fatalf("nothing leaves before connect: %v %v", err, asked)
	}
	s.Project.Config.Connected = []string{"gcp"}
	if _, err := c.Audit(context.Background(), s, logQuery("other")); !errors.Is(err, connector.ErrAuditUnreadable) || len(asked) != 0 {
		t.Fatal("only a configured project is asked about")
	}
	ans, err := c.Audit(context.Background(), s, logQuery("acme-prod"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Events) != 2 || ans.Events[0].Actor != "ana@acme.com" || ans.Events[0].ActorKind != "user" || ans.Events[1].ActorKind != "service_account" ||
		len(ans.Events[0].Params["binding_added"]) != 1 || ans.Events[0].Params["binding_added"][0] != "roles/owner|user:bo@acme.com" {
		t.Fatalf("%+v", ans)
	}
	want := `logName="projects/acme-prod/logs/cloudaudit.googleapis.com%2Factivity" AND protoPayload.methodName:"SetIamPolicy" AND timestamp>="2026-11-02T09:00:00Z" AND timestamp<="2026-11-09T09:00:00Z"`
	if body["filter"] != want || body["resourceNames"].([]any)[0] != "projects/acme-prod" || body["pageSize"] != float64(100) {
		t.Fatalf("%v", body)
	}
	for _, call := range s.Log.Calls() {
		if call.Method == http.MethodPost && call.Endpoint != tokenURL && call.Endpoint != entriesListURL {
			t.Fatalf("%+v", call)
		}
	}
	code = http.StatusForbidden
	if _, err := c.Audit(context.Background(), s, logQuery("acme-prod")); !errors.Is(err, connector.ErrAuditUnreadable) || !strings.Contains(err.Error(), "logging.logEntries.list") {
		t.Fatal(err)
	}
}

func TestGuardAllowsOnlyTheReadOnlyLoggingPost(t *testing.T) {
	tr := &connector.Transport{Policy: Policy([]string{"acme-prod"}, ""), Log: &connector.CallLog{}, Connector: "gcp",
		Next: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
		})}
	try := func(method, u string) error {
		req, _ := http.NewRequest(method, u, nil)
		resp, err := tr.RoundTrip(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	if err := try(http.MethodPost, "https://logging.googleapis.com/v2/entries:list"); err != nil {
		t.Fatal(err)
	}
	for _, r := range [][2]string{
		{http.MethodPost, "https://logging.googleapis.com/v2/entries:write"},
		{http.MethodPost, "https://logging.googleapis.com/v2/entries:tail"},
		{http.MethodPost, "https://logging.googleapis.com/v2/entries:copy"},
		{http.MethodGet, "https://logging.googleapis.com/v2/projects/acme-prod/logs"},
		{http.MethodDelete, "https://logging.googleapis.com/v2/projects/acme-prod/logs/x"},
	} {
		if err := try(r[0], r[1]); !errors.Is(err, connector.ErrBlocked) {
			t.Errorf("%s %s should be blocked, got %v", r[0], r[1], err)
		}
	}
}
