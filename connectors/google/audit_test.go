package google

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
)

func reportsQuery() connector.AuditQuery {
	return connector.AuditQuery{Source: connector.AuditGoogle, Application: "admin", Event: "GRANT_ADMIN_PRIVILEGE",
		From: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)}
}

func TestReportsAuditThroughTheGuard(t *testing.T) {
	var asked []string
	code := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Header.Get("X-Original-Host") {
		case "oauth2.googleapis.com":
			_, _ = io.WriteString(w, `{"access_token":"t","token_type":"Bearer","expires_in":3600}`)
		case "admin.googleapis.com":
			asked = append(asked, r.Method+" "+r.URL.RequestURI())
			w.WriteHeader(code)
			_, _ = io.WriteString(w, `{"kind":"reports#activities","items":[
{"id":{"time":"2026-11-05T10:00:00.000Z","applicationName":"admin"},"actor":{"email":"Ana@acme.com","callerType":"USER"},
 "events":[{"type":"USER_SETTINGS","name":"GRANT_ADMIN_PRIVILEGE","parameters":[{"name":"USER_EMAIL","value":"bo@acme.com"}]}]},
{"id":{"time":"2026-11-06T10:00:00.000Z"},"actor":{"callerType":"KEY","key":"SYSTEM"},
 "events":[{"name":"GRANT_ADMIN_PRIVILEGE","parameters":[{"name":"USER_EMAIL","value":"cy@acme.com"}]}]}]}`)
		default:
			t.Errorf("unexpected host %s", r.Header.Get("X-Original-Host"))
		}
	}))
	defer srv.Close()
	c := New()
	c.Next = rewrite{srv}
	s := scope(t, keyFile(t))
	if _, err := c.Audit(context.Background(), s, reportsQuery()); !errors.Is(err, connector.ErrAuditUnreadable) || len(asked) != 0 || len(s.Log.Calls()) != 0 {
		t.Fatalf("nothing leaves before connect: %v", err)
	}
	s.Project.Config.Connected = []string{"google"}
	ans, err := c.Audit(context.Background(), s, reportsQuery())
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Events) != 2 || ans.Events[0].Actor != "ana@acme.com" || ans.Events[0].Params["USER_EMAIL"][0] != "bo@acme.com" ||
		ans.Events[1].ActorKind != "key" || ans.Events[1].Actor != "" {
		t.Fatalf("%+v", ans)
	}
	if len(asked) != 1 || !strings.HasPrefix(asked[0], "GET /admin/reports/v1/activity/users/all/applications/admin?") ||
		!strings.Contains(asked[0], "eventName=GRANT_ADMIN_PRIVILEGE") || !strings.Contains(asked[0], "startTime=2026-11-02T09%3A00%3A00Z") ||
		!strings.Contains(asked[0], "endTime=2026-11-09T09%3A00%3A00Z") || strings.Contains(asked[0], "%40") {
		t.Fatalf("one GET for the window, with no address in the URL: %v", asked)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	code = http.StatusForbidden
	if _, err := c.Audit(context.Background(), s, reportsQuery()); !errors.Is(err, connector.ErrAuditUnreadable) || !strings.Contains(err.Error(), ReportsScope) {
		t.Fatal(err)
	}
}
