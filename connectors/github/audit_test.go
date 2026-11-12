package github

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
)

func auditQuery() connector.AuditQuery {
	return connector.AuditQuery{Source: connector.AuditGitHub, Org: "acme", Repo: "acme/api", Action: "repository_ruleset",
		From: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC), To: time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)}
}

func TestAuditReadsTheWindowThroughTheGuard(t *testing.T) {
	lg := &reqLog{}
	c := fakeGitHub(t, routes{logKey: lg, "/orgs/acme/audit-log": []any{
		obj{"@timestamp": float64(time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC).UnixMilli()), "action": "repository_ruleset.update",
			"actor": "Ana-Dev", "repo": "acme/api", "org": "acme"},
		obj{"@timestamp": float64(time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC).UnixMilli()), "action": "repository_ruleset.update",
			"actor": "renovate[bot]", "repo": "acme/api"},
	}})
	s := scope(t)
	if c.AuditReady(s) {
		t.Fatal("ready before connect")
	}
	if _, err := c.Audit(context.Background(), s, auditQuery()); !errors.Is(err, connector.ErrAuditUnreadable) || len(lg.all()) != 0 {
		t.Fatalf("nothing leaves before connect: %v %v", err, lg.all())
	}
	s.Project.Config.Connected = []string{"github"}
	ans, err := c.Audit(context.Background(), s, auditQuery())
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Events) != 2 || ans.Events[0].Actor != "Ana-Dev" || ans.Events[0].ActorKind != "user" || ans.Events[1].ActorKind != "bot" ||
		ans.Events[0].Params["repo"][0] != "acme/api" || !ans.Events[0].At.Equal(time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v", ans)
	}
	u, _ := url.Parse(lg.all()[0])
	q := u.Query()
	if u.Path != "/orgs/acme/audit-log" || q.Get("per_page") != "100" || q.Get("include") != "web" ||
		q.Get("phrase") != "action:repository_ruleset repo:acme/api created:2026-11-02T09:00:00+00:00..2026-11-09T09:00:00+00:00" {
		t.Fatalf("%s", lg.all()[0])
	}
	for _, call := range s.Log.Calls() {
		if call.Method != "GET" || call.Endpoint != "https://api.github.com/orgs/acme/audit-log" || strings.Contains(call.Endpoint, "?") {
			t.Fatalf("%+v", call)
		}
	}
}

func TestAuditOnAPlanWithoutItIsNotReadable(t *testing.T) {
	c := fakeGitHub(t, routes{"/orgs/acme/audit-log": status{404, "Not Found"}})
	s := scope(t)
	s.Project.Config.Connected = []string{"github"}
	_, err := c.Audit(context.Background(), s, auditQuery())
	if !errors.Is(err, connector.ErrAuditUnreadable) || !strings.Contains(err.Error(), "Enterprise Cloud") {
		t.Fatal(err)
	}
}
