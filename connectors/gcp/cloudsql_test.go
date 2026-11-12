package gcp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// sqlFake answers the token exchange and Cloud SQL instances.list per project.
type sqlFake struct {
	t     *testing.T
	calls []string
}

func (f *sqlFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := r.Header.Get("X-Original-Host")
	f.calls = append(f.calls, r.Method+" "+host+r.URL.Path)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case host == "oauth2.googleapis.com" && r.Method == http.MethodPost && r.URL.Path == "/token":
		_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
	case host == sqlHost && r.Method == http.MethodGet && r.URL.Path == "/v1/projects/acme-prod/instances":
		if r.URL.Query().Get("pageToken") == "" {
			_, _ = io.WriteString(w, `{"items":[{"name":"orders","region":"europe-west1","databaseVersion":"POSTGRES_16","instanceType":"CLOUD_SQL_INSTANCE",
				"replicaNames":["orders-replica"],
				"settings":{"deletionProtectionEnabled":true,"retainBackupsOnDelete":true,"userLabels":{"team":"payments"},
				"backupConfiguration":{"enabled":true,"pointInTimeRecoveryEnabled":true,"backupRetentionSettings":{"retentionUnit":"COUNT","retainedBackups":14}}}}],
				"nextPageToken":"p2"}`)
			return
		}
		_, _ = io.WriteString(w, `{"items":[
			{"name":"orders-replica","region":"europe-west1","databaseVersion":"POSTGRES_16","instanceType":"READ_REPLICA_INSTANCE","masterInstanceName":"acme-prod:orders","settings":{}},
			{"name":"scratch","region":"europe-west1","databaseVersion":"MYSQL_8_0","settings":{"backupConfiguration":{"enabled":false}}}]}`)
	case host == sqlHost && r.Method == http.MethodGet && r.URL.Path == "/v1/projects/acme-prod/operations":
		switch r.URL.Query().Get("instance") {
		case "orders":
			if r.URL.Query().Get("pageToken") == "" {
				// An import is not a restore, and a restore that failed is not one either.
				_, _ = io.WriteString(w, `{"items":[
					{"operationType":"IMPORT","status":"DONE","endTime":"2026-11-01T10:00:00Z","targetId":"orders"},
					{"operationType":"RESTORE_VOLUME","status":"DONE","endTime":"2026-11-02T10:00:00Z","targetId":"orders","error":{"errors":[{"code":"X","message":"m"}]}},
					{"operationType":"RESTORE_VOLUME","status":"RUNNING","targetId":"orders"}],"nextPageToken":"o2"}`)
				return
			}
			_, _ = io.WriteString(w, `{"items":[{"operationType":"CLONE","status":"DONE","endTime":"2026-10-18T09:30:00.120Z","targetId":"orders"}]}`)
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"error":{"code":403,"message":"denied","status":"PERMISSION_DENIED"}}`)
		}
	case host == sqlHost && r.URL.Path == "/v1/projects/acme-dev/instances":
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"code":403,"message":"Cloud SQL Admin API has not been used","status":"PERMISSION_DENIED","details":[{"reason":"SERVICE_DISABLED"}]}}`)
	case host == sqlHost && r.URL.Path == "/v1/projects/acme-data/instances":
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"error":{"code":403,"message":"The client is not authorized to make this request.","status":"PERMISSION_DENIED"}}`)
	default:
		f.t.Errorf("unexpected call %s %s%s", r.Method, host, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}
}

func sqlCollection(c *Connector) connector.Collection {
	for _, col := range c.Collections() {
		if col.Name == CollectionBackups {
			return col
		}
	}
	panic("no cloudsql collection")
}

func TestCollectCloudSQL(t *testing.T) {
	f := &sqlFake{t: t}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := newConn(srv)
	s := scope("acme-prod", "acme-dev", "acme-data")
	s.Project.Config.Production = []string{"acme-prod"}
	g := graph.New()
	if err := c.Collect(context.Background(), sqlCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	if len(g.Nodes(graph.KindDatabase)) != 2 {
		t.Fatalf("a read replica is judged through its primary: %+v", g.Nodes(graph.KindDatabase))
	}
	orders, _ := g.Get("gcp:db/acme-prod/orders")
	a := orders.Attrs
	if a["retention_days"] != int64(14) || a["automated_backups"] != true || a["deletion_protection"] != true ||
		a["production"] != true || a["separate_copy"] != "unknown" || a["region"] != "europe-west1" || a["engine"] != "POSTGRES_16" {
		t.Fatalf("Cloud SQL never shows a copy in another project, so it is unknown: %+v", a)
	}
	if d := a["copy_detail"].(string); !strings.Contains(d, "same project") || !strings.Contains(d, "not a backup") {
		t.Fatal(d)
	}
	scratch, _ := g.Get("gcp:db/acme-prod/scratch")
	if scratch.Attrs["automated_backups"] != false || scratch.Attrs["retention_days"] != int64(0) {
		t.Fatalf("%+v", scratch.Attrs)
	}
	if orders.Attrs["last_restore"] != "2026-10-18T09:30:00Z" || orders.Attrs["restore_scope"] != "instance" || orders.Attrs["restores_readable"] != false {
		t.Fatalf("a finished clone counts for its source; another instance's operations were unreadable: %+v", orders.Attrs)
	}
	if d := orders.Attrs["restore_detail"].(string); !strings.Contains(d, "clone of orders") || !strings.Contains(d, "could not be read for scratch") {
		t.Fatal(d)
	}
	if scratch.Attrs["last_restore"] != "" || scratch.Attrs["restore_scope"] != "" || scratch.Attrs["restores_readable"] != false {
		t.Fatalf("nothing read is not never restored: %+v", scratch.Attrs)
	}
	prod, _ := g.Get(graph.ScanID(BackupScanner, "acme-prod"))
	if prod.Attrs["inspected"] != int64(2) || prod.Attrs["partial"] != nil {
		t.Fatalf("%+v", prod.Attrs)
	}
	dev, _ := g.Get(graph.ScanID(BackupScanner, "acme-dev"))
	if e, _ := dev.Attrs["error"].(string); !strings.Contains(e, "sqladmin.googleapis.com") || !strings.Contains(e, "billed to") {
		t.Fatalf("an API not turned on is an error that says where to turn it on: %+v", dev.Attrs)
	}
	data, _ := g.Get(graph.ScanID(BackupScanner, "acme-data"))
	if e, _ := data.Attrs["error"].(string); !strings.Contains(e, "403") {
		t.Fatalf("a denied read is an error: %+v", data.Attrs)
	}
}

func TestCloudSQLWritesAreRefused(t *testing.T) {
	tr := &connector.Transport{Policy: Policy([]string{"acme-prod"}, ""), Log: &connector.CallLog{}, Connector: "gcp"}
	for _, m := range []string{http.MethodPost, http.MethodPatch, http.MethodDelete} {
		req, _ := http.NewRequest(m, "https://"+sqlHost+"/v1/projects/acme-prod/instances/orders", nil)
		if _, err := tr.RoundTrip(req); !errors.Is(err, connector.ErrBlocked) {
			t.Errorf("%s on Cloud SQL must be refused: %v", m, err)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, "https://"+sqlHost+"/v1/projects/acme-prod/instances/orders/export", nil)
	if _, err := tr.RoundTrip(req); !errors.Is(err, connector.ErrBlocked) {
		t.Fatal("an export is a POST and is refused")
	}
}

func TestCloudSQLRestoreIntoAnotherInstanceCountsForTheProject(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Original-Host")
		w.Header().Set("Content-Type", "application/json")
		switch {
		case host == "oauth2.googleapis.com":
			_, _ = io.WriteString(w, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
		case r.Method != http.MethodGet:
			t.Errorf("only GET: %s %s", r.Method, r.URL.Path)
		case r.URL.Path == "/v1/projects/acme-prod/instances":
			_, _ = io.WriteString(w, `{"items":[{"name":"orders","settings":{"backupConfiguration":{"enabled":true}}},{"name":"restore-drill","settings":{}}]}`)
		case r.URL.Path == "/v1/projects/acme-prod/operations" && r.URL.Query().Get("instance") == "restore-drill":
			_, _ = io.WriteString(w, `{"items":[{"operationType":"RESTORE_VOLUME","status":"DONE","endTime":"2026-10-23T08:00:00Z","targetId":"restore-drill"}]}`)
		case r.URL.Path == "/v1/projects/acme-prod/operations":
			_, _ = io.WriteString(w, `{"kind":"sql#operationsList"}`)
		default:
			t.Errorf("unexpected %s", r.URL.Path)
		}
	})
	srv := httptest.NewServer(h)
	defer srv.Close()
	c := newConn(srv)
	s := scope("acme-prod")
	g := graph.New()
	if err := c.Collect(context.Background(), sqlCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	orders, _ := g.Get("gcp:db/acme-prod/orders")
	if orders.Attrs["last_restore"] != "2026-10-23T08:00:00Z" || orders.Attrs["restore_scope"] != "project" || orders.Attrs["restores_readable"] != true {
		t.Fatalf("a restore into a scratch instance counts for the project, at lower confidence: %+v", orders.Attrs)
	}
	if d := orders.Attrs["restore_detail"].(string); !strings.Contains(d, "restore-drill") || !strings.Contains(d, "does not name the backup") {
		t.Fatal(d)
	}
	for _, call := range s.Log.Calls() {
		if call.Method != http.MethodGet && call.Endpoint != tokenURL {
			t.Fatalf("Cloud SQL is read with GET only: %+v", call)
		}
	}
}

func TestCloudSQLOperationsWritesAreRefused(t *testing.T) {
	// The restore read adds no host: the policy's hosts are the ones it had.
	hosts := []string{}
	for h := range Policy([]string{"acme-prod"}, "").Hosts {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if strings.Join(hosts, " ") != "cloudresourcemanager.googleapis.com iam.googleapis.com policyanalyzer.googleapis.com sqladmin.googleapis.com storage.googleapis.com" {
		t.Fatalf("hosts: %v", hosts)
	}
	tr := &connector.Transport{Policy: Policy([]string{"acme-prod"}, ""), Log: &connector.CallLog{}, Connector: "gcp"}
	for _, u := range []string{"/v1/projects/acme-prod/operations/op-1/cancel", "/v1/projects/acme-prod/instances/orders/restoreBackup",
		"/v1/projects/acme-prod/instances/orders/clone"} {
		req, _ := http.NewRequest(http.MethodPost, "https://"+sqlHost+u, nil)
		if _, err := tr.RoundTrip(req); !errors.Is(err, connector.ErrBlocked) {
			t.Errorf("POST %s must be refused: %v", u, err)
		}
	}
}
