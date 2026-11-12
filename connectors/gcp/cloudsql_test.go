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
