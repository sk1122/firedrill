package aws

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

const acct = "111122223333"

// rdsPage wraps DB instances or clusters in a Describe response.
func rdsPage(op, list, marker string) string {
	m := ""
	if marker != "" {
		m = "<Marker>" + marker + "</Marker>"
	}
	return "<" + op + "Response xmlns=\"http://rds.amazonaws.com/doc/2014-10-31/\"><" + op + "Result>" + m + list + "</" + op + "Result></" + op + "Response>"
}

const (
	ordersXML = `<DBInstances><DBInstance><DBInstanceIdentifier>orders</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:111122223333:db:orders</DBInstanceArn>
<Engine>postgres</Engine><BackupRetentionPeriod>14</BackupRetentionPeriod><DeletionProtection>true</DeletionProtection>
<TagList><Tag><Key>Environment</Key><Value>Production</Value></Tag></TagList>
<DBInstanceAutomatedBackupsReplications><DBInstanceAutomatedBackupsReplication><DBInstanceAutomatedBackupsArn>arn:aws:rds:us-west-2:111122223333:auto-backup:ab-orders</DBInstanceAutomatedBackupsArn></DBInstanceAutomatedBackupsReplication></DBInstanceAutomatedBackupsReplications>
</DBInstance>
<DBInstance><DBInstanceIdentifier>ledger-1</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:111122223333:db:ledger-1</DBInstanceArn><DBClusterIdentifier>ledger</DBClusterIdentifier><Engine>aurora-postgresql</Engine><BackupRetentionPeriod>1</BackupRetentionPeriod></DBInstance>
</DBInstances>`
	scratchXML = `<DBInstances><DBInstance><DBInstanceIdentifier>scratch</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:111122223333:db:scratch</DBInstanceArn><Engine>mysql</Engine><BackupRetentionPeriod>0</BackupRetentionPeriod><DeletionProtection>false</DeletionProtection></DBInstance>
<DBInstance><DBInstanceIdentifier>orders-replica</DBInstanceIdentifier><DBInstanceArn>arn:aws:rds:us-east-1:111122223333:db:orders-replica</DBInstanceArn><ReadReplicaSourceDBInstanceIdentifier>orders</ReadReplicaSourceDBInstanceIdentifier><Engine>postgres</Engine></DBInstance></DBInstances>`
	ledgerXML = `<DBClusters><DBCluster><DBClusterIdentifier>ledger</DBClusterIdentifier><DBClusterArn>arn:aws:rds:us-east-1:111122223333:cluster:ledger</DBClusterArn><Engine>aurora-postgresql</Engine><BackupRetentionPeriod>3</BackupRetentionPeriod><DeletionProtection>false</DeletionProtection></DBCluster></DBClusters>`
)

type fakeAWS struct {
	mu       sync.Mutex
	calls    []string
	rdsDeny  bool
	copyDeny bool
}

func (f *fakeAWS) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/copy-jobs") {
			f.mu.Lock()
			f.calls = append(f.calls, "ListCopyJobs")
			f.mu.Unlock()
			if r.Method != http.MethodGet || r.URL.Query().Get("state") != "COMPLETED" || r.URL.Query().Get("createdAfter") == "" {
				t.Errorf("copy jobs call: %s %s", r.Method, r.URL.RawQuery)
			}
			if f.copyDeny {
				w.Header().Set("X-Amzn-ErrorType", "AccessDeniedException")
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"message":"not authorized to perform backup:ListCopyJobs"}`)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("nextToken") == "" {
				_, _ = io.WriteString(w, `{"CopyJobs":[{"ResourceArn":"arn:aws:rds:us-east-1:111122223333:db:orders","DestinationBackupVaultArn":"arn:aws:backup:us-east-1:444455556666:backup-vault:acme-vault","State":"COMPLETED"}],"NextToken":"t2"}`)
				return
			}
			_, _ = io.WriteString(w, `{"CopyJobs":[{"ResourceArn":"arn:aws:rds:us-east-1:111122223333:cluster:ledger","DestinationBackupVaultArn":"arn:aws:backup:us-west-2:111122223333:backup-vault:same","State":"COMPLETED"}]}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(body))
		action := q.Get("Action")
		f.mu.Lock()
		f.calls = append(f.calls, action)
		f.mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		if f.rdsDeny {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `<ErrorResponse><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>not authorized</Message></Error><RequestId>1</RequestId></ErrorResponse>`)
			return
		}
		switch action {
		case "DescribeDBClusters":
			_, _ = io.WriteString(w, rdsPage("DescribeDBClusters", ledgerXML, ""))
		case "DescribeDBInstances":
			if q.Get("Marker") == "" {
				_, _ = io.WriteString(w, rdsPage("DescribeDBInstances", ordersXML, "m2"))
				return
			}
			_, _ = io.WriteString(w, rdsPage("DescribeDBInstances", scratchXML, ""))
		default:
			t.Errorf("unexpected action %s", action)
			w.WriteHeader(500)
		}
	}
}

func fakeBackups(t *testing.T, f *fakeAWS, production ...string) (*Connector, connector.Scope) {
	t.Helper()
	srv := httptest.NewServer(f.handler(t))
	t.Cleanup(srv.Close)
	c := New()
	c.Load = func(context.Context, string) (awssdk.Config, error) {
		return awssdk.Config{Region: "us-east-1", BaseEndpoint: awssdk.String(srv.URL), RetryMaxAttempts: 1,
			Credentials: credentials.NewStaticCredentialsProvider("a", "b", "")}, nil
	}
	p := &config.Project{}
	p.Config.AWS.Accounts = append(p.Config.AWS.Accounts, struct {
		Profile string `yaml:"profile"`
	}{"acme-prod"})
	p.Config.Production = production
	s := connector.Scope{Project: p, Now: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Log: &connector.CallLog{}, Hasher: graph.NewHasher("s")}
	return c, s
}

func backupsCollection(c *Connector) connector.Collection {
	for _, col := range c.Collections() {
		if col.Name == CollectionBackups {
			return col
		}
	}
	panic("no backups collection")
}

func TestCollectBackups(t *testing.T) {
	f := &fakeAWS{}
	c, s := fakeBackups(t, f)
	g := graph.New()
	if err := c.Collect(context.Background(), backupsCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	for _, a := range f.calls {
		prefix := "rds:"
		if a == "ListCopyJobs" {
			prefix = "backup:"
		}
		if !connector.AWSActions[prefix+a] {
			t.Errorf("called %s, which is not on the list", a)
		}
	}
	dbs := g.Nodes(graph.KindDatabase)
	if len(dbs) != 3 {
		t.Fatalf("a cluster member and a read replica are judged through their source: %+v", dbs)
	}
	orders, _ := g.Get(graph.ID("aws:db/" + acct + "/us-east-1/orders"))
	if orders.Attrs["separate_copy"] != "yes" || orders.Attrs["retention_days"] != int64(14) || orders.Attrs["deletion_protection"] != true ||
		orders.Attrs["production"] != true || orders.Attrs["production_marked"] != false || orders.Attrs["profile"] != "acme-prod" {
		t.Fatalf("%+v", orders.Attrs)
	}
	if d := orders.Attrs["copy_detail"].(string); !strings.Contains(d, "444455556666") || !strings.Contains(d, "us-west-2 (same account)") {
		t.Fatal(d)
	}
	ledger, _ := g.Get(graph.ID("aws:db/" + acct + "/us-east-1/ledger"))
	if ledger.Attrs["separate_copy"] != "no" || ledger.Attrs["db_kind"] != "cluster" || ledger.Attrs["retention_days"] != int64(3) {
		t.Fatalf("a copy to another region of the same account is not separate: %+v", ledger.Attrs)
	}
	scratch, _ := g.Get(graph.ID("aws:db/" + acct + "/us-east-1/scratch"))
	if scratch.Attrs["automated_backups"] != false || scratch.Attrs["production"] != false {
		t.Fatalf("%+v", scratch.Attrs)
	}
	scan, ok := g.Get(graph.ScanID(BackupScanner, "acme-prod"))
	if !ok || scan.Attrs["inspected"] != int64(3) || scan.Attrs["partial"] != nil {
		t.Fatalf("%+v", scan)
	}
}

func TestBackupsProductionByConfig(t *testing.T) {
	c, s := fakeBackups(t, &fakeAWS{}, acct)
	g := graph.New()
	if err := c.Collect(context.Background(), backupsCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	scratch, _ := g.Get(graph.ID("aws:db/" + acct + "/us-east-1/scratch"))
	if scratch.Attrs["production"] != true || scratch.Attrs["production_marked"] != true {
		t.Fatalf("an account named under production makes every database in it production: %+v", scratch.Attrs)
	}
}

func TestCopyJobsDeniedMeansUnknown(t *testing.T) {
	c, s := fakeBackups(t, &fakeAWS{copyDeny: true})
	g := graph.New()
	if err := c.Collect(context.Background(), backupsCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	orders, _ := g.Get(graph.ID("aws:db/" + acct + "/us-east-1/orders"))
	if orders.Attrs["separate_copy"] != "unknown" {
		t.Fatalf("an unreadable copy list is never a no and never a yes: %+v", orders.Attrs)
	}
	scan, _ := g.Get(graph.ScanID(BackupScanner, "acme-prod"))
	if p, _ := scan.Attrs["partial"].(string); !strings.Contains(p, "copy jobs not readable") {
		t.Fatalf("%+v", scan.Attrs)
	}
}

func TestRDSDeniedIsAnErrorForBackupsOnly(t *testing.T) {
	c, s := fakeBackups(t, &fakeAWS{rdsDeny: true})
	g := graph.New()
	if err := c.Collect(context.Background(), backupsCollection(c), s, g); err != nil {
		t.Fatalf("a denied RDS read must not fail the IAM drills too: %v", err)
	}
	scan, _ := g.Get(graph.ScanID(BackupScanner, "acme-prod"))
	if e, _ := scan.Attrs["error"].(string); !strings.Contains(e, "AccessDenied") {
		t.Fatalf("%+v", scan.Attrs)
	}
	if len(g.Nodes(graph.KindDatabase)) != 0 {
		t.Fatal("nothing read means no databases, and the error says so")
	}
}

func TestRegionsComeFromConfigOrProfile(t *testing.T) {
	f := &fakeAWS{}
	c, s := fakeBackups(t, f)
	s.Project.Config.AWS.Regions = []string{"us-east-1", "eu-west-1"}
	g := graph.New()
	if err := c.Collect(context.Background(), backupsCollection(c), s, g); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range f.calls {
		if a == "DescribeDBClusters" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("each listed region is read once: %v", f.calls)
	}

	// No region anywhere: nothing is read and the scan says what to set.
	c2, s2 := fakeBackups(t, &fakeAWS{})
	load := c2.Load
	c2.Load = func(ctx context.Context, p string) (awssdk.Config, error) {
		cfg, err := load(ctx, p)
		cfg.Region = ""
		return cfg, err
	}
	g2 := graph.New()
	if err := c2.Collect(context.Background(), backupsCollection(c2), s2, g2); err != nil {
		t.Fatal(err)
	}
	scan, _ := g2.Get(graph.ScanID(BackupScanner, "acme-prod"))
	if e, _ := scan.Attrs["error"].(string); !strings.Contains(e, "aws.regions") {
		t.Fatalf("%+v", scan.Attrs)
	}
}

func TestRDSAndBackupWritesAreRefusedBeforeAnyCall(t *testing.T) {
	f := &fakeAWS{}
	c, s := fakeBackups(t, f)
	cfg, _ := c.Load(context.Background(), "x")
	_, err := RDSClientFor(cfg, s.Log).DeleteDBInstance(context.Background(), &rds.DeleteDBInstanceInput{DBInstanceIdentifier: awssdk.String("orders")})
	if !errors.Is(err, connector.ErrBlocked) {
		t.Fatalf("got %v", err)
	}
	_, err = BackupClientFor(cfg, s.Log).DeleteRecoveryPoint(context.Background(), &backup.DeleteRecoveryPointInput{
		BackupVaultName: awssdk.String("v"), RecoveryPointArn: awssdk.String("arn:aws:backup:us-east-1:111122223333:recovery-point:x")})
	if !errors.Is(err, connector.ErrBlocked) {
		t.Fatalf("got %v", err)
	}
	if len(f.calls) != 0 {
		t.Fatalf("a refused action reached the server: %v", f.calls)
	}
	v := strings.Join(s.Log.Violations(), " ")
	if !strings.Contains(v, "rds:DeleteDBInstance") || !strings.Contains(v, "backup:DeleteRecoveryPoint") {
		t.Fatal(v)
	}
}
