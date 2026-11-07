package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/graph"
)

func TestAnalyze(t *testing.T) {
	admin := `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	iamAll := `{"Statement":{"Effect":"Allow","Action":"iam:*","Resource":"*"}}`
	del := `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:DeleteObject"],"Resource":"*"}]}`
	s3All := `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::x"}]}`
	partial := `{"Statement":[{"Effect":"Allow","Action":"s3:Del*","Resource":"*"}]}`
	read := `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}`
	deny := `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	cases := []struct {
		name, doc   string
		admin, dest bool
	}{
		{"star on star", admin, true, true},
		{"iam star", iamAll, true, true},
		{"delete action", del, false, true},
		{"service wildcard", s3All, false, true},
		{"partial wildcard", partial, false, true},
		{"read only", read, false, false},
		{"deny only", deny, false, false},
		{"url encoded", url.QueryEscape(del), false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := analyze([]string{c.doc}, nil, nil)
			if f.admin != c.admin || (len(f.destructive) > 0) != c.dest {
				t.Fatalf("%+v", f)
			}
		})
	}
	if f := analyze(nil, []string{"arn:aws:iam::aws:policy/AdministratorAccess"}, nil); !f.admin {
		t.Fatal("the managed admin policy is admin")
	}
	if f := analyze(nil, []string{"arn:x"}, map[string]string{"arn:x": del}); len(f.destructive) == 0 {
		t.Fatal("managed policies are read")
	}
}

func TestParseReport(t *testing.T) {
	m, err := parseReport("user,arn,password_last_used\nravi,a,2026-10-01T00:00:00+00:00\nci,a,N/A\n")
	if err != nil || len(m) != 1 || m["ravi"].IsZero() {
		t.Fatalf("%v %v", err, m)
	}
	if _, err := parseReport("nope\n1\n"); err == nil {
		t.Fatal("missing columns must be an error")
	}
}

const authXML = `<GetAccountAuthorizationDetailsResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/"><GetAccountAuthorizationDetailsResult><IsTruncated>false</IsTruncated>
<UserDetailList><member><UserName>ci</UserName><Arn>arn:aws:iam::111111111111:user/ci</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate><UserPolicyList><member><PolicyName>p</PolicyName><PolicyDocument>%7B%22Statement%22%3A%5B%7B%22Effect%22%3A%22Allow%22%2C%22Action%22%3A%22s3%3ADeleteObject%22%2C%22Resource%22%3A%22%2A%22%7D%5D%7D</PolicyDocument></member></UserPolicyList></member></UserDetailList>
<RoleDetailList>
<member><RoleName>BreakGlass</RoleName><Path>/</Path><Arn>arn:aws:iam::111111111111:role/BreakGlass</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate><AttachedManagedPolicies><member><PolicyName>AdministratorAccess</PolicyName><PolicyArn>arn:aws:iam::aws:policy/AdministratorAccess</PolicyArn></member></AttachedManagedPolicies></member>
<member><RoleName>AWSReservedSSO_Admin_abc</RoleName><Path>/aws-reserved/sso.amazonaws.com/</Path><Arn>arn:aws:iam::111111111111:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_Admin_abc</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate></member>
<member><RoleName>Deploy</RoleName><Path>/</Path><Arn>arn:aws:iam::111111111111:role/Deploy</Arn><CreateDate>2020-01-01T00:00:00Z</CreateDate><RoleLastUsed><LastUsedDate>2026-10-01T00:00:00Z</LastUsedDate></RoleLastUsed></member>
</RoleDetailList><GroupDetailList/><Policies/></GetAccountAuthorizationDetailsResult></GetAccountAuthorizationDetailsResponse>`

func fakeIAM(t *testing.T) (*Connector, connector.Scope, *[]string) {
	t.Helper()
	var actions []string
	report := "user,arn,password_last_used\nci,a,2026-09-01T00:00:00+00:00\n"
	generated := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q, _ := url.ParseQuery(string(body))
		action := q.Get("Action")
		actions = append(actions, action)
		w.Header().Set("Content-Type", "text/xml")
		switch action {
		case "GetAccountAuthorizationDetails":
			_, _ = io.WriteString(w, authXML)
		case "GenerateCredentialReport":
			state := "STARTED"
			if generated > 0 {
				state = "COMPLETE"
			}
			generated++
			fmt.Fprintf(w, `<GenerateCredentialReportResponse><GenerateCredentialReportResult><State>%s</State></GenerateCredentialReportResult></GenerateCredentialReportResponse>`, state)
		case "GetCredentialReport":
			fmt.Fprintf(w, `<GetCredentialReportResponse><GetCredentialReportResult><Content>%s</Content><ReportFormat>text/csv</ReportFormat></GetCredentialReportResult></GetCredentialReportResponse>`, base64.StdEncoding.EncodeToString([]byte(report)))
		case "ListAccessKeys":
			_, _ = io.WriteString(w, `<ListAccessKeysResponse><ListAccessKeysResult><IsTruncated>false</IsTruncated><AccessKeyMetadata><member><UserName>ci</UserName><AccessKeyId>AKIAIOSFODNN7ABCDEFG</AccessKeyId><Status>Active</Status></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`)
		case "GetAccessKeyLastUsed":
			_, _ = io.WriteString(w, `<GetAccessKeyLastUsedResponse><GetAccessKeyLastUsedResult><UserName>ci</UserName><AccessKeyLastUsed><LastUsedDate>2026-11-01T00:00:00Z</LastUsedDate><ServiceName>s3</ServiceName><Region>us-east-1</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></GetAccessKeyLastUsedResponse>`)
		default:
			t.Errorf("unexpected action %s", action)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.ReportWait = time.Millisecond
	c.Load = func(context.Context, string) (awssdk.Config, error) {
		return awssdk.Config{
			Region: "us-east-1", BaseEndpoint: awssdk.String(srv.URL),
			Credentials: credentials.NewStaticCredentialsProvider("a", "b", ""),
		}, nil
	}
	p := &config.Project{}
	p.Config.AWS.Accounts = append(p.Config.AWS.Accounts, struct {
		Profile string `yaml:"profile"`
	}{"prod"})
	p.Config.AWS.BreakGlass = []string{"arn:aws:iam::111111111111:role/BreakGlass"}
	s := connector.Scope{Project: p, Now: time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC), Log: &connector.CallLog{}, Hasher: graph.NewHasher("s")}
	return c, s, &actions
}

func TestCollectAccount(t *testing.T) {
	c, s, actions := fakeIAM(t)
	g := graph.New()
	if err := c.Collect(context.Background(), c.Collections()[0], s, g); err != nil {
		t.Fatal(err)
	}
	if v := s.Log.Violations(); len(v) != 0 {
		t.Fatal(v)
	}
	for _, a := range *actions {
		if !connector.AWSActions["iam:"+a] {
			t.Errorf("called %s, which is not on the list", a)
		}
	}
	u, ok := g.Get("aws:iam-user/111111111111/ci")
	if !ok {
		t.Fatal("no user")
	}
	if u.Attrs["last_used"] != "2026-11-01T00:00:00Z" {
		t.Fatalf("the later of password and key use: %+v", u.Attrs)
	}
	if len(u.Attrs["destructive_actions"].([]any)) != 1 || u.Attrs["is_admin"] != false {
		t.Fatalf("%+v", u.Attrs)
	}
	k, ok := g.Get("aws:key/AKIAIOSFODNN7ABCDEFG")
	if !ok || k.Attrs["user"] != "ci" || k.Attrs["account"] != "111111111111" {
		t.Fatalf("%+v", k)
	}
	bg, _ := g.Get("aws:iam-role/111111111111/BreakGlass")
	if bg.Attrs["is_admin"] != true || bg.Attrs["excluded"] != true {
		t.Fatalf("%+v", bg.Attrs)
	}
	sso, _ := g.Get("aws:iam-role/111111111111/AWSReservedSSO_Admin_abc")
	if sso.Attrs["excluded"] != true {
		t.Fatalf("%+v", sso.Attrs)
	}
	dep, _ := g.Get("aws:iam-role/111111111111/Deploy")
	if dep.Attrs["excluded"] != false || dep.Attrs["last_used"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("%+v", dep.Attrs)
	}
}

func TestUnlistedActionIsRefusedBeforeAnyCall(t *testing.T) {
	c, s, actions := fakeIAM(t)
	cfg, _ := c.Load(context.Background(), "x")
	cl := ClientFor(cfg, s.Log)
	_, err := cl.DeleteUser(context.Background(), &iam.DeleteUserInput{UserName: awssdk.String("ci")})
	if !errors.Is(err, connector.ErrBlocked) {
		t.Fatalf("got %v", err)
	}
	if len(*actions) != 0 {
		t.Fatalf("a refused action reached the server: %v", *actions)
	}
	if !strings.Contains(strings.Join(s.Log.Violations(), ""), "iam:DeleteUser") {
		t.Fatal(s.Log.Violations())
	}
}

func TestIsDestructive(t *testing.T) {
	yes := []string{"*", "s3:*", "s3:deleteobject", "ec2:terminateinstances", "rds:*delete*", "s3:del*", "dynamodb:droptable"}
	no := []string{"s3:getobject", "s3:listbucket", "iam:listusers", "s3:get*"}
	for _, a := range yes {
		if !isDestructive(a) {
			t.Errorf("%s should be destructive", a)
		}
	}
	for _, a := range no {
		if isDestructive(a) {
			t.Errorf("%s should not be destructive", a)
		}
	}
}
