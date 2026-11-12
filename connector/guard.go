package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrBlocked marks a call the guard refused. It stops the run.
var ErrBlocked = errors.New("blocked by the read-only guard")

// Call is one outbound call as logged.
type Call struct {
	Time      time.Time `json:"time"`
	Connector string    `json:"connector"`
	Method    string    `json:"method"`
	Endpoint  string    `json:"endpoint"`
	Blocked   bool      `json:"blocked,omitempty"`
}

// CallLog records every outbound call and every call the guard refused. It
// stores the endpoint with no query string, so no value in a URL reaches disk.
type CallLog struct {
	mu         sync.Mutex
	calls      []Call
	violations []string
}

// Add records one call.
func (l *CallLog) Add(c Call) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, c)
	if c.Blocked {
		l.violations = append(l.violations, fmt.Sprintf("%s %s %s", c.Connector, c.Method, c.Endpoint))
	}
}

// Calls returns every call so far.
func (l *CallLog) Calls() []Call {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Call(nil), l.calls...)
}

// Violations returns every refused call so far.
func (l *CallLog) Violations() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.violations...)
}

// WriteTo appends the log as JSON Lines to a file.
func (l *CallLog) WriteFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	for _, c := range l.Calls() {
		if err := enc.Encode(c); err != nil {
			return err
		}
	}
	return f.Close()
}

// Policy says which calls a connector may make.
type Policy struct {
	// Hosts may receive GET and HEAD. An empty map with HostAllowed set defers
	// to that function.
	Hosts map[string]bool
	// HostAllowed, when set, decides GET and HEAD hosts at call time.
	HostAllowed func(host string) bool
	// PostURLs are the exact scheme, host and path allowed to receive POST.
	PostURLs map[string]bool
	// Paths, when a host has an entry, limits GET and HEAD on that host to
	// paths matching one of its patterns. A host that also serves write or
	// inference APIs is listed here, so a read of anything else is refused.
	Paths map[string][]*regexp.Regexp
}

// GitHubPolicy allows reads of the GitHub API and its tarball redirect host.
func GitHubPolicy() Policy {
	return Policy{Hosts: map[string]bool{"api.github.com": true, "codeload.github.com": true}}
}

// GooglePolicy allows reads of the Admin SDK and the OAuth token exchange. The
// Admin SDK host takes the directory users list and each user's OAuth tokens
// list, both GET.
func GooglePolicy() Policy {
	return Policy{
		Hosts:    map[string]bool{"admin.googleapis.com": true},
		PostURLs: map[string]bool{"https://oauth2.googleapis.com/token": true},
	}
}

// AnthropicPolicy allows only GET of the two Admin API reads Firedrill uses.
// api.anthropic.com also serves inference and every Admin API write, so the
// path is limited too: a POST that would create, update or archive anything,
// and a GET of any other path, is refused.
func AnthropicPolicy() Policy {
	return Policy{
		Hosts: map[string]bool{"api.anthropic.com": true},
		Paths: map[string][]*regexp.Regexp{"api.anthropic.com": {
			// Every API key: ID, name, status, partial hint, creator and workspace.
			// https://platform.claude.com/docs/en/api/admin/api_keys/list
			regexp.MustCompile(`^/v1/organizations/api_keys$`),
			// Workspace IDs and names, to name each key's workspace.
			// https://platform.claude.com/docs/en/api/admin/workspaces/list
			regexp.MustCompile(`^/v1/organizations/workspaces$`),
		}},
	}
}

// OpenAIPolicy allows only GET of the four Administration API reads Firedrill
// uses. api.openai.com also serves inference and every write, so the path is
// limited too.
func OpenAIPolicy() Policy {
	return Policy{
		Hosts: map[string]bool{"api.openai.com": true},
		Paths: map[string][]*regexp.Regexp{"api.openai.com": {
			// Every project: ID, name and status.
			// https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/methods/list
			regexp.MustCompile(`^/v1/organization/projects$`),
			// Each project's API keys: ID, name, redacted value, owner, created.
			// https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/api_keys/methods/list
			regexp.MustCompile(`^/v1/organization/projects/[A-Za-z0-9_-]+/api_keys$`),
			// Each project's hard spend limit.
			// https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/projects/subresources/spend_limit/index.md
			regexp.MustCompile(`^/v1/organization/projects/[A-Za-z0-9_-]+/spend_limit$`),
			// The organization's hard spend limit.
			// https://developers.openai.com/api/reference/resources/admin/subresources/organization/subresources/spend_limit/index.md
			regexp.MustCompile(`^/v1/organization/spend_limit$`),
		}},
	}
}

// Transport is the guarded HTTP client every connector gets from Base.
type Transport struct {
	Next      http.RoundTripper
	Policy    Policy
	Log       *CallLog
	Connector string
}

// RoundTrip refuses anything outside the policy and logs every call.
func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	endpoint := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path
	call := Call{Time: time.Now().UTC(), Connector: t.Connector, Method: r.Method, Endpoint: endpoint}
	if err := t.check(r.Method, r.URL.Hostname(), r.URL.Host, endpoint); err != nil {
		call.Blocked = true
		t.Log.Add(call)
		return nil, err
	}
	t.Log.Add(call)
	next := t.Next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(r)
}

func (t *Transport) check(method, hostname, hostport, endpoint string) error {
	switch method {
	case http.MethodGet, http.MethodHead:
		hostOK := t.Policy.Hosts[hostname] || t.Policy.Hosts[hostport] ||
			(t.Policy.HostAllowed != nil && (t.Policy.HostAllowed(hostname) || t.Policy.HostAllowed(hostport)))
		if !hostOK {
			return fmt.Errorf("%w: %s may not call host %s", ErrBlocked, t.Connector, hostport)
		}
		patterns, limited := t.Policy.Paths[hostname]
		if !limited {
			patterns, limited = t.Policy.Paths[hostport]
		}
		if !limited {
			return nil
		}
		path := endpoint[strings.Index(endpoint, "://")+3:]
		if i := strings.Index(path, "/"); i >= 0 {
			path = path[i:]
		} else {
			path = "/"
		}
		for _, p := range patterns {
			if p.MatchString(path) {
				return nil
			}
		}
		return fmt.Errorf("%w: %s may not %s %s", ErrBlocked, t.Connector, method, endpoint)
	case http.MethodPost:
		if t.Policy.PostURLs[endpoint] {
			return nil
		}
	}
	return fmt.Errorf("%w: %s may not %s %s", ErrBlocked, t.Connector, method, endpoint)
}

// Client returns an HTTP client behind the guard. Redirects pass through the
// guard too, since each hop is a new round trip.
func Client(name string, p Policy, log *CallLog, next http.RoundTripper) *http.Client {
	return &http.Client{Timeout: 60 * time.Second, Transport: &Transport{Next: next, Policy: p, Log: log, Connector: name}}
}

// AWSActions is the fixed list of AWS actions Firedrill may call, each named as
// IAM names it: service prefix and operation. Broad reads such as
// secretsmanager:GetSecretValue or s3:GetObject are refused even if the
// credential allows them.
var AWSActions = map[string]bool{
	"iam:GetAccountAuthorizationDetails": true,
	"iam:GetAccessKeyLastUsed":           true,
	"iam:ListAccessKeys":                 true,
	"iam:GenerateCredentialReport":       true,
	"iam:GetCredentialReport":            true,
	// Each RDS DB instance's backup retention, deletion protection, engine and
	// tags, and its cross-Region automated backup replications.
	// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html
	"rds:DescribeDBInstances": true,
	// The same settings for Aurora and other DB clusters, where retention and
	// deletion protection live on the cluster.
	// https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBClusters.html
	"rds:DescribeDBClusters": true,
	// Completed AWS Backup copy jobs, whose destination vault ARN names the
	// account a copy went to.
	// https://docs.aws.amazon.com/aws-backup/latest/devguide/API_ListCopyJobs.html
	"backup:ListCopyJobs": true,
}

// AWSServicePrefix maps an SDK service ID to the prefix IAM uses for its
// actions. A service missing here is refused whatever operation it calls.
var AWSServicePrefix = map[string]string{"IAM": "iam", "RDS": "rds", "Backup": "backup"}

// CheckAWS refuses an AWS action outside the list, and records it.
func CheckAWS(log *CallLog, action string) error {
	call := Call{Time: time.Now().UTC(), Connector: "aws", Method: "CALL", Endpoint: action}
	if !AWSActions[action] {
		call.Blocked = true
		log.Add(call)
		return fmt.Errorf("%w: AWS action %s is not on the list", ErrBlocked, action)
	}
	log.Add(call)
	return nil
}

// UnderDomain reports whether host is a domain or one of its subdomains.
func UnderDomain(host, domain string) bool {
	host, domain = strings.ToLower(host), strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}
