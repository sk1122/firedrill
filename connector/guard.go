package connector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
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
}

// GitHubPolicy allows reads of the GitHub API and its tarball redirect host.
func GitHubPolicy() Policy {
	return Policy{Hosts: map[string]bool{"api.github.com": true, "codeload.github.com": true}}
}

// GooglePolicy allows reads of the Admin SDK and the OAuth token exchange.
func GooglePolicy() Policy {
	return Policy{
		Hosts:    map[string]bool{"admin.googleapis.com": true},
		PostURLs: map[string]bool{"https://oauth2.googleapis.com/token": true},
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
		if t.Policy.Hosts[hostname] || t.Policy.Hosts[hostport] {
			return nil
		}
		if t.Policy.HostAllowed != nil && (t.Policy.HostAllowed(hostname) || t.Policy.HostAllowed(hostport)) {
			return nil
		}
		return fmt.Errorf("%w: %s may not call host %s", ErrBlocked, t.Connector, hostport)
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

// AWSActions is the fixed list of AWS actions Firedrill may call. Broad reads
// such as secretsmanager:GetSecretValue or s3:GetObject are refused even if the
// credential allows them.
var AWSActions = map[string]bool{
	"iam:GetAccountAuthorizationDetails": true,
	"iam:GetAccessKeyLastUsed":           true,
	"iam:ListAccessKeys":                 true,
	"iam:GenerateCredentialReport":       true,
	"iam:GetCredentialReport":            true,
}

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
