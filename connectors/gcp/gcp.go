// Package gcp reads IAM bindings, Cloud Storage bucket access and service
// account keys in every listed Google Cloud project. Every call is a GET, except
// the token exchange and getIamPolicy on each listed project, each allowed by
// exact URL.
package gcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// CredentialsEnv names an optional variable holding a credentials file's path.
// It is separate from GOOGLE_APPLICATION_CREDENTIALS, which the Workspace
// connector uses for its own key.
const CredentialsEnv = "FIREDRILL_GCP_CREDENTIALS"

// Scope is the OAuth scope Firedrill asks for. The IAM API accepts only the
// full cloud-platform scope, so reads are limited by the reader account's
// roles and by the guard, not by the scope.
const Scope = "https://www.googleapis.com/auth/cloud-platform"

const (
	crmHost      = "cloudresourcemanager.googleapis.com"
	iamHost      = "iam.googleapis.com"
	storageHost  = "storage.googleapis.com"
	analyzerHost = "policyanalyzer.googleapis.com"
	tokenURL     = "https://oauth2.googleapis.com/token"
)

// Connector reads Google Cloud.
type Connector struct {
	connector.Base
	// ReadFile reads the credentials file. Tests replace it.
	ReadFile func(path string) ([]byte, error)
}

// New returns the connector.
func New() *Connector {
	return &Connector{
		Base:     connector.Base{ConnectorName: "gcp", Limit: 10, Burst: 10},
		ReadFile: os.ReadFile,
	}
}

func init() { connector.Register(New()) }

// Policy allows GET on the four API hosts, the token exchange, getIamPolicy on
// each listed project, and, when impersonating, the one generateAccessToken URL
// in the credentials file, each by exact URL.
func Policy(projects []string, impersonationURL string) connector.Policy {
	post := map[string]bool{tokenURL: true}
	if impersonationURL != "" {
		post[impersonationURL] = true
	}
	for _, p := range projects {
		post[getIamPolicyURL(p)] = true
	}
	return connector.Policy{
		Hosts:    map[string]bool{crmHost: true, iamHost: true, storageHost: true, analyzerHost: true},
		PostURLs: post,
	}
}

func getIamPolicyURL(project string) string {
	return "https://" + crmHost + "/v3/projects/" + project + ":getIamPolicy"
}

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{
		Name:  "gcp",
		Nodes: []string{graph.KindGCPProject, graph.KindGCPBinding, graph.KindGCPBucket, graph.KindGCPKey},
		Permission: "Viewer and Security Reviewer on each project, and Policy Analyzer's " +
			"Activity Analysis Viewer for key last use. Scope " + Scope,
		Calls: []string{
			"POST " + tokenURL,
			"POST https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/{reader}:generateAccessToken, when impersonating",
			"POST https://" + crmHost + "/v3/projects/{project}:getIamPolicy",
			"GET https://" + iamHost + "/v1/projects/{project}/serviceAccounts",
			"GET https://" + iamHost + "/v1/projects/{project}/serviceAccounts/{account}/keys",
			"GET https://" + analyzerHost + "/v1/projects/{project}/locations/global/activityTypes/serviceAccountKeyLastAuthentication/activities:query",
			"GET https://" + storageHost + "/storage/v1/b?project={project}",
			"GET https://" + storageHost + "/storage/v1/b/{bucket}/iam",
		},
	}}
}

// credentialsPath is FIREDRILL_GCP_CREDENTIALS, or gcloud's application
// default credentials file.
func credentialsPath(s connector.Scope) string {
	get := os.Getenv
	if s.Getenv != nil {
		get = s.Getenv
	}
	if p := get(CredentialsEnv); p != "" {
		return p
	}
	dir := get("CLOUDSDK_CONFIG")
	if dir == "" {
		if runtime.GOOS == "windows" {
			if app := get("APPDATA"); app != "" {
				dir = filepath.Join(app, "gcloud")
			}
		} else if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".config", "gcloud")
		}
	}
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "application_default_credentials.json")
}

// Available is true when projects are listed and a credentials file exists.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if len(s.Project.Config.GCP.Projects) == 0 {
		return false, "connect gcp"
	}
	p := credentialsPath(s)
	if p == "" {
		return false, "connect gcp"
	}
	if _, err := c.ReadFile(p); err != nil {
		return false, "connect gcp"
	}
	return true, ""
}

// client is a guarded client authorized with Scope. Token
// refreshes go through the guard too.
func (c *Connector) client(ctx context.Context, s connector.Scope) (*http.Client, string, error) {
	raw, err := c.ReadFile(credentialsPath(s))
	if err != nil {
		return nil, "", fmt.Errorf("read the GCP credentials: %w", errors.Unwrap(err))
	}
	var meta struct {
		Type             string `json:"type"`
		QuotaProject     string `json:"quota_project_id"`
		ImpersonationURL string `json:"service_account_impersonation_url"`
	}
	_ = json.Unmarshal(raw, &meta)
	typ := googleoauth.CredentialsType(meta.Type)
	impURL := ""
	switch typ {
	case googleoauth.AuthorizedUser, googleoauth.ServiceAccount:
	case googleoauth.ImpersonatedServiceAccount:
		if !impersonationURL.MatchString(meta.ImpersonationURL) {
			return nil, "", fmt.Errorf("the GCP credentials name an unexpected impersonation URL")
		}
		impURL = meta.ImpersonationURL
	default:
		return nil, "", fmt.Errorf("GCP credentials of type %q are not supported", meta.Type)
	}
	c.Policy = Policy(s.Project.Config.GCP.Projects, impURL)
	guarded := c.HTTP(s.Log)
	tctx := context.WithValue(ctx, oauth2.HTTPClient, guarded)
	creds, err := googleoauth.CredentialsFromJSONWithType(tctx, raw, typ, Scope)
	if err != nil {
		return nil, "", fmt.Errorf("the GCP credentials could not be parsed")
	}
	// A user login bills its quota project. A service account, impersonated or
	// not, bills its own project, so no other project is touched.
	quota := ""
	if typ == googleoauth.AuthorizedUser {
		quota = meta.QuotaProject
	}
	return oauth2.NewClient(tctx, creds.TokenSource), quota, nil
}

// impersonationURL is the only form of impersonation URL accepted.
var impersonationURL = regexp.MustCompile(`^https://iamcredentials\.googleapis\.com/v1/projects/-/serviceAccounts/[A-Za-z0-9._@-]+:generateAccessToken$`)

type api struct {
	cl    *http.Client
	quota string
}

// apiError is a Google API error with its status and reason.
type apiError struct {
	Status int
	Reason string
	Msg    string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("HTTP %d %s: %s", e.Status, e.Reason, e.Msg)
}

func (a *api) do(ctx context.Context, method, u string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.quota != "" {
		req.Header.Set("X-Goog-User-Project", a.quota)
	}
	resp, err := a.cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct {
				Message string `json:"message"`
				Status  string `json:"status"`
				Details []struct {
					Reason string `json:"reason"`
				} `json:"details"`
			} `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		reason := e.Error.Status
		for _, d := range e.Error.Details {
			if d.Reason != "" {
				reason = d.Reason
			}
		}
		return &apiError{Status: resp.StatusCode, Reason: reason, Msg: e.Error.Message}
	}
	return json.Unmarshal(data, out)
}

// Collect reads every listed project.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	cl, quota, err := c.client(ctx, s)
	if err != nil {
		return err
	}
	a := &api{cl: cl, quota: quota}
	// One project that cannot be read gives ERROR on that project's drills;
	// the others still run. Only when none can be read does the connector fail.
	var errs []error
	for _, p := range s.Project.Config.GCP.Projects {
		if err := c.collectProject(ctx, a, p, s, out); err != nil {
			if errors.Is(err, connector.ErrBlocked) {
				return err
			}
			errs = append(errs, fmt.Errorf("gcp project %s: %w", p, err))
			out.Node(graph.Node{ID: graph.ID("gcp:project/" + p), Kind: graph.KindGCPProject, Source: "gcp", SeenAt: s.Now,
				Attrs: map[string]any{"name": p, "number": "", "member_domains": memberDomains(s), "partial": []any{},
					"error": err.Error()}})
		}
	}
	if len(errs) == len(s.Project.Config.GCP.Projects) {
		return errors.Join(errs...)
	}
	return nil
}

func memberDomains(s connector.Scope) []any {
	var out []any
	for _, d := range s.Project.Config.GCP.MemberDomains {
		out = append(out, strings.ToLower(d))
	}
	if len(out) == 0 && s.Project.Config.Google.Domain != "" {
		out = append(out, strings.ToLower(s.Project.Config.Google.Domain))
	}
	if out == nil {
		out = []any{}
	}
	return out
}

func (c *Connector) collectProject(ctx context.Context, a *api, project string, s connector.Scope, out graph.Writer) error {
	var policy struct {
		Bindings []struct {
			Role      string    `json:"role"`
			Members   []string  `json:"members"`
			Condition *struct{} `json:"condition"`
		} `json:"bindings"`
	}
	body := map[string]any{"options": map[string]any{"requestedPolicyVersion": 3}}
	if err := a.do(ctx, http.MethodPost, getIamPolicyURL(project), body, &policy); err != nil {
		return fmt.Errorf("read the IAM policy: %w", err)
	}
	projID := graph.ID("gcp:project/" + project)
	var partial []any
	number := ""
	for _, b := range policy.Bindings {
		for _, m := range b.Members {
			mem := parseMember(m, project)
			if mem.number != "" {
				number = mem.number
			}
			id := graph.ID("gcp:binding/" + project + "/" + b.Role + "/" + s.Hasher.Sum(m))
			out.Node(graph.Node{ID: id, Kind: graph.KindGCPBinding, Source: "gcp", SeenAt: s.Now,
				Attrs: map[string]any{
					"project": project, "role": b.Role, "member_type": mem.kind, "member_domain": mem.domain,
					"google_managed": mem.googleManaged, "default_account": mem.defaultAccount,
					"conditional": b.Condition != nil, "member": mem.public,
				},
				Private: map[string]any{"email": mem.email}})
			out.Edge(graph.Edge{From: projID, To: id, Kind: graph.EdgeOwns, Source: "gcp"})
		}
	}

	if err := c.collectKeys(ctx, a, project, s, out, &partial); err != nil {
		return err
	}
	if err := c.collectBuckets(ctx, a, project, s, out, &partial); err != nil {
		return err
	}
	out.Node(graph.Node{ID: projID, Kind: graph.KindGCPProject, Source: "gcp", SeenAt: s.Now, Attrs: map[string]any{
		"name": project, "number": number, "member_domains": memberDomains(s), "partial": partial,
	}})
	return nil
}

type member struct {
	kind, domain, email, number, public string
	googleManaged, defaultAccount       bool
}

// parseMember splits an IAM member such as user:a@b.com. Email addresses are
// private; a service account's address is kept, since it names no person.
func parseMember(m, project string) member {
	kind, rest, ok := strings.Cut(m, ":")
	if !ok {
		return member{kind: m, public: m}
	}
	if kind == "deleted" {
		inner, _, _ := strings.Cut(rest, "?")
		mm := parseMember(inner, project)
		mm.kind = "deleted_" + mm.kind
		return mm
	}
	switch kind {
	case "user", "group":
		_, domain, _ := strings.Cut(rest, "@")
		return member{kind: kind, domain: strings.ToLower(domain), email: strings.ToLower(rest)}
	case "domain":
		return member{kind: kind, domain: strings.ToLower(rest), public: rest}
	case "serviceAccount":
		mm := member{kind: "service_account", public: rest}
		local, domain, _ := strings.Cut(strings.ToLower(rest), "@")
		mm.domain = domain
		switch {
		case domain == project+".iam.gserviceaccount.com":
		case domain == "developer.gserviceaccount.com" && strings.HasSuffix(local, "-compute"):
			mm.defaultAccount = true
			mm.number = strings.TrimSuffix(local, "-compute")
		case domain == "appspot.gserviceaccount.com":
			mm.defaultAccount = true
		case domain == "cloudservices.gserviceaccount.com":
			// The Google APIs Service Agent, which Google gives Editor.
			mm.googleManaged = true
			mm.number = local
		case strings.HasSuffix(domain, "gserviceaccount.com"):
			mm.googleManaged = true
		}
		return mm
	}
	return member{kind: kind, public: m}
}

func (c *Connector) collectKeys(ctx context.Context, a *api, project string, s connector.Scope, out graph.Writer, partial *[]any) error {
	type key struct {
		Name           string `json:"name"`
		ValidAfterTime string `json:"validAfterTime"`
		KeyType        string `json:"keyType"`
		Disabled       bool   `json:"disabled"`
	}
	var accounts []string
	tok := ""
	for {
		var page struct {
			Accounts []struct {
				Email    string `json:"email"`
				Disabled bool   `json:"disabled"`
			} `json:"accounts"`
			Next string `json:"nextPageToken"`
		}
		u := "https://" + iamHost + "/v1/projects/" + project + "/serviceAccounts?pageSize=100"
		if tok != "" {
			u += "&pageToken=" + url.QueryEscape(tok)
		}
		if err := a.do(ctx, http.MethodGet, u, nil, &page); err != nil {
			return fmt.Errorf("list service accounts: %w", err)
		}
		for _, acc := range page.Accounts {
			accounts = append(accounts, acc.Email)
		}
		if page.Next == "" {
			break
		}
		tok = page.Next
	}
	lastUsed, err := c.keyLastUse(ctx, a, project)
	if err != nil {
		var ae *apiError
		if !errors.As(err, &ae) || (ae.Status != http.StatusForbidden && ae.Status != http.StatusNotFound) {
			return fmt.Errorf("read key last use: %w", err)
		}
		// Last use is evidence only: the 90-day age rule already fails any key
		// unused for 90 days. Without Policy Analyzer it reads as unknown.
		*partial = append(*partial, "key last use: Policy Analyzer is not enabled or not readable")
		lastUsed = nil
	}
	for _, acc := range accounts {
		var res struct {
			Keys []key `json:"keys"`
		}
		u := "https://" + iamHost + "/v1/projects/" + project + "/serviceAccounts/" + url.PathEscape(acc) + "/keys?keyTypes=USER_MANAGED"
		if err := a.do(ctx, http.MethodGet, u, nil, &res); err != nil {
			return fmt.Errorf("list keys of %s: %w", acc, err)
		}
		for _, k := range res.Keys {
			keyID := k.Name[strings.LastIndex(k.Name, "/")+1:]
			last := ""
			known := lastUsed != nil
			if lastUsed != nil {
				last = lastUsed[keyID]
			}
			out.Node(graph.Node{ID: graph.ID("gcp:key/" + project + "/" + keyID), Kind: graph.KindGCPKey, Source: "gcp", SeenAt: s.Now,
				Attrs: map[string]any{
					"project": project, "service_account": strings.ToLower(acc), "key_id": keyID,
					"created": normTime(k.ValidAfterTime), "last_used": last, "last_use_known": known, "disabled": k.Disabled,
				}})
		}
	}
	return nil
}

// keyLastUse maps key IDs to their last authentication time, from Policy
// Analyzer, which keeps about two weeks to a few months of history.
func (c *Connector) keyLastUse(ctx context.Context, a *api, project string) (map[string]string, error) {
	out := map[string]string{}
	tok := ""
	for {
		var page struct {
			Activities []struct {
				FullResourceName string `json:"fullResourceName"`
				Activity         struct {
					LastAuthenticatedTime string `json:"lastAuthenticatedTime"`
				} `json:"activity"`
			} `json:"activities"`
			Next string `json:"nextPageToken"`
		}
		u := "https://" + analyzerHost + "/v1/projects/" + project +
			"/locations/global/activityTypes/serviceAccountKeyLastAuthentication/activities:query?pageSize=1000"
		if tok != "" {
			u += "&pageToken=" + url.QueryEscape(tok)
		}
		if err := a.do(ctx, http.MethodGet, u, nil, &page); err != nil {
			return nil, err
		}
		for _, act := range page.Activities {
			id := act.FullResourceName[strings.LastIndex(act.FullResourceName, "/")+1:]
			if t := normTime(act.Activity.LastAuthenticatedTime); t > out[id] {
				out[id] = t
			}
		}
		if page.Next == "" {
			return out, nil
		}
		tok = page.Next
	}
}

func (c *Connector) collectBuckets(ctx context.Context, a *api, project string, s connector.Scope, out graph.Writer, partial *[]any) error {
	tok := ""
	for {
		var page struct {
			Items []struct {
				Name      string `json:"name"`
				IAMConfig struct {
					PublicAccessPrevention string `json:"publicAccessPrevention"`
					Uniform                struct {
						Enabled bool `json:"enabled"`
					} `json:"uniformBucketLevelAccess"`
				} `json:"iamConfiguration"`
			} `json:"items"`
			Next string `json:"nextPageToken"`
		}
		u := "https://" + storageHost + "/storage/v1/b?project=" + url.QueryEscape(project) + "&maxResults=500"
		if tok != "" {
			u += "&pageToken=" + url.QueryEscape(tok)
		}
		if err := a.do(ctx, http.MethodGet, u, nil, &page); err != nil {
			return fmt.Errorf("list buckets: %w", err)
		}
		for _, b := range page.Items {
			var pol struct {
				Bindings []struct {
					Role    string   `json:"role"`
					Members []string `json:"members"`
				} `json:"bindings"`
			}
			readable := true
			if err := a.do(ctx, http.MethodGet, "https://"+storageHost+"/storage/v1/b/"+url.PathEscape(b.Name)+"/iam", nil, &pol); err != nil {
				var ae *apiError
				if !errors.As(err, &ae) || (ae.Status != http.StatusForbidden && ae.Status != http.StatusNotFound) {
					return fmt.Errorf("read the IAM policy of bucket %s: %w", b.Name, err)
				}
				// One bucket we may not read makes the result partial, not a failure.
				readable = false
				*partial = append(*partial, "bucket "+b.Name+": access policy not readable")
			}
			public := []any{}
			for _, bind := range pol.Bindings {
				for _, m := range bind.Members {
					if m == "allUsers" || m == "allAuthenticatedUsers" {
						public = append(public, m+" "+bind.Role)
					}
				}
			}
			pap := b.IAMConfig.PublicAccessPrevention
			if pap == "" {
				pap = "inherited"
			}
			out.Node(graph.Node{ID: graph.ID("gcp:bucket/" + b.Name), Kind: graph.KindGCPBucket, Source: "gcp", SeenAt: s.Now,
				Attrs: map[string]any{
					"project": project, "name": b.Name, "public_grants": public,
					"public_access_prevention": pap, "uniform_access": b.IAMConfig.Uniform.Enabled,
					"policy_readable": readable,
				}})
		}
		if page.Next == "" {
			return nil
		}
		tok = page.Next
	}
}

// normTime returns an RFC 3339 time in UTC to the second, or "" when unreadable.
func normTime(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
