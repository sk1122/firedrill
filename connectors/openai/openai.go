// Package openai reads the project API keys and hard spend limits of an
// OpenAI organization through the Administration API, with GET only. The admin
// key is read from the environment, sent only to api.openai.com, and never
// stored.
package openai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// KeyEnv names the variable holding the admin key.
const KeyEnv = "FIREDRILL_OPENAI_ADMIN_KEY"

// Scanner names the scan record of the keys read.
const Scanner = "ai_keys"

const base = "https://api.openai.com"

// Connector reads OpenAI project API keys.
type Connector struct{ connector.Base }

// New returns the connector.
func New() *Connector {
	return &Connector{Base: connector.Base{ConnectorName: "openai", Policy: connector.OpenAIPolicy(), Limit: 5, Burst: 5}}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{
		Name:       "project api keys",
		Nodes:      []string{graph.KindAIKey},
		Permission: "an Admin key in " + KeyEnv + "; Firedrill sends it only with GET",
		Calls: []string{
			"GET " + base + "/v1/organization/spend_limit",
			"GET " + base + "/v1/organization/projects",
			"GET " + base + "/v1/organization/projects/{project}/api_keys",
			"GET " + base + "/v1/organization/projects/{project}/spend_limit",
		},
	}}
}

func adminKey(s connector.Scope) string {
	if s.Getenv == nil {
		return ""
	}
	return s.Getenv(KeyEnv)
}

// Available is true when OpenAI was connected on purpose and the admin key is
// set. A key in the environment alone is never enough.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if !s.Project.Config.IsConnected("openai") || adminKey(s) == "" {
		return false, "connect openai"
	}
	return true, ""
}

// statusError is a response that was not a success.
type statusError struct {
	path string
	code int
}

func (e *statusError) Error() string {
	if e.code == http.StatusUnauthorized || e.code == http.StatusForbidden {
		return fmt.Sprintf("GET %s: HTTP %d: the admin key was refused; it must be an Admin key of the organization", e.path, e.code)
	}
	return fmt.Sprintf("GET %s: HTTP %d", e.path, e.code)
}

type client struct {
	cl  *http.Client
	key string
}

// get reads one page. The key goes only in the header, only to the OpenAI
// host, and no error repeats it or the response body.
func (a *client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if req.URL.Host == "api.openai.com" {
		req.Header.Set("Authorization", "Bearer "+a.key)
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
		return &statusError{path: path, code: resp.StatusCode}
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("GET %s: unreadable response", path)
	}
	return nil
}

// pages reads every page of a list, following last_id while has_more.
func pages[T any](ctx context.Context, a *client, path string, q url.Values, each func(T)) error {
	after := ""
	for {
		qq := url.Values{}
		for k, v := range q {
			qq[k] = v
		}
		qq.Set("limit", "100")
		if after != "" {
			qq.Set("after", after)
		}
		var page struct {
			Data    []T    `json:"data"`
			HasMore bool   `json:"has_more"`
			LastID  string `json:"last_id"`
		}
		if err := a.get(ctx, path, qq, &page); err != nil {
			return err
		}
		for _, d := range page.Data {
			each(d)
		}
		if !page.HasMore || page.LastID == "" || page.LastID == after {
			return nil
		}
		after = page.LastID
	}
}

// limit is what one spend limit read showed.
type limit struct {
	known, capped bool
}

// spendLimit reads a hard spend limit. A threshold above zero is a cap; zero is
// no cap. Any refusal, or a 404, which the reference does not explain, leaves it
// unknown: missing evidence is never read as a cap or as no cap.
func spendLimit(ctx context.Context, a *client, path string) (limit, error) {
	var l struct {
		Object          string `json:"object"`
		ThresholdAmount *int64 `json:"threshold_amount"`
	}
	if err := a.get(ctx, path, nil, &l); err != nil {
		var se *statusError
		if errors.As(err, &se) {
			return limit{}, nil
		}
		return limit{}, err
	}
	if l.ThresholdAmount == nil {
		return limit{}, nil
	}
	return limit{known: true, capped: *l.ThresholdAmount > 0}, nil
}

type project struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

type apiKey struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	RedactedValue      string `json:"redacted_value"`
	CreatedAt          int64  `json:"created_at"`
	ExpiresAt          *int64 `json:"expires_at"`
	OwnerProjectAccess string `json:"owner_project_access"`
	Owner              struct {
		Type string `json:"type"`
		User *struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		ServiceAccount *struct {
			ID string `json:"id"`
		} `json:"service_account"`
	} `json:"owner"`
}

// Collect reads the organization's spend limit, then each active project's
// keys and spend limit. A project whose keys cannot be listed makes the result
// partial.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	key := adminKey(s)
	if key == "" {
		return errors.New("no admin key in " + KeyEnv)
	}
	cl := c.HTTP(s.Log)
	// A redirect could carry the key to another host, so none is followed.
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a := &client{cl: cl, key: key}

	var projects []project
	if err := pages(ctx, a, "/v1/organization/projects", nil, func(p project) { projects = append(projects, p) }); err != nil {
		return fmt.Errorf("openai: %w", err)
	}
	org, err := spendLimit(ctx, a, "/v1/organization/spend_limit")
	if err != nil {
		return fmt.Errorf("openai: %w", err)
	}
	var partial []string
	n := 0
	for _, p := range projects {
		if p.Status == "archived" {
			continue
		}
		var keys []apiKey
		err := pages(ctx, a, "/v1/organization/projects/"+url.PathEscape(p.ID)+"/api_keys",
			url.Values{"owner_project_access": {"any"}}, func(k apiKey) { keys = append(keys, k) })
		if err != nil {
			var se *statusError
			if !errors.As(err, &se) {
				return fmt.Errorf("openai: %w", err)
			}
			partial = append(partial, "keys of project "+p.ID+" could not be listed")
			continue
		}
		proj, err := spendLimit(ctx, a, "/v1/organization/projects/"+url.PathEscape(p.ID)+"/spend_limit")
		if err != nil {
			return fmt.Errorf("openai: %w", err)
		}
		for _, k := range keys {
			n++
			writeKey(k, p, org, proj, s, out)
		}
	}
	attrs := map[string]any{"scanner": Scanner, "scope": "openai", "inspected": int64(n)}
	if len(partial) > 0 {
		attrs["partial"] = strings.Join(partial, "; ")
	}
	out.Node(graph.Node{ID: graph.ScanID(Scanner, "openai"), Kind: graph.KindScan, Source: "openai", SeenAt: s.Now, Attrs: attrs})
	return nil
}

// HintShape is a provider's own redacted value: a short prefix, three dots and
// a few last characters. Anything else is not stored.
var HintShape = regexp.MustCompile(`^[A-Za-z0-9_-]{0,20}\.\.\.[A-Za-z0-9_-]{0,8}$`)

// writeKey writes one key. Its owner is a hashed person ID when OpenAI gives
// the owner's email; the email itself is never kept. An owner who no longer has
// access to the project does not count as an owner.
func writeKey(k apiKey, p project, org, proj limit, s connector.Scope, out graph.Writer) {
	kind, who := "unknown", ""
	switch {
	case k.Owner.User != nil && k.Owner.User.Email != "":
		kind, who = "user", "person:"+s.Hasher.Email(k.Owner.User.Email)
	case k.Owner.User != nil && k.Owner.User.ID != "":
		kind, who = "user", "openai:user/"+k.Owner.User.ID
	case k.Owner.ServiceAccount != nil && k.Owner.ServiceAccount.ID != "":
		kind, who = "service_account", "openai:service-account/"+k.Owner.ServiceAccount.ID
	}
	status := "active"
	if k.ExpiresAt != nil && *k.ExpiresAt > 0 && time.Unix(*k.ExpiresAt, 0).Before(s.Now) {
		status = "expired"
	}
	capped := org.capped || proj.capped
	readable := capped || (org.known && proj.known)
	scope := "unknown"
	switch {
	case org.capped:
		scope = "organization"
	case proj.capped:
		scope = "project"
	case readable:
		scope = "none"
	}
	hint := ""
	if HintShape.MatchString(k.RedactedValue) {
		hint = k.RedactedValue
	}
	created := ""
	if k.CreatedAt > 0 {
		created = time.Unix(k.CreatedAt, 0).UTC().Format(time.RFC3339)
	}
	out.Node(graph.Node{ID: graph.ID("openai:key/" + p.ID + "/" + k.ID), Kind: graph.KindAIKey, Source: "openai", SeenAt: s.Now,
		Attrs: map[string]any{
			"provider": "openai", "key_id": k.ID, "hint": hint, "name": k.Name, "status": status,
			"workspace": "", "workspace_name": "", "project": p.ID, "project_name": p.Name,
			"owner_kind": kind, "owner": who, "has_owner": who != "" && k.OwnerProjectAccess != "inactive",
			"limit_readable": readable, "capped": capped, "limit_scope": scope,
			"created": created,
		}})
}
