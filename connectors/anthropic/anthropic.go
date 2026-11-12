// Package anthropic reads the API keys of an Anthropic (Claude Console)
// organization through the Admin API, with GET only. The admin key is read
// from the environment, sent only to api.anthropic.com, and never stored.
package anthropic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// KeyEnv names the variable holding the Admin API key.
const KeyEnv = "FIREDRILL_ANTHROPIC_ADMIN_KEY"

// APIVersion is the anthropic-version header the Admin API examples send.
const APIVersion = "2026-10-21"

// Scanner names the scan record of the keys read.
const Scanner = "ai_keys"

const base = "https://api.anthropic.com"

// Connector reads Anthropic API keys.
type Connector struct{ connector.Base }

// New returns the connector.
func New() *Connector {
	return &Connector{Base: connector.Base{ConnectorName: "anthropic", Policy: connector.AnthropicPolicy(), Limit: 5, Burst: 5}}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{
		Name:       "api keys",
		Nodes:      []string{graph.KindAIKey},
		Permission: "an Admin API key (sk-ant-admin...) in " + KeyEnv + "; Firedrill sends it only with GET",
		Calls: []string{
			"GET " + base + "/v1/organizations/workspaces",
			"GET " + base + "/v1/organizations/api_keys",
		},
	}}
}

func adminKey(s connector.Scope) string {
	if s.Getenv == nil {
		return ""
	}
	return s.Getenv(KeyEnv)
}

// Available is true when Anthropic was connected on purpose and the admin key
// is set. A key in the environment alone is never enough.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if !s.Project.Config.IsConnected("anthropic") || adminKey(s) == "" {
		return false, "connect anthropic"
	}
	return true, ""
}

type client struct {
	cl  *http.Client
	key string
}

// get reads one Admin API page. The key goes only in the header, only to the
// Anthropic host, and no error repeats it or the response body.
func (a *client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if req.URL.Host == "api.anthropic.com" {
		req.Header.Set("x-api-key", a.key)
	}
	req.Header.Set("anthropic-version", APIVersion)
	resp, err := a.cl.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("GET %s: HTTP %d: the admin key was refused; it must be an Admin API key of the organization", path, resp.StatusCode)
	case resp.StatusCode/100 != 2:
		return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
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
		qq.Set("limit", "1000")
		if after != "" {
			qq.Set("after_id", after)
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

type actor struct {
	Type             string `json:"type"`
	ID               string `json:"id"`
	UserID           string `json:"user_id"`
	ServiceAccountID string `json:"service_account_id"`
}

type apiKey struct {
	ID             string  `json:"id"`
	Name           string  `json:"name"`
	Status         string  `json:"status"`
	CreatedAt      string  `json:"created_at"`
	PartialKeyHint *string `json:"partial_key_hint"`
	WorkspaceID    *string `json:"workspace_id"`
	CreatedBy      *actor  `json:"created_by"`
	Principal      *actor  `json:"principal"`
	Scope          *struct {
		Type        string `json:"type"`
		WorkspaceID string `json:"workspace_id"`
	} `json:"scope"`
}

// Collect reads every workspace's name, then every API key.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	key := adminKey(s)
	if key == "" {
		return errors.New("no admin key in " + KeyEnv)
	}
	cl := c.HTTP(s.Log)
	// A redirect could carry the key header to another host, so none is followed.
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	a := &client{cl: cl, key: key}

	names := map[string]string{}
	err := pages(ctx, a, "/v1/organizations/workspaces", url.Values{"include_archived": {"true"}, "include_default": {"true"}},
		func(w struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}) {
			names[w.ID] = w.Name
		})
	if err != nil {
		return fmt.Errorf("anthropic: %w", err)
	}
	n := 0
	err = pages(ctx, a, "/v1/organizations/api_keys", nil, func(k apiKey) {
		n++
		writeKey(k, names, s, out)
	})
	if err != nil {
		return fmt.Errorf("anthropic: %w", err)
	}
	out.Node(graph.Node{ID: graph.ScanID(Scanner, "anthropic"), Kind: graph.KindScan, Source: "anthropic", SeenAt: s.Now,
		Attrs: map[string]any{"scanner": Scanner, "scope": "anthropic", "inspected": int64(n)}})
	return nil
}

// HintShape is a provider's own redacted hint: a short prefix, three dots and
// a few last characters. Anything else is not stored, in case a full key ever
// came back in its place.
var HintShape = regexp.MustCompile(`^[A-Za-z0-9_-]{0,20}\.\.\.[A-Za-z0-9_-]{0,8}$`)

// owner names who a key acts as, or else who created it, by provider ID.
func owner(k apiKey) (kind, id string) {
	for _, a := range []*actor{k.Principal, k.CreatedBy} {
		if a == nil {
			continue
		}
		switch {
		case a.Type == "user_actor" && a.UserID != "":
			return "user", "anthropic:user/" + a.UserID
		case a.Type == "service_account_actor" && a.ServiceAccountID != "":
			return "service_account", "anthropic:service-account/" + a.ServiceAccountID
		case a.Type == "user" && a.ID != "":
			return "user", "anthropic:user/" + a.ID
		case a.Type == "service_account" && a.ID != "":
			return "service_account", "anthropic:service-account/" + a.ID
		}
	}
	return "unknown", ""
}

// writeKey writes one key. The Admin API shows no spend limit for a Claude
// Console organization, workspace or key, so the limit is never readable here:
// a cap can only be declared in ai-keys.yaml.
func writeKey(k apiKey, names map[string]string, s connector.Scope, out graph.Writer) {
	ws := ""
	if k.Scope != nil {
		ws = k.Scope.WorkspaceID
	}
	if ws == "" && k.WorkspaceID != nil {
		ws = *k.WorkspaceID
	}
	hint := ""
	if k.PartialKeyHint != nil && HintShape.MatchString(*k.PartialKeyHint) {
		hint = *k.PartialKeyHint
	}
	kind, who := owner(k)
	out.Node(graph.Node{ID: graph.ID("anthropic:key/" + k.ID), Kind: graph.KindAIKey, Source: "anthropic", SeenAt: s.Now,
		Attrs: map[string]any{
			"provider": "anthropic", "key_id": k.ID, "hint": hint, "name": k.Name, "status": k.Status,
			"workspace": ws, "workspace_name": names[ws], "project": "", "project_name": "",
			"owner_kind": kind, "owner": who, "has_owner": who != "",
			"limit_readable": false, "capped": false, "limit_scope": "unknown",
			"created": stamp(k.CreatedAt),
		}})
}

func stamp(ts string) string {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
