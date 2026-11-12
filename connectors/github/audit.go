package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sk1122/firedrill/connector"
)

// The organization audit log says who changed a ruleset, branch protection,
// repo access or an org role. It is optional: it needs GitHub Enterprise
// Cloud and an organization owner's token with read:audit_log (classic), so
// most tokens cannot read it, and then each change keeps its window.
// https://docs.github.com/en/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization
// https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/reviewing-the-audit-log-for-your-organization

// AuditPermission is what reading the audit log needs.
const AuditPermission = "GitHub Enterprise Cloud; an organization owner's token with read:audit_log"

// AuditSource names this source on a diff entry.
func (c *Connector) AuditSource() string { return connector.AuditGitHub }

// AuditReady is true only when GitHub was connected on purpose.
func (c *Connector) AuditReady(s connector.Scope) bool {
	ok, _ := c.Available(s)
	return ok
}

// auditPhrase builds the search phrase: one action or category, the repo when
// there is one, and the window between the two snapshots, nothing wider.
func auditPhrase(q connector.AuditQuery) string {
	parts := []string{"action:" + q.Action}
	if q.Repo != "" {
		parts = append(parts, "repo:"+q.Repo)
	}
	parts = append(parts, "created:"+q.From.UTC().Format("2006-01-02T15:04:05+00:00")+".."+q.To.UTC().Format("2006-01-02T15:04:05+00:00"))
	return strings.Join(parts, " ")
}

// Audit asks the organization audit log for one action in the window. It
// reads one page of up to 100 events.
func (c *Connector) Audit(ctx context.Context, s connector.Scope, q connector.AuditQuery) (connector.AuditAnswer, error) {
	if !c.AuditReady(s) || q.Org == "" {
		return connector.AuditAnswer{}, fmt.Errorf("%w: GitHub is not connected", connector.ErrAuditUnreadable)
	}
	v := url.Values{}
	v.Set("phrase", auditPhrase(q))
	v.Set("include", "web")
	v.Set("order", "desc")
	v.Set("per_page", "100")
	u := "https://api.github.com/orgs/" + url.PathEscape(q.Org) + "/audit-log?" + v.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return connector.AuditAnswer{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+s.Token)
	resp, err := c.HTTP(s.Log).Do(req)
	if err != nil {
		return connector.AuditAnswer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return connector.AuditAnswer{}, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		return connector.AuditAnswer{}, fmt.Errorf("%w: HTTP %d (the audit log needs %s)", connector.ErrAuditUnreadable, resp.StatusCode, AuditPermission)
	case resp.StatusCode/100 != 2:
		return connector.AuditAnswer{}, fmt.Errorf("%w: HTTP %d", connector.ErrAuditUnreadable, resp.StatusCode)
	}
	var events []map[string]any
	if err := json.Unmarshal(body, &events); err != nil {
		return connector.AuditAnswer{}, fmt.Errorf("%w: the audit log answer was not a list", connector.ErrAuditUnreadable)
	}
	ans := connector.AuditAnswer{Truncated: strings.Contains(resp.Header.Get("Link"), `rel="next"`)}
	for _, e := range events {
		at, ok := auditTime(e["@timestamp"])
		if !ok {
			if at, ok = auditTime(e["created_at"]); !ok {
				continue
			}
		}
		actor, _ := e["actor"].(string)
		kind := "user"
		if strings.HasSuffix(actor, "[bot]") {
			kind = "bot"
		}
		params := map[string][]string{}
		for _, k := range []string{"repo", "user"} {
			if v, _ := e[k].(string); v != "" {
				params[k] = []string{strings.ToLower(v)}
			}
		}
		action, _ := e["action"].(string)
		ans.Events = append(ans.Events, connector.AuditEvent{At: at, Actor: actor, ActorKind: kind, Params: params, Action: action})
	}
	return ans, nil
}

// auditTime reads an event's time, which the schema gives as an integer: a
// count of milliseconds since the epoch (seconds if small).
func auditTime(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok || f <= 0 {
		return time.Time{}, false
	}
	if f > 1e12 {
		return time.UnixMilli(int64(f)).UTC(), true
	}
	return time.Unix(int64(f), 0).UTC(), true
}

// Every connector that can say who made a change implements connector.Auditor.
var _ connector.Auditor = (*Connector)(nil)
