package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"

	"github.com/sk1122/firedrill/connector"
)

// ReportsScope is the read-only scope of the Admin SDK Reports API, which
// says who granted an admin role, suspended a user, authorized an OAuth app
// or added a group member. It is optional: without it in the domain-wide
// delegation, each change keeps its window.
// https://developers.google.com/workspace/admin/reports/reference/rest/v1/activities/list
const ReportsScope = "https://www.googleapis.com/auth/admin.reports.audit.readonly"

// AuditSource names this source on a diff entry.
func (c *Connector) AuditSource() string { return connector.AuditGoogle }

// AuditReady is true only when Google Workspace was connected on purpose.
func (c *Connector) AuditReady(s connector.Scope) bool {
	ok, _ := c.Available(s)
	return ok
}

// reportsURL is the activities.list call for one application and event in
// the window. No address is put in the URL: events are matched afterwards by
// hashing the parameter they name.
func reportsURL(q connector.AuditQuery) string {
	v := url.Values{}
	v.Set("eventName", q.Event)
	v.Set("startTime", q.From.UTC().Format(time.RFC3339))
	v.Set("endTime", q.To.UTC().Format(time.RFC3339))
	v.Set("maxResults", "1000")
	return "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/" + url.PathEscape(q.Application) + "?" + v.Encode()
}

// Audit reads one page of one application's events of one name in the window.
func (c *Connector) Audit(ctx context.Context, s connector.Scope, q connector.AuditQuery) (connector.AuditAnswer, error) {
	if !c.AuditReady(s) {
		return connector.AuditAnswer{}, fmt.Errorf("%w: Google Workspace is not connected", connector.ErrAuditUnreadable)
	}
	key, err := os.ReadFile(keyPath(s))
	if err != nil {
		return connector.AuditAnswer{}, fmt.Errorf("%w: the service account key could not be read", connector.ErrAuditUnreadable)
	}
	conf, err := googleoauth.JWTConfigFromJSON(key, ReportsScope)
	if err != nil {
		return connector.AuditAnswer{}, fmt.Errorf("%w: the service account key could not be parsed", connector.ErrAuditUnreadable)
	}
	conf.Subject = s.Project.Config.Google.AdminEmail
	cl := conf.Client(context.WithValue(ctx, oauth2.HTTPClient, c.HTTP(s.Log)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reportsURL(q), nil)
	if err != nil {
		return connector.AuditAnswer{}, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		if errors.Is(err, connector.ErrBlocked) {
			return connector.AuditAnswer{}, err
		}
		// A scope the delegation lacks fails the token exchange.
		return connector.AuditAnswer{}, fmt.Errorf("%w: the token for %s was refused; add it to the domain-wide delegation", connector.ErrAuditUnreadable, ReportsScope)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return connector.AuditAnswer{}, err
	}
	if resp.StatusCode/100 != 2 {
		return connector.AuditAnswer{}, fmt.Errorf("%w: HTTP %d (needs %s in the domain-wide delegation)", connector.ErrAuditUnreadable, resp.StatusCode, ReportsScope)
	}
	var page struct {
		Items []struct {
			ID struct {
				Time json.RawMessage `json:"time"`
			} `json:"id"`
			Actor struct {
				Email           string `json:"email"`
				CallerType      string `json:"callerType"`
				ApplicationInfo struct {
					ApplicationName string `json:"applicationName"`
				} `json:"applicationInfo"`
			} `json:"actor"`
			Events []struct {
				Name       string `json:"name"`
				Parameters []struct {
					Name       string   `json:"name"`
					Value      string   `json:"value"`
					MultiValue []string `json:"multiValue"`
				} `json:"parameters"`
			} `json:"events"`
		} `json:"items"`
		NextPageToken string `json:"nextPageToken"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return connector.AuditAnswer{}, fmt.Errorf("%w: the reports answer could not be read", connector.ErrAuditUnreadable)
	}
	ans := connector.AuditAnswer{Truncated: page.NextPageToken != ""}
	for _, it := range page.Items {
		at, ok := reportTime(it.ID.Time)
		if !ok {
			continue
		}
		actor, kind := strings.ToLower(it.Actor.Email), "user"
		switch {
		case it.Actor.CallerType == "KEY":
			actor, kind = "", "key"
		case actor == "" && it.Actor.ApplicationInfo.ApplicationName != "":
			actor, kind = it.Actor.ApplicationInfo.ApplicationName, "app"
		case strings.HasSuffix(actor, ".gserviceaccount.com"):
			kind = "service_account"
		}
		for _, ev := range it.Events {
			if ev.Name != q.Event {
				continue
			}
			params := map[string][]string{}
			for _, p := range ev.Parameters {
				vals := p.MultiValue
				if p.Value != "" {
					vals = append(vals, p.Value)
				}
				params[p.Name] = append(params[p.Name], vals...)
			}
			ans.Events = append(ans.Events, connector.AuditEvent{At: at, Actor: actor, ActorKind: kind, Params: params, Action: q.Application + "." + ev.Name})
		}
	}
	return ans, nil
}

// reportTime reads id.time, an RFC 3339 string or a number of seconds.
func reportTime(raw json.RawMessage) (time.Time, bool) {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			return t.UTC(), true
		}
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.Unix(n, 0).UTC(), true
		}
		return time.Time{}, false
	}
	var n float64
	if json.Unmarshal(raw, &n) == nil && n > 0 {
		return time.Unix(int64(n), 0).UTC(), true
	}
	return time.Time{}, false
}

// Every connector that can say who made a change implements connector.Auditor.
var _ connector.Auditor = (*Connector)(nil)
