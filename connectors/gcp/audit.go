package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sk1122/firedrill/connector"
)

// Cloud Audit Logs say who changed a project's IAM policy. entries.list is a
// POST that only reads; the guard allows it by exact URL. The filter keeps to
// the Admin Activity log of one configured project, SetIamPolicy calls, and
// the window between the two snapshots. It needs logging.logEntries.list on
// the project (Logs Viewer, roles/logging.viewer, grants it), and the
// cloud-platform scope Firedrill already asks for is one entries.list accepts.
// Without the permission, each change keeps its window.
// https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/entries/list
// https://docs.cloud.google.com/logging/docs/audit
const entriesListURL = "https://logging.googleapis.com/v2/entries:list"

// AuditPermission is what reading the audit log needs.
const AuditPermission = "logging.logEntries.list on each project (Logs Viewer)"

// AuditSource names this source on a diff entry.
func (c *Connector) AuditSource() string { return connector.AuditGCP }

// AuditReady is true only when Google Cloud was connected on purpose.
func (c *Connector) AuditReady(s connector.Scope) bool {
	ok, _ := c.Available(s)
	return ok
}

// auditFilter is the Logging query for one project's IAM policy changes in
// the window, in the Admin Activity log only.
func auditFilter(q connector.AuditQuery) string {
	return fmt.Sprintf(`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity" AND protoPayload.methodName:%q AND timestamp>=%q AND timestamp<=%q`,
		q.Project, q.Method, q.From.UTC().Format(time.RFC3339), q.To.UTC().Format(time.RFC3339))
}

// Audit reads one page of up to 100 Admin Activity entries for one project.
func (c *Connector) Audit(ctx context.Context, s connector.Scope, q connector.AuditQuery) (connector.AuditAnswer, error) {
	if !c.AuditReady(s) || !slices.Contains(s.Project.Config.GCP.Projects, q.Project) {
		return connector.AuditAnswer{}, fmt.Errorf("%w: project %s is not a connected GCP project", connector.ErrAuditUnreadable, q.Project)
	}
	cl, quota, err := c.client(ctx, s)
	if err != nil {
		return connector.AuditAnswer{}, fmt.Errorf("%w: %v", connector.ErrAuditUnreadable, err)
	}
	a := &api{cl: cl, quota: quota}
	body := map[string]any{
		"resourceNames": []string{"projects/" + q.Project},
		"filter":        auditFilter(q),
		"orderBy":       "timestamp desc",
		"pageSize":      100,
	}
	var page struct {
		Entries []struct {
			Timestamp    string `json:"timestamp"`
			ProtoPayload struct {
				MethodName         string `json:"methodName"`
				AuthenticationInfo struct {
					PrincipalEmail string `json:"principalEmail"`
				} `json:"authenticationInfo"`
				ServiceData struct {
					PolicyDelta struct {
						BindingDeltas []struct {
							Action string `json:"action"`
							Role   string `json:"role"`
							Member string `json:"member"`
						} `json:"bindingDeltas"`
					} `json:"policyDelta"`
				} `json:"serviceData"`
			} `json:"protoPayload"`
		} `json:"entries"`
		NextPageToken string `json:"nextPageToken"`
	}
	if err := a.do(ctx, http.MethodPost, entriesListURL, body, &page); err != nil {
		if errors.Is(err, connector.ErrBlocked) {
			return connector.AuditAnswer{}, err
		}
		var ae *apiError
		if errors.As(err, &ae) {
			return connector.AuditAnswer{}, fmt.Errorf("%w: HTTP %d %s (needs %s)", connector.ErrAuditUnreadable, ae.Status, ae.Reason, AuditPermission)
		}
		return connector.AuditAnswer{}, fmt.Errorf("%w: %v", connector.ErrAuditUnreadable, err)
	}
	ans := connector.AuditAnswer{Truncated: page.NextPageToken != ""}
	for _, e := range page.Entries {
		at, err := time.Parse(time.RFC3339Nano, e.Timestamp)
		if err != nil {
			continue
		}
		actor := strings.ToLower(e.ProtoPayload.AuthenticationInfo.PrincipalEmail)
		kind := "user"
		if strings.HasSuffix(actor, ".gserviceaccount.com") {
			kind = "service_account"
		}
		params := map[string][]string{}
		for _, d := range e.ProtoPayload.ServiceData.PolicyDelta.BindingDeltas {
			if d.Action == "ADD" {
				params["binding_added"] = append(params["binding_added"], d.Role+"|"+d.Member)
			}
		}
		ans.Events = append(ans.Events, connector.AuditEvent{At: at.UTC(), Actor: actor, ActorKind: kind, Params: params, Action: e.ProtoPayload.MethodName})
	}
	return ans, nil
}

// Every connector that can say who made a change implements connector.Auditor.
var _ connector.Auditor = (*Connector)(nil)
