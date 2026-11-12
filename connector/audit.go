package connector

import (
	"context"
	"errors"
	"time"
)

// Audit sources, as a diff entry names them.
const (
	AuditGitHub = "github_audit"
	AuditGoogle = "google_reports"
	AuditGCP    = "gcp_audit"
)

// ErrAuditUnreadable marks an audit source that cannot be read with the access
// given: a plan without the audit log, a token without the permission, or a
// scope the delegation lacks. The run keeps the window for each change and
// says the source was not readable; it is never an error on anything else.
var ErrAuditUnreadable = errors.New("audit source not readable")

// AuditQuery asks one audit source for the events of one kind in the window
// between two snapshots. Only that window is ever asked for.
type AuditQuery struct {
	Source string
	From   time.Time
	To     time.Time
	// GitHub: the organization, a repo (owner/name) or empty, and one action
	// or action category for the search phrase.
	Org, Repo, Action string
	// Google Workspace Reports: the application and one event name.
	Application, Event string
	// Google Cloud: the project and the method name the filter matches.
	Project, Method string
}

// Key identifies a query, so the same question is asked once.
func (q AuditQuery) Key() string {
	return q.Source + "|" + q.Org + "|" + q.Repo + "|" + q.Action + "|" + q.Application + "|" + q.Event + "|" + q.Project + "|" + q.Method
}

// AuditEvent is one event an audit source returned. Actor and Params may hold
// an address or a login: they stay in memory, and the run turns them into
// hashed IDs before anything is written.
type AuditEvent struct {
	At time.Time
	// Actor is who made the change: a login, an address, or an app's name.
	Actor string
	// ActorKind is "user", "bot", "service_account", "app" or "key".
	ActorKind string
	// Params are what the run matches a change by, such as the repo, the
	// user an event changed, an OAuth client ID, or "role|member" for each
	// IAM binding a policy change added.
	Params map[string][]string
	// Action names the event, such as repository_ruleset.update.
	Action string
}

// AuditAnswer is one query's events. Truncated is true when the source had
// more than the one page read.
type AuditAnswer struct {
	Events    []AuditEvent
	Truncated bool
}

// Auditor is a connector that can say who made a change. Audit makes at most
// one call per query (one page). Ready says whether the source may be asked:
// the system must have been connected on purpose, as for any other read.
type Auditor interface {
	Name() string
	AuditSource() string
	AuditReady(s Scope) bool
	Audit(ctx context.Context, s Scope, q AuditQuery) (AuditAnswer, error)
}
