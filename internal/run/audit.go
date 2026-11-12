package run

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// DefaultAuditCap bounds how many audit calls one run makes. Changes past it
// keep the window between the two snapshots, and the diff says how many were
// not asked.
const DefaultAuditCap = 50

// AuditNote records what the audit step did, in the stored diff.
type AuditNote struct {
	// Asked names the sources asked at least once.
	Asked []string `json:"asked,omitempty"`
	// NotReadable names each source that could not be read and why. Its
	// changes keep the window.
	NotReadable []string `json:"not_readable,omitempty"`
	Calls       int      `json:"calls"`
	// NotAsked counts questions left unasked because the cap was reached.
	NotAsked int `json:"not_asked,omitempty"`
	Cap      int `json:"cap"`
	// Truncated names questions whose answer had more than the one page read.
	Truncated int `json:"truncated,omitempty"`
}

// auditAsk is one question for one change: the query, and how to tell which
// of its events made this change.
type auditAsk struct {
	q     connector.AuditQuery
	match func(connector.AuditEvent) bool
}

// The GitHub audit log actions asked about, by kind of change. Rulesets and
// branch protection come from the organization audit log's documented
// categories; member changes from documented events.
// https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/audit-log-events-for-your-organization
var (
	githubRuleActions   = []string{"repository_ruleset", "protected_branch"}
	githubAccessActions = []string{"repo.add_member", "repo.update_member", "team.add_repository", "team.update_repository_permission"}
	githubOrgActions    = []string{"org.update_member", "org.add_member", "org.add_outside_collaborator"}
)

// asksFor works out which audit questions could name who made a change. A
// change no source covers gets none, and keeps the window.
func asksFor(ch graph.Change, org string, h graph.Hasher, from, to time.Time) []auditAsk {
	var out []auditAsk
	gh := func(repo string, actions []string, match func(connector.AuditEvent) bool) {
		if org == "" {
			return
		}
		for _, a := range actions {
			out = append(out, auditAsk{q: connector.AuditQuery{Source: connector.AuditGitHub, Org: org, Repo: repo, Action: a, From: from, To: to}, match: match})
		}
	}
	google := func(app string, events []string, match func(connector.AuditEvent) bool) {
		for _, e := range events {
			out = append(out, auditAsk{q: connector.AuditQuery{Source: connector.AuditGoogle, Application: app, Event: e, From: from, To: to}, match: match})
		}
	}
	gcp := func(project string, match func(connector.AuditEvent) bool) {
		if project == "" {
			return
		}
		out = append(out, auditAsk{q: connector.AuditQuery{Source: connector.AuditGCP, Project: project, Method: "SetIamPolicy", From: from, To: to}, match: match})
	}
	ids := []graph.ID{ch.Subject}
	if ch.Edge != nil {
		ids = append(ids, ch.Edge.From, ch.Edge.To)
	}
	repoOf := func() string {
		for _, id := range ids {
			s := string(id)
			for _, p := range []string{"github:branch-rule/", "github:repo/"} {
				if rest, ok := strings.CutPrefix(s, p); ok {
					parts := strings.Split(rest, "/")
					if len(parts) >= 2 {
						return parts[0] + "/" + parts[1]
					}
				}
			}
		}
		return ""
	}
	byRepo := func(repo string) func(connector.AuditEvent) bool {
		return func(e connector.AuditEvent) bool { return hasParam(e, "repo", strings.ToLower(repo)) }
	}
	byGitHubUser := func(id graph.ID) func(connector.AuditEvent) bool {
		return func(e connector.AuditEvent) bool {
			for _, u := range e.Params["user"] {
				if graph.ID("github:user/"+h.Sum(strings.ToLower(u))) == id {
					return true
				}
			}
			return false
		}
	}
	switch {
	case ch.Kind == graph.KindBranchRule || (ch.Edge != nil && ch.Edge.Kind == graph.EdgeCanBypass):
		if repo := repoOf(); repo != "" {
			gh(repo, githubRuleActions, byRepo(repo))
		}
	case ch.Edge != nil && ch.Edge.Source == "github" && (ch.Edge.Kind == graph.EdgeWritesTo || ch.Edge.Kind == graph.EdgeAdminOf) &&
		strings.HasPrefix(string(ch.Edge.To), "github:repo/"):
		repo := repoOf()
		user := ch.Edge.From
		gh(repo, githubAccessActions, func(e connector.AuditEvent) bool {
			return byRepo(repo)(e) && (len(e.Params["user"]) == 0 || byGitHubUser(user)(e))
		})
	case ch.Kind == graph.KindGitHubUser:
		gh("", githubOrgActions, byGitHubUser(ch.Subject))
	case ch.Kind == graph.KindIdentityUser && (ch.Attr == "is_admin" || ch.Attr == "is_delegated_admin" || ch.Type == graph.ChangeNewAdmin):
		google("admin", []string{"GRANT_ADMIN_PRIVILEGE", "ASSIGN_ROLE"}, byGoogleParam(h, "USER_EMAIL", ch.Subject, "google:user/"))
	case ch.Kind == graph.KindIdentityUser && ch.Attr == "suspended":
		google("admin", []string{"SUSPEND_USER", "UNSUSPEND_USER"}, byGoogleParam(h, "USER_EMAIL", ch.Subject, "google:user/"))
	case ch.Kind == graph.KindOAuthApp || (ch.Edge != nil && ch.Edge.Kind == graph.EdgeGrantedTo):
		id := ch.Subject
		if ch.Edge != nil {
			id = ch.Edge.From
		}
		client := strings.TrimPrefix(string(id), "google:oauth-app/")
		google("token", []string{"authorize"}, func(e connector.AuditEvent) bool { return hasParam(e, "client_id", client) })
	case ch.Kind == graph.KindGoogleGroup || (ch.Edge != nil && ch.Edge.Kind == graph.EdgeMemberOf && ch.Edge.Source == "google"):
		group := ch.Subject
		if ch.Edge != nil {
			group = ch.Edge.To
		}
		google("groups", []string{"add_user"}, byGoogleParam(h, "group_email", group, "google:group/"))
	case ch.Kind == graph.KindGCPBinding || ch.Kind == graph.KindGCPProject ||
		(ch.Edge != nil && (ch.Edge.Kind == graph.EdgeViaGroup || strings.HasPrefix(string(ch.Edge.To), "gcp:binding/"))):
		binding := ch.Subject
		if ch.Edge != nil {
			binding = ch.Edge.To
		}
		project := gcpProjectOf(binding)
		gcp(project, func(e connector.AuditEvent) bool {
			deltas := e.Params["binding_added"]
			if len(deltas) == 0 || !strings.HasPrefix(string(binding), "gcp:binding/") {
				// No delta to match by: every policy change in the project
				// and window is a candidate.
				return true
			}
			for _, d := range deltas {
				role, member, _ := strings.Cut(d, "|")
				if graph.ID("gcp:binding/"+project+"/"+role+"/"+h.Sum(member)) == binding {
					return true
				}
			}
			return false
		})
	}
	return out
}

func gcpProjectOf(id graph.ID) string {
	s := string(id)
	for _, p := range []string{"gcp:binding/", "gcp:project/"} {
		if rest, ok := strings.CutPrefix(s, p); ok {
			proj, _, _ := strings.Cut(rest, "/")
			return proj
		}
	}
	return ""
}

func hasParam(e connector.AuditEvent, name, want string) bool {
	for _, v := range e.Params[name] {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// byGoogleParam matches an event whose parameter holds the address an ID was
// hashed from. The address is hashed here and never compared in the clear.
func byGoogleParam(h graph.Hasher, name string, id graph.ID, prefix string) func(connector.AuditEvent) bool {
	return func(e connector.AuditEvent) bool {
		for _, v := range e.Params[name] {
			if graph.ID(prefix+h.Email(v)) == id {
				return true
			}
		}
		return false
	}
}

// actorID turns an event's actor into what a diff may store: a person's
// hashed ID when the account links to one, the account's hashed ID otherwise,
// or a label for an app, bot, key or service account. Never the address or
// login itself.
func actorID(e connector.AuditEvent, source string, g graph.Reader, h graph.Hasher) string {
	owner := func(account graph.ID) string {
		for _, edge := range g.Edges(graph.EdgeSamePerson) {
			if edge.To == account {
				return string(edge.From)
			}
		}
		return ""
	}
	actor := strings.TrimSpace(e.Actor)
	switch e.ActorKind {
	case "bot":
		return "GitHub app " + strings.TrimSuffix(actor, "[bot]")
	case "app":
		if actor == "" {
			return "an app"
		}
		return "app " + actor
	case "key":
		return "an API key"
	case "service_account":
		local, domain, _ := strings.Cut(strings.ToLower(actor), "@")
		project, _, _ := strings.Cut(domain, ".")
		return "service account " + local + " (" + project + ")"
	}
	if actor == "" {
		return ""
	}
	if source == connector.AuditGitHub {
		account := graph.ID("github:user/" + h.Sum(strings.ToLower(actor)))
		if p := owner(account); p != "" {
			return p
		}
		return string(account)
	}
	hash := h.Email(actor)
	if p := owner(graph.ID("google:user/" + hash)); p != "" {
		return p
	}
	if _, ok := g.Get(graph.ID("person:" + hash)); ok {
		return "person:" + hash
	}
	return "google:user/" + hash
}

// auditDiff asks the connected audit sources who made each change, between
// the two snapshots only, and fills in the actor where one answers. It never
// fails the run: a source that cannot be read is named, and its changes keep
// the window. It returns nil when no audit source is connected.
func auditDiff(ctx context.Context, c Config, res *Result, d *graph.DiffResult) *AuditNote {
	auditors := c.Auditors
	if auditors == nil {
		for _, conn := range c.Connectors {
			if a, ok := conn.(connector.Auditor); ok {
				auditors = append(auditors, a)
			}
		}
	}
	ready := map[string]connector.Auditor{}
	for _, a := range auditors {
		// Only a source whose system was connected on purpose, read this run
		// and not failed is ever asked.
		if !res.Available[a.Name()] || res.Failures[a.Name()] != "" || !contains(res.ran, a.Name()) || !a.AuditReady(c.Scope) {
			continue
		}
		ready[a.AuditSource()] = a
	}
	if len(ready) == 0 || len(d.Changes) == 0 {
		return nil
	}
	limit := c.AuditCap
	if limit <= 0 {
		limit = DefaultAuditCap
	}
	note := &AuditNote{Cap: limit}
	org := ""
	if c.Project != nil {
		org = c.Project.Config.GitHub.Org
	}
	h := c.Scope.Hasher
	answers := map[string]connector.AuditAnswer{}
	unreadable := map[string]string{}
	asked := map[string]bool{}
	notAsked := map[string]bool{}
	type found struct {
		at    time.Time
		actor string
	}
	for i := range d.Changes {
		ch := &d.Changes[i]
		var hits []found
		source := ""
		for _, ask := range asksFor(*ch, org, h, d.From, d.To) {
			a, ok := ready[ask.q.Source]
			if !ok || unreadable[ask.q.Source] != "" {
				continue
			}
			key := ask.q.Key()
			ans, done := answers[key]
			if !done {
				if note.Calls >= limit {
					if !notAsked[key] {
						notAsked[key] = true
						note.NotAsked++
					}
					continue
				}
				note.Calls++
				asked[ask.q.Source] = true
				var err error
				ans, err = a.Audit(ctx, c.Scope, ask.q)
				if err != nil {
					if errors.Is(err, connector.ErrBlocked) {
						res.Fatal = "the read-only guard stopped this run: " + err.Error()
						return note
					}
					unreadable[ask.q.Source] = shortErr(err)
					continue
				}
				if ans.Truncated {
					note.Truncated++
				}
				answers[key] = ans
			}
			for _, e := range ans.Events {
				// Only the window between the two snapshots counts.
				if e.At.Before(d.From) || e.At.After(d.To) || !ask.match(e) {
					continue
				}
				if id := actorID(e, ask.q.Source, res.Graph, h); id != "" {
					hits = append(hits, found{e.At, id})
					source = ask.q.Source
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		// The latest event names the actor; others follow, each once.
		sort.SliceStable(hits, func(a, b int) bool { return hits[a].at.After(hits[b].at) })
		seen := map[string]bool{}
		var actors []string
		for _, f := range hits {
			if !seen[f.actor] {
				seen[f.actor] = true
				actors = append(actors, f.actor)
			}
		}
		at := hits[0].at.UTC()
		ch.Actor, ch.ActorSource, ch.ActedAt = actors[0], source, &at
		rest := actors[1:]
		if len(rest) > 2 {
			ch.MoreActors = len(rest) - 2
			rest = rest[:2]
		}
		ch.OtherActors = rest
	}
	for s := range asked {
		note.Asked = append(note.Asked, s)
	}
	for s, why := range unreadable {
		note.NotReadable = append(note.NotReadable, s+": "+why)
	}
	for s := range ready {
		if !asked[s] && unreadable[s] == "" && note.NotAsked > 0 {
			note.NotReadable = append(note.NotReadable, s+": not asked, the cap of audit calls was reached")
		}
	}
	sort.Strings(note.Asked)
	sort.Strings(note.NotReadable)
	return note
}

// shortErr keeps an error's message short for the stored note. Connectors
// return messages with no address, login or token in them.
func shortErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return fmt.Sprint(s)
}
