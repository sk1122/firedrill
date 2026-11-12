package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	gh "github.com/google/go-github/v93/github"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// Scanners of the people collection. The org record says whether members and
// teams were read; each repo's record says whether its collaborators and
// bypass list were.
const (
	PeopleScanner     = "github_people"
	RepoPeopleScanner = "github_repo_people"
)

// privateActors is the branch rule's private key holding its bypass actors as
// read, logins included.
const privateActors = "bypass_actors"

// Kinds of bypass actor, as read from classic protection or a ruleset.
const (
	actorUser      = "user"
	actorTeam      = "team"
	actorApp       = "app"
	actorDeployKey = "deploy_key"
	actorRole      = "repo_role"
	actorOrgAdmin  = "org_admin"
)

// How a bypass arises, kept on each resolved row.
const (
	viaClassic           = "classic_allowance"
	viaAdminsNotEnforced = "admins_not_enforced"
)

// bypassActor is one actor that may skip review on a default branch, before
// it is resolved to people. Name is a login for a user, which is personal, so
// the list is kept only in a node's Private.
type bypassActor struct {
	Kind string
	ID   int64
	Name string // login, team or app slug, or role: admin, maintain or write
	Via  string
	Mode string // a ruleset's bypass_mode, empty for classic protection
}

// repoRoles maps the IDs GitHub gives built-in repository roles in a ruleset's
// bypass list. Any other ID is a custom role, which is not resolved.
var repoRoles = map[int64]string{5: "admin", 2: "maintain", 4: "write"}

func classicAllowances(a *gh.BypassPullRequestAllowances) []bypassActor {
	var out []bypassActor
	for _, u := range a.Users {
		out = append(out, bypassActor{Kind: actorUser, ID: u.GetID(), Name: u.GetLogin(), Via: viaClassic})
	}
	for _, t := range a.Teams {
		out = append(out, bypassActor{Kind: actorTeam, ID: t.GetID(), Name: t.GetSlug(), Via: viaClassic})
	}
	for _, app := range a.Apps {
		name := app.GetSlug()
		if name == "" {
			name = app.GetName()
		}
		out = append(out, bypassActor{Kind: actorApp, ID: app.GetID(), Name: name, Via: viaClassic})
	}
	return out
}

// parseActors reads a ruleset's bypass_actors as GitHub returns them, which is
// also what the admin export stores.
func parseActors(raw []json.RawMessage, via string) []bypassActor {
	out := []bypassActor{}
	for _, r := range raw {
		var a struct {
			ActorID   *int64 `json:"actor_id"`
			ActorType string `json:"actor_type"`
			Mode      string `json:"bypass_mode"`
		}
		_ = json.Unmarshal(r, &a)
		id := int64(0)
		if a.ActorID != nil {
			id = *a.ActorID
		}
		b := bypassActor{ID: id, Via: via, Mode: a.Mode}
		switch a.ActorType {
		case "Team":
			b.Kind = actorTeam
		case "Integration":
			b.Kind = actorApp
		case "OrganizationAdmin":
			b.Kind = actorOrgAdmin
		case "DeployKey":
			b.Kind = actorDeployKey
		case "RepositoryRole":
			b.Kind, b.Name = actorRole, repoRoles[id]
		default:
			// An actor type this version does not know cannot be resolved.
			b.Kind = actorRole
		}
		out = append(out, b)
	}
	return out
}

// permRank orders repo permissions, lowest first.
var permRank = map[string]int{"pull": 1, "read": 1, "triage": 2, "push": 3, "write": 3, "maintain": 4, "admin": 5}

// highestPermission names a collaborator's effective permission.
func highestPermission(u *gh.User) string {
	if p := u.GetPermissions(); p != nil {
		for _, c := range []struct {
			name string
			on   *bool
		}{{"admin", p.Admin}, {"maintain", p.Maintain}, {"push", p.Push}, {"triage", p.Triage}, {"pull", p.Pull}} {
			if c.on != nil && *c.on {
				return c.name
			}
		}
	}
	switch rn := u.GetRoleName(); rn {
	case "write":
		return "push"
	case "read":
		return "pull"
	default:
		return rn
	}
}

// ghPerson is one account as the people collection sees it.
type ghPerson struct {
	login, kind string
	siteAdmin   *bool
	orgRole     string
	teams       map[string]bool
}

type ghTeam struct {
	id                    int64
	slug, privacy, parent string
	members               map[string]bool // lowercased logins, child teams' members included
	repos                 map[string]string
}

// peopleRun holds what one people collection read.
type peopleRun struct {
	ctx    context.Context
	cl     *gh.Client
	s      connector.Scope
	out    graph.Writer
	owner  string
	isOrg  bool
	people map[string]*ghPerson // by lowercased login
	admins []string
	teams  map[string]*ghTeam // by slug
	byID   map[int64]string
	apps   map[string]bypassActor
}

// failure is a read the token was refused, recorded on a scan record rather
// than returned, so the rest of GitHub still runs.
type failure struct{ msg string }

func (f failure) Error() string { return f.msg }

// pages calls list until GitHub reports no next page, 100 a page.
func pages(list func(page int) (*gh.Response, error)) (*gh.Response, error) {
	page := 1
	for {
		resp, err := list(page)
		if err != nil || resp == nil || resp.NextPage == 0 {
			return resp, err
		}
		page = resp.NextPage
	}
}

// refused turns an error into a failure for a scan record, unless the guard
// blocked it, which stops the run.
func refused(err error, what string) error {
	if errors.Is(err, connector.ErrBlocked) {
		return err
	}
	return failure{msg: fmt.Sprintf("%s: %v", what, err)}
}

func (r *peopleRun) person(u *gh.User) *ghPerson {
	login := strings.ToLower(u.GetLogin())
	p := r.people[login]
	if p == nil {
		kind := "user"
		if strings.EqualFold(u.GetType(), "Bot") || strings.HasSuffix(login, "[bot]") {
			kind = "bot"
		}
		p = &ghPerson{login: u.GetLogin(), kind: kind, orgRole: "none", teams: map[string]bool{}}
		r.people[login] = p
	}
	if u.SiteAdmin != nil {
		p.siteAdmin = u.SiteAdmin
	}
	return p
}

// collectPeople reads org members, outside collaborators, teams and each
// listed repo's collaborators, then resolves every branch rule's bypass actors
// to people. A refused read is recorded on a scan record, so only the facts
// that need people give ERROR or WARN; repo settings keep working.
func (c *Connector) collectPeople(ctx context.Context, s connector.Scope, out graph.Writer) error {
	cl, err := c.client(s)
	if err != nil {
		return err
	}
	r := &peopleRun{ctx: ctx, cl: cl, s: s, out: out, owner: s.Project.Config.GitHub.Org, isOrg: true,
		people: map[string]*ghPerson{}, teams: map[string]*ghTeam{}, byID: map[int64]string{}, apps: map[string]bypassActor{}}
	orgAttrs := map[string]any{}
	if err := r.readOrg(); err != nil {
		var f failure
		if !errors.As(err, &f) {
			return err
		}
		orgAttrs["error"], orgAttrs["partial"] = f.msg, f.msg
		r.scan(PeopleScanner, r.owner, 0, orgAttrs)
		return nil
	}
	if !r.isOrg {
		orgAttrs["note"] = r.owner + " is a user account, not an org: it has no members or teams, so only repo collaborators are read"
	}
	orgAttrs["org"] = r.isOrg

	// A repo that could not be read in full is partial on its own record.
	for _, name := range s.Project.Config.GitHub.Repos {
		if err := r.readRepo(name); err != nil {
			return err
		}
	}
	r.write()
	r.scan(PeopleScanner, r.owner, len(r.people), orgAttrs)
	return nil
}

func (r *peopleRun) scan(scanner, scope string, inspected int, attrs map[string]any) {
	attrs["scanner"], attrs["scope"], attrs["inspected"] = scanner, scope, int64(inspected)
	r.out.Node(graph.Node{ID: graph.ScanID(scanner, scope), Kind: graph.KindScan, Source: "github", SeenAt: r.s.Now, Attrs: attrs})
}

// readOrg reads members by role, outside collaborators and teams. An owner
// that is a user account has none of them.
func (r *peopleRun) readOrg() error {
	for _, role := range []string{"admin", "member"} {
		resp, err := pages(func(page int) (*gh.Response, error) {
			list, resp, err := r.cl.Organizations.ListMembers(r.ctx, r.owner, &gh.ListMembersOptions{Role: role, ListOptions: gh.ListOptions{PerPage: 100, Page: page}})
			for _, u := range list {
				p := r.person(u)
				p.orgRole = role
				if role == "admin" {
					r.admins = append(r.admins, strings.ToLower(u.GetLogin()))
				}
			}
			return resp, err
		})
		switch {
		case err == nil:
		case notFound(resp) && role == "admin":
			r.isOrg = false
			return nil
		case forbidden(resp), notFound(resp):
			return failure{msg: fmt.Sprintf("the token cannot read the members of %s: give it organization Members: read", r.owner)}
		default:
			return refused(err, "read the members of "+r.owner)
		}
	}
	resp, err := pages(func(page int) (*gh.Response, error) {
		list, resp, err := r.cl.Organizations.ListOutsideCollaborators(r.ctx, r.owner, &gh.ListOutsideCollaboratorsOptions{ListOptions: gh.ListOptions{PerPage: 100, Page: page}})
		for _, u := range list {
			r.person(u).orgRole = "outside"
		}
		return resp, err
	})
	switch {
	case err == nil:
	case forbidden(resp), notFound(resp):
		return failure{msg: fmt.Sprintf("the token cannot read the outside collaborators of %s: give it organization Members: read", r.owner)}
	default:
		return refused(err, "read the outside collaborators of "+r.owner)
	}
	return r.readTeams()
}

// readTeams reads every team and its members once. GitHub lists a child
// team's members under its parent too; they are added here as well, so the
// parent's access reaches them either way.
func (r *peopleRun) readTeams() error {
	resp, err := pages(func(page int) (*gh.Response, error) {
		list, resp, err := r.cl.Teams.ListTeams(r.ctx, r.owner, &gh.ListOptions{PerPage: 100, Page: page})
		for _, t := range list {
			team := &ghTeam{id: t.GetID(), slug: t.GetSlug(), privacy: t.GetPrivacy(), members: map[string]bool{}, repos: map[string]string{}}
			if t.Parent != nil {
				team.parent = t.Parent.GetSlug()
			}
			r.teams[team.slug] = team
			r.byID[team.id] = team.slug
		}
		return resp, err
	})
	switch {
	case err == nil:
	case forbidden(resp), notFound(resp):
		return failure{msg: fmt.Sprintf("the token cannot read the teams of %s: give it organization Members: read", r.owner)}
	default:
		return refused(err, "read the teams of "+r.owner)
	}
	for _, slug := range sortedTeamSlugs(r.teams) {
		team := r.teams[slug]
		for _, role := range []string{"maintainer", "member"} {
			resp, err := pages(func(page int) (*gh.Response, error) {
				list, resp, err := r.cl.Teams.ListTeamMembersBySlug(r.ctx, r.owner, slug, &gh.TeamListTeamMembersOptions{Role: role, ListOptions: gh.ListOptions{PerPage: 100, Page: page}})
				for _, u := range list {
					r.person(u)
					team.members[strings.ToLower(u.GetLogin())] = true
				}
				return resp, err
			})
			switch {
			case err == nil:
			case forbidden(resp), notFound(resp):
				return failure{msg: fmt.Sprintf("the token cannot read the members of team %s: give it organization Members: read", slug)}
			default:
				return refused(err, "read the members of team "+slug)
			}
		}
	}
	// Child teams' members belong to every ancestor.
	for _, team := range r.teams {
		seen := map[string]bool{team.slug: true}
		for p := r.teams[team.parent]; p != nil && !seen[p.slug]; p = r.teams[p.parent] {
			seen[p.slug] = true
			for m := range team.members {
				p.members[m] = true
			}
		}
	}
	for _, team := range r.teams {
		for m := range team.members {
			r.people[m].teams[team.slug] = true
		}
	}
	return nil
}

func sortedTeamSlugs(m map[string]*ghTeam) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// readRepo reads one repo's collaborators and teams, resolves its bypass
// actors and writes its scan record. A refused read makes the repo partial;
// only a call the guard blocked is returned.
func (r *peopleRun) readRepo(name string) error {
	full := r.owner + "/" + name
	repoID := graph.ID("github:repo/" + full)
	attrs := map[string]any{}
	var problems []string
	perms := map[string]string{}
	collabOK := true
	resp, err := pages(func(page int) (*gh.Response, error) {
		list, resp, err := r.cl.Repositories.ListCollaborators(r.ctx, r.owner, name, &gh.ListCollaboratorsOptions{Affiliation: "all", ListOptions: gh.ListOptions{PerPage: 100, Page: page}})
		for _, u := range list {
			r.person(u)
			perms[strings.ToLower(u.GetLogin())] = highestPermission(u)
		}
		return resp, err
	})
	if err != nil {
		if errors.Is(err, connector.ErrBlocked) {
			return err
		}
		collabOK = false
		perms = map[string]string{}
		if forbidden(resp) || notFound(resp) {
			problems = append(problems, fmt.Sprintf("the token cannot read the collaborators of %s: give it repository Metadata: read, from an account with push access", full))
		} else {
			problems = append(problems, fmt.Sprintf("read the collaborators of %s: %v", full, err))
		}
	}
	for login, perm := range perms {
		switch {
		case perm == "admin":
			r.out.Edge(graph.Edge{From: r.userID(login), To: repoID, Kind: graph.EdgeAdminOf, Source: "github"})
		case permRank[perm] >= permRank["push"]:
			r.out.Edge(graph.Edge{From: r.userID(login), To: repoID, Kind: graph.EdgeWritesTo, Source: "github"})
		}
	}
	if r.isOrg {
		resp, err := pages(func(page int) (*gh.Response, error) {
			list, resp, err := r.cl.Repositories.ListTeams(r.ctx, r.owner, name, &gh.ListOptions{PerPage: 100, Page: page})
			for _, t := range list {
				if team := r.teams[t.GetSlug()]; team != nil {
					team.repos[full] = t.GetPermission()
				}
			}
			return resp, err
		})
		if err != nil {
			if errors.Is(err, connector.ErrBlocked) {
				return err
			}
			if forbidden(resp) || notFound(resp) {
				problems = append(problems, fmt.Sprintf("the token cannot read the teams with access to %s: give it repository Metadata: read", full))
			} else {
				problems = append(problems, fmt.Sprintf("read the teams with access to %s: %v", full, err))
			}
		}
	}
	if p := r.resolveBypass(full, perms, collabOK); p != "" {
		problems = append(problems, p)
	}
	if len(problems) > 0 {
		attrs["partial"] = strings.Join(problems, "; ")
	}
	r.scan(RepoPeopleScanner, full, len(perms), attrs)
	return nil
}

func (r *peopleRun) userID(login string) graph.ID {
	return graph.ID("github:user/" + r.s.Hasher.Sum(strings.ToLower(login)))
}

// resolveBypass turns the branch rule's bypass actors into people, apps and
// deploy keys, writes a can_bypass edge for each and puts the resolved list on
// the branch rule. When any actor cannot be resolved, the list is unknown and
// nothing is listed, never an empty "nobody". It returns why, or "".
func (r *peopleRun) resolveBypass(full string, perms map[string]string, collabOK bool) string {
	ruleID := graph.ID("github:branch-rule/" + full + "/default")
	reader, ok := r.out.(graph.Reader)
	if !ok {
		return "the bypass list of " + full + " could not be resolved"
	}
	rule, ok := reader.Get(ruleID)
	if !ok {
		return "the branch rule of " + full + " was not read"
	}
	known, _ := rule.Attrs["bypass_actors_known"].(bool)
	actors, _ := rule.Private[privateActors].([]bypassActor)
	why := ""
	if !known {
		why = "the bypass list of " + full + " could not be read: run firedrill export rulesets as a repo admin"
	}

	type grant struct{ via, through string }
	users := map[string][]grant{}
	var teams []map[string]any
	var others []bypassActor
	addUsers := func(logins []string, via, through string) {
		for _, l := range logins {
			users[l] = append(users[l], grant{via, through})
		}
	}
	atLeast := func(role string) []string {
		var out []string
		for l, p := range perms {
			if permRank[p] >= permRank[role] {
				out = append(out, l)
			}
		}
		return out
	}
	for _, a := range actors {
		if !known {
			break
		}
		switch a.Kind {
		case actorUser:
			login := a.Name
			r.person(&gh.User{Login: &login})
			addUsers([]string{strings.ToLower(a.Name)}, a.Via, "")
		case actorTeam:
			slug := a.Name
			if slug == "" {
				slug = r.byID[a.ID]
			}
			team := r.teams[slug]
			if team == nil {
				known, why = false, fmt.Sprintf("a bypass team of %s could not be found among the org's teams", full)
				continue
			}
			teams = append(teams, map[string]any{"kind": actorTeam, "id": slug, "via": a.Via})
			addUsers(sortedSet(team.members), a.Via, "team:"+slug)
		case actorRole:
			if !collabOK {
				known, why = false, "the collaborators of "+full+" could not be read, so who holds a bypass role is unknown"
				continue
			}
			role := a.Name
			if role == "write" {
				role = "push"
			}
			addUsers(atLeast(role), a.Via, "role:"+a.Name)
		case actorOrgAdmin:
			addUsers(r.admins, a.Via, "org_admin")
		case actorApp, actorDeployKey:
			others = append(others, a)
		}
	}

	rows := []any{}
	if known {
		logins := make([]string, 0, len(users))
		for l := range users {
			logins = append(logins, l)
		}
		sort.Strings(logins)
		repoID := graph.ID("github:repo/" + full)
		for _, l := range logins {
			id := r.userID(l)
			for _, g := range users[l] {
				row := map[string]any{"kind": actorUser, "id": string(id), "via": g.via}
				if g.through != "" {
					row["through"] = g.through
				}
				rows = append(rows, row)
			}
			r.out.Edge(graph.Edge{From: id, To: repoID, Kind: graph.EdgeCanBypass, Source: "github"})
		}
		for _, t := range teams {
			rows = append(rows, t)
		}
		for _, a := range others {
			id := r.nonHuman(a, full)
			rows = append(rows, map[string]any{"kind": a.Kind, "id": string(id), "via": a.Via})
			r.out.Edge(graph.Edge{From: id, To: repoID, Kind: graph.EdgeCanBypass, Source: "github"})
		}
	} else if why == "" {
		why = "the bypass list of " + full + " could not be resolved"
	}
	attrs := map[string]any{}
	for k, v := range rule.Attrs {
		attrs[k] = v
	}
	attrs["bypass_actors_known"] = known
	if !known {
		rows = []any{}
	}
	attrs["bypass_actors"] = rows
	rule.Attrs = attrs
	r.out.Node(rule)
	return why
}

// nonHuman records an app or deploy key that may bypass. A deploy key in a
// ruleset has no ID, so it stands for the repo's deploy keys.
func (r *peopleRun) nonHuman(a bypassActor, full string) graph.ID {
	if a.Kind == actorDeployKey {
		key := full
		if a.ID != 0 {
			key = fmt.Sprintf("%s/%d", full, a.ID)
		}
		id := graph.ID("github:deploy-key/" + key)
		r.apps[string(id)] = bypassActor{Kind: actorDeployKey, ID: a.ID, Name: "deploy keys of " + full}
		return id
	}
	key := fmt.Sprint(a.ID)
	if a.ID == 0 {
		key = a.Name
	}
	id := graph.ID("github:app/" + key)
	if prev, ok := r.apps[string(id)]; !ok || prev.Name == "" {
		r.apps[string(id)] = a
	}
	return id
}

// write puts every person, team, app and deploy key in the graph. Logins stay
// in Private, so no snapshot holds one.
func (r *peopleRun) write() {
	orgID := graph.ID("github:org/" + r.owner)
	for login, p := range r.people {
		id := r.userID(login)
		attrs := map[string]any{"org": r.owner, "org_role": p.orgRole, "type": p.kind}
		if p.siteAdmin != nil {
			attrs["site_admin"] = *p.siteAdmin
		}
		r.out.Node(graph.Node{ID: id, Kind: graph.KindGitHubUser, Source: "github", SeenAt: r.s.Now, Attrs: attrs,
			Private: map[string]any{"login": p.login}})
		if p.orgRole == "admin" || p.orgRole == "member" {
			r.out.Edge(graph.Edge{From: id, To: orgID, Kind: graph.EdgeMemberOf, Source: "github"})
		}
		if p.orgRole == "admin" {
			r.out.Edge(graph.Edge{From: id, To: orgID, Kind: graph.EdgeAdminOf, Source: "github"})
		}
		for slug := range p.teams {
			r.out.Edge(graph.Edge{From: id, To: teamID(r.owner, slug), Kind: graph.EdgeMemberOf, Source: "github"})
		}
	}
	for slug, t := range r.teams {
		repos := []any{}
		for _, full := range sortedStrings(t.repos) {
			perm := t.repos[full]
			repos = append(repos, map[string]any{"repo": full, "permission": perm})
			repoID := graph.ID("github:repo/" + full)
			switch {
			case perm == "admin":
				r.out.Edge(graph.Edge{From: teamID(r.owner, slug), To: repoID, Kind: graph.EdgeAdminOf, Source: "github"})
			case permRank[perm] >= permRank["push"]:
				r.out.Edge(graph.Edge{From: teamID(r.owner, slug), To: repoID, Kind: graph.EdgeWritesTo, Source: "github"})
			}
		}
		r.out.Node(graph.Node{ID: teamID(r.owner, slug), Kind: graph.KindGitHubTeam, Source: "github", SeenAt: r.s.Now, Attrs: map[string]any{
			"slug": slug, "org": r.owner, "privacy": t.privacy, "parent": t.parent, "repos": repos,
		}})
	}
	for id, a := range r.apps {
		kind := graph.KindGitHubApp
		attrs := map[string]any{"org": r.owner, "name": a.Name}
		if a.Kind == actorDeployKey {
			kind = graph.KindDeployKey
		}
		if a.ID != 0 {
			attrs["actor_id"] = a.ID
		}
		r.out.Node(graph.Node{ID: graph.ID(id), Kind: kind, Source: "github", SeenAt: r.s.Now, Attrs: attrs})
	}
}

func teamID(org, slug string) graph.ID { return graph.ID("github:team/" + org + "/" + slug) }

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedStrings(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
