package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

func user(login string, id int) obj { return obj{"login": login, "id": id, "type": "User"} }

func collab(login string, id int, perm string) obj {
	u := user(login, id)
	order := []string{"pull", "triage", "push", "maintain", "admin"}
	perms := obj{}
	at := slices.Index(order, perm)
	for i, p := range order {
		perms[p] = i <= at
	}
	u["permissions"] = perms
	return u
}

// people is a small org: ana is an owner, bo and cy members (cy on a second
// page), dee an outside collaborator, eve and fy members with triage and pull,
// and a bot. Team core is a child of platform.
func people(extra routes) routes {
	bot := collab("acme-ci[bot]", 90, "push")
	bot["type"] = "Bot"
	r := base(routes{
		"/orgs/acme/members?role=admin":    []any{user("ana-acme", 1)},
		"/orgs/acme/members?role=member":   paged{{user("bo-acme", 2), user("eve-acme", 5)}, {user("cy-acme", 3), user("fy-acme", 6)}},
		"/orgs/acme/outside_collaborators": []any{user("dee-ext", 4)},
		"/orgs/acme/teams": []any{
			obj{"id": 11, "slug": "platform", "privacy": "closed"},
			obj{"id": 12, "slug": "core", "privacy": "secret", "parent": obj{"id": 11, "slug": "platform"}},
			obj{"id": 13, "slug": "release", "privacy": "closed"},
		},
		// An empty team list, as GitHub returns for a role with nobody in it.
		"/orgs/acme/teams/platform/members":                 []any{},
		"/orgs/acme/teams/core/members":                     []any{},
		"/orgs/acme/teams/release/members":                  []any{},
		"/orgs/acme/teams/platform/members?role=maintainer": []any{user("ana-acme", 1)},
		"/orgs/acme/teams/platform/members?role=member":     []any{user("bo-acme", 2)},
		"/orgs/acme/teams/core/members?role=member":         []any{user("cy-acme", 3)},
		"/orgs/acme/teams/release/members?role=member":      []any{user("bo-acme", 2)},
		"/repos/acme/api/collaborators": paged{
			{collab("ana-acme", 1, "admin"), collab("bo-acme", 2, "maintain"), collab("cy-acme", 3, "push")},
			{collab("dee-ext", 4, "push"), collab("eve-acme", 5, "triage"), collab("fy-acme", 6, "pull"), bot},
		},
		"/repos/acme/api/teams": []any{obj{"slug": "platform", "permission": "push"}, obj{"slug": "release", "permission": "admin"}},
	})
	for k, v := range extra {
		r[k] = v
	}
	return r
}

// collectAll runs every collection in order into one graph, as a run does.
func collectAll(t *testing.T, c *Connector, s connector.Scope) *graph.Graph {
	t.Helper()
	g := graph.New()
	for _, col := range c.Collections() {
		if err := c.Collect(context.Background(), col, s, g); err != nil {
			t.Fatal(err)
		}
	}
	if v := s.Log.Violations(); len(v) > 0 {
		t.Fatalf("guard violations: %v", v)
	}
	return g
}

func uid(s connector.Scope, login string) graph.ID {
	return graph.ID("github:user/" + s.Hasher.Sum(login))
}

func hasEdge(g *graph.Graph, from, to graph.ID, kind string) bool {
	for _, e := range g.Edges(kind) {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}

func factOf(t *testing.T, g graph.Reader, name string) (facts.Result, error) {
	t.Helper()
	def, ok := facts.Lookup(name)
	if !ok {
		t.Fatalf("no fact %s", name)
	}
	return def.Fn(g, facts.Args{Values: map[string]any{}, Target: map[string]any{"name": "acme/api"}, Now: now})
}

func mustFact(t *testing.T, g graph.Reader, name string) facts.Result {
	t.Helper()
	r, err := factOf(t, g, name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r
}

func TestPeopleMembersTeamsAndCollaborators(t *testing.T) {
	lg := &reqLog{}
	r := people(routes{logKey: lg})
	s := scope(t)
	g := collectAll(t, fakeGitHub(t, r), s)

	roles := map[string]string{"ana-acme": "admin", "bo-acme": "member", "cy-acme": "member", "dee-ext": "outside", "eve-acme": "member", "fy-acme": "member"}
	for login, role := range roles {
		n, ok := g.Get(uid(s, login))
		if !ok {
			t.Fatalf("no node for %s", login)
		}
		if n.Attrs["org_role"] != role || n.Attrs["type"] != "user" || n.Private["login"] != login {
			t.Errorf("%s: %+v %+v", login, n.Attrs, n.Private)
		}
		for _, v := range n.Attrs {
			if s, _ := v.(string); s == login {
				t.Errorf("%s: the login is in Attrs", login)
			}
		}
	}
	if bot, _ := g.Get(uid(s, "acme-ci[bot]")); bot.Attrs["type"] != "bot" {
		t.Fatalf("bot: %+v", bot.Attrs)
	}
	org := graph.ID("github:org/acme")
	if !hasEdge(g, uid(s, "ana-acme"), org, graph.EdgeAdminOf) || hasEdge(g, uid(s, "bo-acme"), org, graph.EdgeAdminOf) {
		t.Fatal("only owners are admin_of the org")
	}
	if !hasEdge(g, uid(s, "cy-acme"), org, graph.EdgeMemberOf) || hasEdge(g, uid(s, "dee-ext"), org, graph.EdgeMemberOf) {
		t.Fatal("members, from every page, are member_of the org; outside collaborators are not")
	}
	// cy is in core, a child of platform, so platform's access reaches cy.
	if !hasEdge(g, uid(s, "cy-acme"), teamID("acme", "core"), graph.EdgeMemberOf) || !hasEdge(g, uid(s, "cy-acme"), teamID("acme", "platform"), graph.EdgeMemberOf) {
		t.Fatal("a child team's member belongs to its parent too")
	}
	core, _ := g.Get(teamID("acme", "core"))
	if core.Attrs["parent"] != "platform" || core.Attrs["privacy"] != "secret" || core.Attrs["slug"] != "core" {
		t.Fatalf("%+v", core.Attrs)
	}
	repo := graph.ID("github:repo/acme/api")
	for login, want := range map[string]string{"ana-acme": graph.EdgeAdminOf, "bo-acme": graph.EdgeWritesTo, "cy-acme": graph.EdgeWritesTo, "dee-ext": graph.EdgeWritesTo, "acme-ci[bot]": graph.EdgeWritesTo} {
		if !hasEdge(g, uid(s, login), repo, want) {
			t.Errorf("%s should %s the repo", login, want)
		}
	}
	for _, login := range []string{"eve-acme", "fy-acme"} {
		if hasEdge(g, uid(s, login), repo, graph.EdgeWritesTo) || hasEdge(g, uid(s, login), repo, graph.EdgeAdminOf) {
			t.Errorf("%s has triage or pull, not write", login)
		}
	}
	if !hasEdge(g, teamID("acme", "release"), repo, graph.EdgeAdminOf) || !hasEdge(g, teamID("acme", "platform"), repo, graph.EdgeWritesTo) {
		t.Fatal("team access to the repo")
	}
	scanNode, _ := g.Get(graph.ScanID(PeopleScanner, "acme"))
	if scanNode.Attrs["inspected"] != int64(7) || scanNode.Attrs["partial"] != nil || scanNode.Attrs["org"] != true {
		t.Fatalf("%+v", scanNode.Attrs)
	}
	var collabCalls int
	for _, u := range lg.all() {
		if strings.HasPrefix(u, "/repos/acme/api/collaborators") {
			collabCalls++
			if !strings.Contains(u, "affiliation=all") || !strings.Contains(u, "per_page=100") {
				t.Errorf("%s", u)
			}
		}
		if strings.HasPrefix(u, "/users/") && u != "/users/acme" {
			t.Errorf("no user profile is fetched per member: %s", u)
		}
	}
	if collabCalls != 2 {
		t.Fatalf("both pages of collaborators are read: %d", collabCalls)
	}

	rows := mustFact(t, g, "github.people").Data.([]any)
	if len(rows) != 6 {
		t.Fatalf("one row per human, bots left out: %d", len(rows))
	}
	byLogin := map[string]map[string]any{}
	for _, row := range rows {
		m := row.(map[string]any)
		byLogin[m["login"].(string)] = m
	}
	ana, dee, cy := byLogin["ana-acme"], byLogin["dee-ext"], byLogin["cy-acme"]
	if ana["org_role"] != "admin" || !slices.Equal(ana["repos_admin"].([]any), []any{"acme/api"}) || ana["id"] != string(uid(s, "ana-acme")) {
		t.Fatalf("%+v", ana)
	}
	if dee["is_outside"] != true || !slices.Equal(dee["repos_write"].([]any), []any{"acme/api"}) {
		t.Fatalf("%+v", dee)
	}
	if !slices.Equal(cy["teams"].([]any), []any{"core", "platform"}) {
		t.Fatalf("%+v", cy)
	}
}

// bypassOf collects with the given rules and returns github.bypass_actors.
func bypassOf(t *testing.T, s connector.Scope, extra routes) (map[string]any, *graph.Graph) {
	t.Helper()
	g := collectAll(t, fakeGitHub(t, people(extra)), s)
	return mustFact(t, g, "github.bypass_actors").Data.(map[string]any), g
}

func peopleIDs(t *testing.T, data map[string]any) []string {
	t.Helper()
	var out []string
	for _, p := range data["people"].([]any) {
		out = append(out, p.(map[string]any)["login"].(string))
	}
	slices.Sort(out)
	return out
}

func classic(enforceAdmins bool, allowances obj) obj {
	reviews := obj{"required_approving_review_count": 1}
	if allowances != nil {
		reviews["bypass_pull_request_allowances"] = allowances
	}
	return obj{"required_pull_request_reviews": reviews, "enforce_admins": obj{"enabled": enforceAdmins}}
}

func rulesetWith(actors any) routes {
	r := rulesetRoutes(actors)
	delete(r, "/orgs/acme")
	delete(r, "/repos/acme/api")
	delete(r, "/repos/acme/api/actions/permissions/workflow")
	return r
}

func TestBypassClassicAllowances(t *testing.T) {
	s := scope(t)
	data, g := bypassOf(t, s, routes{protPath: classic(true, obj{
		"users": []any{user("dee-ext", 4)},
		"teams": []any{obj{"id": 13, "slug": "release"}},
		"apps":  []any{obj{"id": 77, "slug": "acme-deployer", "name": "Acme Deployer"}},
	})})
	if data["known"] != true || !slices.Equal(peopleIDs(t, data), []string{"bo-acme", "dee-ext"}) {
		t.Fatalf("a listed user and the team's members: %+v", data)
	}
	if !slices.Equal(data["teams"].([]any), []any{"release"}) {
		t.Fatalf("%+v", data["teams"])
	}
	apps := data["apps"].([]any)
	if len(apps) != 1 || apps[0].(map[string]any)["id"] != "github:app/77" || apps[0].(map[string]any)["name"] != "acme-deployer" {
		t.Fatalf("%+v", apps)
	}
	if data["count"] != int64(3) {
		t.Fatalf("%+v", data["count"])
	}
	repo := graph.ID("github:repo/acme/api")
	if !hasEdge(g, uid(s, "bo-acme"), repo, graph.EdgeCanBypass) || !hasEdge(g, "github:app/77", repo, graph.EdgeCanBypass) {
		t.Fatal("can_bypass edges")
	}
	if n, ok := g.Get("github:app/77"); !ok || n.Kind != graph.KindGitHubApp {
		t.Fatal("app node")
	}
	r := rule(t, g)
	if r["bypass"] != "allowed" || r["bypass_actors_known"] != true {
		t.Fatalf("the tri-state is kept: %+v", r)
	}
	for _, row := range r["bypass_actors"].([]any) {
		m := row.(map[string]any)
		if m["kind"] == "user" && m["via"] != viaClassic {
			t.Fatalf("%+v", m)
		}
	}
}

func TestBypassAdminsNotEnforcedMeansRepoAdmins(t *testing.T) {
	s := scope(t)
	data, g := bypassOf(t, s, routes{protPath: classic(false, nil)})
	if !slices.Equal(peopleIDs(t, data), []string{"ana-acme"}) {
		t.Fatalf("%+v", data)
	}
	p := data["people"].([]any)[0].(map[string]any)
	if !slices.Equal(p["via"].([]any), []any{viaAdminsNotEnforced}) {
		t.Fatalf("%+v", p)
	}
	if rule(t, g)["bypass"] != "allowed" {
		t.Fatal("tri-state")
	}
}

func TestBypassRulesetActors(t *testing.T) {
	cases := []struct {
		name   string
		actors []any
		people []string
		apps   []string
	}{
		{"team, with child teams", []any{obj{"actor_id": 11, "actor_type": "Team", "bypass_mode": "always"}}, []string{"ana-acme", "bo-acme", "cy-acme"}, nil},
		{"admin role", []any{obj{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}}, []string{"ana-acme"}, nil},
		{"maintain role", []any{obj{"actor_id": 2, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}}, []string{"ana-acme", "bo-acme"}, nil},
		{"write role", []any{obj{"actor_id": 4, "actor_type": "RepositoryRole", "bypass_mode": "always"}}, []string{"acme-ci[bot]", "ana-acme", "bo-acme", "cy-acme", "dee-ext"}, nil},
		{"org admin", []any{obj{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"}}, []string{"ana-acme"}, nil},
		{"integration", []any{obj{"actor_id": 99, "actor_type": "Integration", "bypass_mode": "always"}}, nil, []string{"github:app/99"}},
		{"deploy key", []any{obj{"actor_id": nil, "actor_type": "DeployKey", "bypass_mode": "always"}}, nil, []string{"github:deploy-key/acme/api"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := scope(t)
			data, g := bypassOf(t, s, rulesetWith(c.actors))
			if data["known"] != true {
				t.Fatalf("%+v", data)
			}
			if got := peopleIDs(t, data); !slices.Equal(got, c.people) {
				t.Fatalf("people %v, want %v", got, c.people)
			}
			var apps []string
			for _, a := range data["apps"].([]any) {
				apps = append(apps, a.(map[string]any)["id"].(string))
				if n, ok := g.Get(graph.ID(a.(map[string]any)["id"].(string))); !ok || (n.Kind != graph.KindGitHubApp && n.Kind != graph.KindDeployKey) {
					t.Fatalf("no node for %v", a)
				}
			}
			if !slices.Equal(apps, c.apps) {
				t.Fatalf("apps %v, want %v", apps, c.apps)
			}
			for _, p := range data["people"].([]any) {
				if v := p.(map[string]any)["via"].([]any); !slices.Equal(v, []any{"ruleset:main"}) {
					t.Fatalf("%+v", p)
				}
			}
			if rule(t, g)["bypass"] != "allowed" {
				t.Fatal("tri-state")
			}
		})
	}
}

func TestBypassFromAdminExport(t *testing.T) {
	s := scope(t)
	writeExport(t, s, now.AddDate(0, 0, -5), []json.RawMessage{
		json.RawMessage(`{"actor_id":13,"actor_type":"Team","bypass_mode":"always"}`),
		json.RawMessage(`{"actor_id":1,"actor_type":"OrganizationAdmin","bypass_mode":"always"}`),
	})
	data, g := bypassOf(t, s, rulesetWith(nil))
	if data["known"] != true || !slices.Equal(peopleIDs(t, data), []string{"ana-acme", "bo-acme"}) {
		t.Fatalf("%+v", data)
	}
	if r := rule(t, g); r["bypass_source"] != "admin_export" || r["bypass"] != "allowed" {
		t.Fatalf("%+v", r)
	}
	if src := mustFact(t, g, "github.bypass_actors").Source; !strings.HasPrefix(src, "admin_export") {
		t.Fatalf("the export's provenance reaches the tag: %s", src)
	}
}

func TestUnreadableBypassListsNobody(t *testing.T) {
	for name, extra := range map[string]routes{
		"no list, no export": rulesetWith(nil),
		"403 on the ruleset": func() routes { r := rulesetWith(nil); r["/repos/acme/api/rulesets/7"] = 403; return r }(),
		"custom role":        rulesetWith([]any{obj{"actor_id": 31337, "actor_type": "RepositoryRole", "bypass_mode": "always"}}),
	} {
		t.Run(name, func(t *testing.T) {
			s := scope(t)
			res, _ := factOfCollect(t, s, extra)
			data := res.Data.(map[string]any)
			if data["known"] != false || len(data["people"].([]any)) != 0 || data["count"] != int64(0) {
				t.Fatalf("an unread list is unknown, never nobody: %+v", data)
			}
			if res.Partial == "" {
				t.Fatal("the repo is partial, so drills reading it give WARN")
			}
		})
	}
	// The unread list writes no can_bypass edges and keeps the tri-state.
	s := scope(t)
	_, g := factOfCollect(t, s, rulesetWith(nil))
	if len(g.Edges(graph.EdgeCanBypass)) != 0 {
		t.Fatal("no can_bypass edge from an unread list")
	}
	if r := rule(t, g); r["bypass"] != "unknown" || r["bypass_actors_known"] != false || len(r["bypass_actors"].([]any)) != 0 {
		t.Fatalf("%+v", r)
	}
	if got := mustFact(t, g, "github.branch_rules").Data.(map[string]any); got["bypass_actors_known"] != false {
		t.Fatalf("%+v", got)
	}
}

func factOfCollect(t *testing.T, s connector.Scope, extra routes) (facts.Result, *graph.Graph) {
	t.Helper()
	g := collectAll(t, fakeGitHub(t, people(extra)), s)
	return mustFact(t, g, "github.bypass_actors"), g
}

func TestNoBypassMeansKnownAndNobody(t *testing.T) {
	data, _ := bypassOf(t, scope(t), nil)
	if data["known"] != true || len(data["people"].([]any)) != 0 || data["count"] != int64(0) {
		t.Fatalf("%+v", data)
	}
}

func TestForbiddenMembersIsACollectionError(t *testing.T) {
	for _, path := range []string{"/orgs/acme/members?role=admin", "/orgs/acme/outside_collaborators", "/orgs/acme/teams", "/orgs/acme/teams/core/members?role=member"} {
		t.Run(path, func(t *testing.T) {
			s := scope(t)
			g := collectAll(t, fakeGitHub(t, people(routes{path: status{403, "Resource not accessible by personal access token"}})), s)
			n, _ := g.Get(graph.ScanID(PeopleScanner, "acme"))
			if msg, _ := n.Attrs["error"].(string); !strings.Contains(msg, "Members: read") {
				t.Fatalf("%+v", n.Attrs)
			}
			for _, name := range []string{"github.people", "github.bypass_actors"} {
				if _, err := factOf(t, g, name); err == nil {
					t.Fatalf("%s must give ERROR", name)
				}
			}
			for _, name := range []string{"github.branch_rules", "github.actions_permissions"} {
				if _, err := factOf(t, g, name); err != nil {
					t.Fatalf("%s keeps working: %v", name, err)
				}
			}
			if len(g.Nodes(graph.KindGitHubUser)) != 0 {
				t.Fatal("no people from a refused read")
			}
		})
	}
}

func TestForbiddenCollaboratorsIsPartial(t *testing.T) {
	s := scope(t)
	g := collectAll(t, fakeGitHub(t, people(routes{"/repos/acme/api/collaborators": 403})), s)
	res := mustFact(t, g, "github.people")
	if !strings.Contains(res.Partial, "collaborators of acme/api") {
		t.Fatalf("%q", res.Partial)
	}
	if len(res.Data.([]any)) == 0 {
		t.Fatal("members are still listed")
	}
	if _, err := factOf(t, g, "github.branch_rules"); err != nil {
		t.Fatal(err)
	}
}

func TestUserOwnedReadsCollaboratorsOnly(t *testing.T) {
	r := people(nil)
	for _, k := range []string{"/orgs/acme/members?role=admin", "/orgs/acme/members?role=member", "/orgs/acme/outside_collaborators", "/orgs/acme/teams", "/orgs/acme"} {
		delete(r, k)
	}
	r["/users/acme"] = obj{"login": "acme", "plan": obj{"name": "pro"}}
	s := scope(t)
	g := collectAll(t, fakeGitHub(t, r), s)
	n, _ := g.Get(graph.ScanID(PeopleScanner, "acme"))
	if n.Attrs["error"] != nil || n.Attrs["org"] != false || !strings.Contains(n.Attrs["note"].(string), "user account") {
		t.Fatalf("%+v", n.Attrs)
	}
	if !hasEdge(g, uid(s, "ana-acme"), "github:repo/acme/api", graph.EdgeAdminOf) {
		t.Fatal("collaborators are still read")
	}
	if len(g.Nodes(graph.KindGitHubTeam)) != 0 {
		t.Fatal("no teams")
	}
	if _, err := factOf(t, g, "github.people"); err != nil {
		t.Fatal(err)
	}
}

func TestNoLoginReachesASnapshot(t *testing.T) {
	s := scope(t)
	g := collectAll(t, fakeGitHub(t, people(rulesetWith([]any{obj{"actor_id": 11, "actor_type": "Team", "bypass_mode": "always"}}))), s)
	snap := graph.TakeSnapshot(g, now)
	tag.ScanSnapshot(&snap, s.Hasher)
	b, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	for _, login := range []string{"ana-acme", "bo-acme", "cy-acme", "dee-ext", "eve-acme", "fy-acme", "acme-ci"} {
		if strings.Contains(string(b), login) {
			t.Errorf("%s is in the snapshot", login)
		}
	}
	// The fact rows carry them, for conditions and evidence.
	b, _ = json.Marshal(mustFact(t, g, "github.people").Data)
	if !strings.Contains(string(b), "ana-acme") {
		t.Fatal("the fact rows carry logins")
	}
	b, _ = json.Marshal(mustFact(t, g, "github.bypass_actors").Data)
	if !strings.Contains(string(b), "cy-acme") {
		t.Fatal("bypass rows carry logins")
	}
}

func TestPeopleCallsAreGetOnly(t *testing.T) {
	c := New()
	log := &connector.CallLog{}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req, _ := http.NewRequest(m, "https://api.github.com/orgs/acme/members", strings.NewReader("{}"))
		if _, err := c.HTTP(log).Do(req); !errors.Is(err, connector.ErrBlocked) {
			t.Errorf("%s was not refused: %v", m, err)
		}
	}
	for _, col := range c.Collections() {
		for _, call := range col.Calls {
			if !strings.HasPrefix(call, "GET https://api.github.com/") {
				t.Errorf("%s: %s", col.Name, call)
			}
		}
	}
}

// The export stores each ruleset's bypass_actors as GitHub returns them, so a
// list exported by an admin resolves to people for a read-only token.
func TestExportRoundTripResolvesActors(t *testing.T) {
	s := scope(t)
	admin := rulesetWith([]any{obj{"actor_id": 12, "actor_type": "Team", "bypass_mode": "pull_request"}})
	admin["/user"] = obj{"login": "ana-acme"}
	admin["/repos/acme/api/rulesets"] = []any{obj{"id": 7, "name": "main"}}
	if _, n, err := fakeGitHub(t, people(admin)).ExportRulesets(context.Background(), s); err != nil || n != 1 {
		t.Fatalf("%v %d", err, n)
	}
	data, g := bypassOf(t, s, rulesetWith(nil))
	if data["known"] != true || !slices.Equal(peopleIDs(t, data), []string{"cy-acme"}) {
		t.Fatalf("%+v", data)
	}
	if rule(t, g)["bypass_source"] != "admin_export" {
		t.Fatal("from the export")
	}
}
