package facts

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sk1122/firedrill/internal/graph"
)

// Scan records the people facts read, besides the GitHub people records.
const (
	googleUsersScanner  = "google_users"
	googleGroupsScanner = "google_groups"
)

// peopleSystems are the systems whose accounts the link step joins to people.
var peopleSystems = []string{"google", "gcp", "github"}

var gcpRoleShape = Obj(map[string]*Shape{
	"project": Str, "role": Str, "via": Str, "is_admin": Bool, "destructive": Bool, "production": Bool,
	"power_known": Bool, "conditional": Bool,
})

func registerPeople() {
	Register(Def{
		Name: "people.accounts", AnyConnector: peopleSystems,
		Shape: Obj(map[string]*Shape{
			"found": List(Obj(map[string]*Shape{
				"id": Str, "email": Str, "systems": List(Str), "external": Bool, "leaver": Bool,
				"google": Obj(map[string]*Shape{"present": Bool, "suspended": Bool, "is_admin": Bool}),
				"github": Obj(map[string]*Shape{
					"present": Bool, "org_role": Str, "repos_admin": List(Str), "repos_write": List(Str), "repos_bypass": List(Str),
				}),
				"gcp": Obj(map[string]*Shape{"roles": List(gcpRoleShape)}),
			})),
			"systems_read":        List(Str),
			"group_members_known": Bool,
			"production_basis":    Str,
			"unlinked":            Obj(map[string]*Shape{"github": Int, "gcp": Int, "total": Int}),
		}),
		Fn: peopleAccounts,
	})
	Register(Def{
		Name: "people.unlinked", AnyConnector: peopleSystems,
		Shape: Obj(map[string]*Shape{
			"found": List(Obj(map[string]*Shape{
				"system": Str, "kind": Str, "id": Str, "is_admin": Bool, "reason": Str,
			})),
			"systems_read": List(Str),
		}),
		Fn: peopleUnlinked,
	})
	Register(Def{
		Name: "people.admins", AnyConnector: peopleSystems,
		Shape: Obj(map[string]*Shape{
			"found": List(Obj(map[string]*Shape{
				"system": Str, "kind": Str, "id": Str, "role": Str, "project": Str, "production": Bool,
				"linked": Bool, "person": Str, "people": List(Str), "owner": Str, "unowned": Bool,
				"current": Bool, "current_known": Bool, "power_known": Bool,
			})),
			"systems_read":     List(Str),
			"production_basis": Str,
		}),
		Fn: peopleAdmins,
	})
}

// peopleIndex is what the three people facts share: which systems were read,
// and every link the link step and the connectors wrote.
type peopleIndex struct {
	g        graph.Reader
	fact     string
	read     map[string]bool
	readList []any
	partial  []string
	r        Result
	// personOf maps an account (Google user, GitHub user, or a GCP binding held
	// directly) to its person.
	personOf map[graph.ID]graph.ID
	accounts map[graph.ID][]graph.ID
	viaGroup map[graph.ID][]graph.ID // person to bindings held through a group
	groupOf  map[graph.ID]graph.ID   // binding to the group it names
	inGroup  map[graph.ID][]graph.ID // group to the accounts and groups in it
	members  map[graph.ID][]graph.ID // binding to the people holding it through its group
	owners   map[graph.ID]string     // principal to its owner in owners.yaml
	repo     map[string]map[graph.ID]map[string]bool
	anyMark  bool
	today    string
}

// newPeopleIndex reads the scan records of every people system. A GitHub org
// that could not be read is an error, so drills give ERROR; a GCP project or
// GitHub repo read only in part, or Google groups not read or not readable,
// make the result partial, so a drill gives WARN rather than good news.
func newPeopleIndex(g graph.Reader, a Args, fact string) (*peopleIndex, error) {
	x := &peopleIndex{g: g, fact: fact, read: map[string]bool{}, r: Result{Source: "api"},
		personOf: map[graph.ID]graph.ID{}, accounts: map[graph.ID][]graph.ID{}, viaGroup: map[graph.ID][]graph.ID{},
		groupOf: map[graph.ID]graph.ID{}, inGroup: map[graph.ID][]graph.ID{}, members: map[graph.ID][]graph.ID{},
		owners: map[graph.ID]string{}, repo: map[string]map[graph.ID]map[string]bool{},
		today: a.Now.UTC().Format("2006-01-02")}
	groupsSeen := false
	for _, n := range g.Nodes(graph.KindScan) {
		switch strAttr(n, "scanner") {
		case googleUsersScanner:
			x.read["google"] = true
		case githubPeopleScanner:
			if msg := strAttr(n, "error"); msg != "" {
				return nil, fmt.Errorf("%s: github: %s", fact, msg)
			}
			x.read["github"] = true
		case githubRepoPeopleScanner:
		case googleGroupsScanner:
			groupsSeen = true
			if msg := strAttr(n, "error"); msg != "" {
				x.partial = append(x.partial, "google groups: "+msg)
				x.r.Read = append(x.r.Read, n.ID)
				continue
			}
		default:
			continue
		}
		if p := strAttr(n, "partial"); p != "" {
			x.partial = append(x.partial, p)
		}
		x.r.Read = append(x.r.Read, n.ID)
	}
	for _, n := range g.Nodes(graph.KindGCPProject) {
		x.read["gcp"] = true
		if msg := strAttr(n, "error"); msg != "" {
			x.partial = append(x.partial, fmt.Sprintf("gcp project %s could not be read: %s", strAttr(n, "name"), msg))
		}
		if isTrue(n.Attrs["production"]) {
			x.anyMark = true
		}
		x.r.Read = append(x.r.Read, n.ID)
	}
	for _, s := range peopleSystems {
		if x.read[s] {
			x.readList = append(x.readList, s)
		}
	}
	if len(x.readList) == 0 {
		return nil, fmt.Errorf("%s: no accounts were read from %s", fact, strings.Join(peopleSystems, ", "))
	}
	x.anyMark = x.anyMark || settingsInt(g, "production_markers", 0) > 0

	for _, e := range g.Edges(graph.EdgeSamePerson) {
		x.personOf[e.To] = e.From
		x.accounts[e.From] = append(x.accounts[e.From], e.To)
	}
	for _, e := range g.Edges(graph.EdgeViaGroup) {
		x.viaGroup[e.From] = append(x.viaGroup[e.From], e.To)
		x.members[e.To] = append(x.members[e.To], e.From)
	}
	groupBindings := 0
	for _, e := range g.Edges(graph.EdgeBoundTo) {
		x.groupOf[e.To] = e.From
		groupBindings++
	}
	for _, e := range g.Edges(graph.EdgeMemberOf) {
		if strings.HasPrefix(string(e.To), "google:group/") {
			x.inGroup[e.To] = append(x.inGroup[e.To], e.From)
		}
	}
	if x.read["gcp"] && groupBindings > 0 && !groupsSeen {
		x.partial = append(x.partial, fmt.Sprintf("Google groups were not read, so who holds the roles of %d group bindings is unknown", groupBindings))
	}
	for _, e := range g.Edges(graph.EdgeOwns) {
		if !strings.HasPrefix(string(e.From), "config-owner:") {
			continue
		}
		if n, ok := g.Get(e.From); ok {
			x.owners[e.To] = strAttr(n, "owner")
		}
	}
	for _, kind := range []string{graph.EdgeAdminOf, graph.EdgeWritesTo, graph.EdgeCanBypass} {
		x.repo[kind] = map[graph.ID]map[string]bool{}
		for _, e := range g.Edges(kind) {
			if repo, ok := strings.CutPrefix(string(e.To), "github:repo/"); ok {
				if x.repo[kind][e.From] == nil {
					x.repo[kind][e.From] = map[string]bool{}
				}
				x.repo[kind][e.From][repo] = true
			}
		}
	}
	return x, nil
}

func (x *peopleIndex) result(data any) (Result, error) {
	x.r.Data = data
	x.r.Partial = strings.Join(x.partial, "; ")
	return x.r, nil
}

// groupKnown says whether every member of a group, nested groups included,
// was read. A group the Google connector did not read is unknown.
func (x *peopleIndex) groupKnown(gid graph.ID) bool {
	seen := map[graph.ID]bool{}
	var walk func(graph.ID) bool
	walk = func(id graph.ID) bool {
		if seen[id] {
			return true
		}
		seen[id] = true
		n, ok := x.g.Get(id)
		if !ok || !isTrue(n.Attrs["members_known"]) {
			return false
		}
		for _, m := range x.inGroup[id] {
			if strings.HasPrefix(string(m), "google:group/") && !walk(m) {
				return false
			}
		}
		return true
	}
	return walk(gid)
}

// groupWhy says why a group's members are unknown.
func (x *peopleIndex) groupWhy(gid graph.ID) string {
	if n, ok := x.g.Get(gid); ok {
		if why, _ := n.Private["why"].(string); why != "" {
			return why
		}
		return "a group nested in it could not be read"
	}
	return "Google groups were not read, so the group's members are unknown"
}

// persons lists every person, leavers included, since a leaver's node keeps
// its kind.
func (x *peopleIndex) persons() []graph.Node {
	var out []graph.Node
	out = append(out, x.g.Nodes(graph.KindPerson)...)
	out = append(out, x.g.Nodes(graph.KindLeaver)...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (x *peopleIndex) isLeaver(p graph.Node) bool {
	d := strAttr(p, "leave_date")
	return p.Kind == graph.KindLeaver && d != "" && d < x.today
}

// current says whether a person has an active Workspace account: one not
// suspended, and they have not left.
func (x *peopleIndex) current(pid graph.ID) bool {
	p, ok := x.g.Get(pid)
	if !ok || x.isLeaver(p) {
		return false
	}
	for _, acc := range x.accounts[pid] {
		if n, ok := x.g.Get(acc); ok && n.Kind == graph.KindIdentityUser && !isTrue(n.Attrs["suspended"]) {
			return true
		}
	}
	return false
}

func (x *peopleIndex) production(b graph.Node) bool {
	if !x.anyMark {
		return true
	}
	return isTrue(b.Attrs["production"])
}

func (x *peopleIndex) productionBasis() string {
	if x.anyMark || !x.read["gcp"] {
		return ""
	}
	return "nothing is named production in config, so every GCP project is treated as production"
}

func (x *peopleIndex) roleRow(b graph.Node, via string) map[string]any {
	x.r.Read = append(x.r.Read, b.ID)
	return map[string]any{
		"project": strAttr(b, "project"), "role": strAttr(b, "role"), "via": via,
		"is_admin": isTrue(b.Attrs["is_admin"]), "destructive": isTrue(b.Attrs["destructive"]),
		"production": x.production(b), "power_known": powerKnown(b), "conditional": isTrue(b.Attrs["conditional"]),
	}
}

// powerKnown is false only for a custom role whose permissions could not be
// read. A binding from before roles were classified is unknown too.
func powerKnown(b graph.Node) bool {
	v, ok := b.Attrs["power_known"].(bool)
	return ok && v
}

var orgRank = map[string]int{"none": 0, "outside": 1, "member": 2, "admin": 3}

func peopleAccounts(g graph.Reader, a Args) (Result, error) {
	x, err := newPeopleIndex(g, a, "people.accounts")
	if err != nil {
		return Result{}, err
	}
	rows := []any{}
	for _, p := range x.persons() {
		x.r.Read = append(x.r.Read, p.ID)
		email, _ := p.Private["email"].(string)
		systems, _ := p.Attrs["systems"].([]any)
		if systems == nil {
			systems = []any{}
		}
		goog := map[string]any{"present": false, "suspended": false, "is_admin": false}
		gh := map[string]any{"present": false, "org_role": "none"}
		admin, write, bypass := map[string]bool{}, map[string]bool{}, map[string]bool{}
		roles := []any{}
		for _, acc := range x.accounts[p.ID] {
			n, ok := g.Get(acc)
			if !ok {
				continue
			}
			x.r.Read = append(x.r.Read, n.ID)
			switch n.Kind {
			case graph.KindIdentityUser:
				goog["present"] = true
				goog["suspended"] = isTrue(n.Attrs["suspended"])
				goog["is_admin"] = isTrue(n.Attrs["is_admin"]) || isTrue(n.Attrs["is_delegated_admin"])
			case graph.KindGitHubUser:
				gh["present"] = true
				if role := strAttr(n, "org_role"); orgRank[role] > orgRank[gh["org_role"].(string)] {
					gh["org_role"] = role
				}
				for r := range x.repo[graph.EdgeAdminOf][n.ID] {
					admin[r] = true
				}
				for r := range x.repo[graph.EdgeWritesTo][n.ID] {
					write[r] = true
				}
				for r := range x.repo[graph.EdgeCanBypass][n.ID] {
					bypass[r] = true
				}
			case graph.KindGCPBinding:
				roles = append(roles, x.roleRow(n, "direct"))
			}
		}
		for _, b := range x.viaGroup[p.ID] {
			if n, ok := g.Get(b); ok {
				roles = append(roles, x.roleRow(n, "group"))
			}
		}
		sort.SliceStable(roles, func(i, j int) bool {
			ri, rj := roles[i].(map[string]any), roles[j].(map[string]any)
			return fmt.Sprint(ri["project"], ri["role"], ri["via"]) < fmt.Sprint(rj["project"], rj["role"], rj["via"])
		})
		gh["repos_admin"], gh["repos_write"], gh["repos_bypass"] = sortedKeys(admin), sortedKeys(write), sortedKeys(bypass)
		rows = append(rows, map[string]any{
			"id": string(p.ID), "email": email, "systems": systems, "external": isTrue(p.Attrs["external"]),
			"leaver": x.isLeaver(p), "google": goog, "github": gh, "gcp": map[string]any{"roles": roles},
		})
	}
	un := x.unlinkedRows()
	counts := map[string]int64{"github": 0, "gcp": 0}
	for _, row := range un {
		counts[row["system"].(string)]++
	}
	known := true
	for _, gid := range x.groupOf {
		if !x.groupKnown(gid) {
			known = false
		}
	}
	return x.result(map[string]any{
		"found": rows, "systems_read": x.readList, "group_members_known": known, "production_basis": x.productionBasis(),
		"unlinked": map[string]any{"github": counts["github"], "gcp": counts["gcp"], "total": int64(len(un))},
	})
}

// isAdminGitHub says whether a GitHub account owns the org or administers a repo.
func (x *peopleIndex) isAdminGitHub(n graph.Node) bool {
	return strAttr(n, "org_role") == "admin" || len(x.repo[graph.EdgeAdminOf][n.ID]) > 0
}

// bindingKind names what holds a binding, as the people facts call it.
func bindingKind(b graph.Node) string {
	switch t := strAttr(b, "member_type"); t {
	case "user", "deleted_user":
		return "person"
	case "group", "deleted_group":
		return "group"
	case "service_account", "deleted_service_account":
		return "service_account"
	case "domain":
		return "domain"
	case "allUsers", "allAuthenticatedUsers":
		return "public"
	default:
		return t
	}
}

// unlinkedRows lists every account no person or owner answers for.
func (x *peopleIndex) unlinkedRows() []map[string]any {
	g := x.g
	var out []map[string]any
	add := func(system, kind string, id graph.ID, admin bool, reason string) {
		out = append(out, map[string]any{"system": system, "kind": kind, "id": string(id), "is_admin": admin, "reason": reason})
		x.r.Read = append(x.r.Read, id)
	}
	if x.read["github"] {
		for _, n := range g.Nodes(graph.KindGitHubUser) {
			if _, ok := x.personOf[n.ID]; ok {
				continue
			}
			admin := x.isAdminGitHub(n)
			switch {
			case strAttr(n, "type") == "user":
				add("github", "person", n.ID, admin, "no entry in people.yaml maps this login to a person")
			case admin && x.owners[n.ID] == "":
				add("github", "app", n.ID, admin, "a bot account with admin rights and no entry in owners.yaml")
			}
		}
		for _, kind := range []string{graph.KindGitHubApp, graph.KindDeployKey} {
			for _, n := range g.Nodes(kind) {
				if x.owners[n.ID] != "" {
					continue
				}
				k := "app"
				if kind == graph.KindDeployKey {
					k = "deploy_key"
				}
				add("github", k, n.ID, false, "can bypass review and has no entry in owners.yaml")
			}
		}
	}
	if x.read["gcp"] {
		for _, b := range g.Nodes(graph.KindGCPBinding) {
			admin := isTrue(b.Attrs["is_admin"])
			powerful := admin || isTrue(b.Attrs["destructive"]) || !powerKnown(b)
			t := strAttr(b, "member_type")
			switch kind := bindingKind(b); {
			case strings.HasPrefix(t, "deleted_"):
				add("gcp", kind, b.ID, admin, "the member was deleted but the binding remains")
			case kind == "person":
				if _, ok := x.personOf[b.ID]; !ok {
					add("gcp", kind, b.ID, admin, "the member's address could not be read")
				}
			case kind == "group":
				if gid, ok := x.groupOf[b.ID]; !ok || !x.groupKnown(gid) {
					why := "Google groups were not read, so the group's members are unknown"
					if ok {
						why = x.groupWhy(gid)
					}
					add("gcp", kind, b.ID, admin, why)
				}
			case kind == "service_account":
				if powerful && x.owners[b.ID] == "" && !isTrue(b.Attrs["google_managed"]) {
					add("gcp", kind, b.ID, admin, "a service account with power and no entry in owners.yaml")
				}
			case kind == "domain" || kind == "public":
				if powerful {
					add("gcp", kind, b.ID, admin, "the role is granted to every account in a domain or to anyone, not to a person")
				}
			}
		}
	}
	return out
}

func peopleUnlinked(g graph.Reader, a Args) (Result, error) {
	x, err := newPeopleIndex(g, a, "people.unlinked")
	if err != nil {
		return Result{}, err
	}
	rows := []any{}
	for _, r := range x.unlinkedRows() {
		rows = append(rows, r)
	}
	return x.result(map[string]any{"found": rows, "systems_read": x.readList})
}

// peopleAdmins lists every admin principal and who answers for it: the person
// it links to, or its owner in owners.yaml. One that has neither is unowned.
func peopleAdmins(g graph.Reader, a Args) (Result, error) {
	x, err := newPeopleIndex(g, a, "people.admins")
	if err != nil {
		return Result{}, err
	}
	rows := []any{}
	add := func(system, kind string, id graph.ID, role, project string, production bool, people []graph.ID, linked, powerKnown bool) {
		owner := x.owners[id]
		ids := []any{}
		cur := len(people) > 0
		for _, p := range people {
			ids = append(ids, string(p))
			cur = cur && x.current(p)
		}
		person := ""
		if len(people) == 1 {
			person = string(people[0])
		}
		rows = append(rows, map[string]any{
			"system": system, "kind": kind, "id": string(id), "role": role, "project": project, "production": production,
			"linked": linked, "person": person, "people": ids, "owner": owner, "unowned": !linked && owner == "",
			"current": cur, "current_known": x.read["google"], "power_known": powerKnown,
		})
		x.r.Read = append(x.r.Read, id)
	}
	single := func(id graph.ID) []graph.ID {
		if p, ok := x.personOf[id]; ok {
			return []graph.ID{p}
		}
		return nil
	}
	if x.read["google"] {
		for _, n := range g.Nodes(graph.KindIdentityUser) {
			role := ""
			switch {
			case isTrue(n.Attrs["is_admin"]):
				role = "super admin"
			case isTrue(n.Attrs["is_delegated_admin"]):
				role = "delegated admin"
			default:
				continue
			}
			p := single(n.ID)
			add("google", "person", n.ID, role, "", false, p, len(p) > 0, true)
		}
	}
	if x.read["github"] {
		for _, n := range g.Nodes(graph.KindGitHubUser) {
			kind := "person"
			if strAttr(n, "type") != "user" {
				kind = "app"
			}
			p := single(n.ID)
			if strAttr(n, "org_role") == "admin" {
				add("github", kind, n.ID, "org owner of "+strAttr(n, "org"), "", false, p, len(p) > 0, true)
			}
			for _, repo := range sortedKeys(x.repo[graph.EdgeAdminOf][n.ID]) {
				add("github", kind, n.ID, "admin of "+repo.(string), "", false, p, len(p) > 0, true)
			}
		}
		for _, n := range g.Nodes(graph.KindGitHubTeam) {
			repos := sortedKeys(x.repo[graph.EdgeAdminOf][n.ID])
			if len(repos) == 0 {
				continue
			}
			var people []graph.ID
			all := true
			for _, m := range x.inGroupGitHub(n.ID) {
				if p, ok := x.personOf[m]; ok {
					people = append(people, p)
				} else {
					all = false
				}
			}
			for _, repo := range repos {
				add("github", "group", n.ID, "admin of "+repo.(string)+" through the team", "", false, uniq(people), all && len(people) > 0, true)
			}
		}
	}
	if x.read["gcp"] {
		for _, b := range g.Nodes(graph.KindGCPBinding) {
			known := powerKnown(b)
			if !isTrue(b.Attrs["is_admin"]) && known {
				continue
			}
			kind := bindingKind(b)
			var people []graph.ID
			linked := false
			switch kind {
			case "person":
				people = single(b.ID)
				linked = len(people) > 0
			case "group":
				if gid, ok := x.groupOf[b.ID]; ok && x.groupKnown(gid) {
					people = uniq(x.members[b.ID])
					linked = len(people) > 0
				}
			}
			// A Google-managed service agent answers to Google, not to the team.
			if kind == "service_account" && isTrue(b.Attrs["google_managed"]) && x.owners[b.ID] == "" {
				x.owners[b.ID] = "google-managed"
			}
			add("gcp", kind, b.ID, strAttr(b, "role"), strAttr(b, "project"), x.production(b), people, linked, known)
		}
	}
	return x.result(map[string]any{"found": rows, "systems_read": x.readList, "production_basis": x.productionBasis()})
}

// inGroupGitHub lists the GitHub users in a team.
func (x *peopleIndex) inGroupGitHub(team graph.ID) []graph.ID {
	var out []graph.ID
	for _, e := range x.g.Edges(graph.EdgeMemberOf) {
		if e.To == team && strings.HasPrefix(string(e.From), "github:user/") {
			out = append(out, e.From)
		}
	}
	return out
}

func uniq(ids []graph.ID) []graph.ID {
	seen := map[graph.ID]bool{}
	var out []graph.ID
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
