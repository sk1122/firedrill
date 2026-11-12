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
		Name: "people.powers", AnyConnector: peopleSystems,
		Shape: Obj(map[string]*Shape{
			"found": List(Obj(map[string]*Shape{
				"id": Str, "email": Str, "systems": List(Str), "external": Bool, "leaver": Bool,
				"github_present": Bool, "github_org_role": Str, "github_repos": List(Str), "github_admin_repos": List(Str),
				"github_bypass": List(Str),
				"gcp_roles":     List(Str), "gcp_admin": List(Str), "gcp_destructive": List(Str), "prod_destructive": List(Str),
				"gcp_power_known": Bool,
				"google_present":  Bool, "google_active": Bool, "google_admin": Bool,
			})),
			"systems_read":        List(Str),
			"group_members_known": Bool,
			"bypass_known":        Bool,
			"production_basis":    Str,
			"unlinked":            Obj(map[string]*Shape{"github": Int, "gcp": Int, "total": Int, "bypass_repos": List(Str)}),
		}),
		Fn: peoplePowers,
	})
	Register(Def{
		Name: "people.unlinked", AnyConnector: peopleSystems,
		Shape: Obj(map[string]*Shape{
			"found": List(Obj(map[string]*Shape{
				"system": Str, "kind": Str, "id": Str, "is_admin": Bool, "reason": Str, "human": Bool,
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
				"human": Bool, "unverified": Bool,
				"current": Bool, "current_known": Bool, "power_known": Bool, "members_known": Bool, "departed": Bool,
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

// departed says whether a person has left, or has a Google account and every
// one of them is suspended. A person with no Google account is not known to
// have gone.
func (x *peopleIndex) departed(pid graph.ID) bool {
	p, ok := x.g.Get(pid)
	if !ok {
		return false
	}
	if x.isLeaver(p) {
		return true
	}
	accounts, active := 0, 0
	for _, acc := range x.accounts[pid] {
		if n, ok := x.g.Get(acc); ok && n.Kind == graph.KindIdentityUser {
			accounts++
			if !isTrue(n.Attrs["suspended"]) {
				active++
			}
		}
	}
	return accounts > 0 && active == 0
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

// personRow is what every account of one person holds, read once and shared
// by people.accounts and people.powers.
type personRow struct {
	node                          graph.Node
	email                         string
	systems                       []any
	googPresent, googSusp, googAd bool
	ghPresent                     bool
	orgRole                       string
	admin, write, bypass          map[string]bool
	roles                         []any
}

// personRows joins each person to their accounts: a Google user, GitHub users,
// and GCP roles held directly or through a group.
func (x *peopleIndex) personRows() []personRow {
	g := x.g
	var out []personRow
	for _, p := range x.persons() {
		x.r.Read = append(x.r.Read, p.ID)
		row := personRow{node: p, orgRole: "none", admin: map[string]bool{}, write: map[string]bool{}, bypass: map[string]bool{}, roles: []any{}}
		row.email, _ = p.Private["email"].(string)
		row.systems, _ = p.Attrs["systems"].([]any)
		if row.systems == nil {
			row.systems = []any{}
		}
		for _, acc := range x.accounts[p.ID] {
			n, ok := g.Get(acc)
			if !ok {
				continue
			}
			x.r.Read = append(x.r.Read, n.ID)
			switch n.Kind {
			case graph.KindIdentityUser:
				row.googPresent = true
				row.googSusp = isTrue(n.Attrs["suspended"])
				row.googAd = isTrue(n.Attrs["is_admin"]) || isTrue(n.Attrs["is_delegated_admin"])
			case graph.KindGitHubUser:
				row.ghPresent = true
				if role := strAttr(n, "org_role"); orgRank[role] > orgRank[row.orgRole] {
					row.orgRole = role
				}
				for r := range x.repo[graph.EdgeAdminOf][n.ID] {
					row.admin[r] = true
				}
				for r := range x.repo[graph.EdgeWritesTo][n.ID] {
					row.write[r] = true
				}
				for r := range x.repo[graph.EdgeCanBypass][n.ID] {
					row.bypass[r] = true
				}
			case graph.KindGCPBinding:
				row.roles = append(row.roles, x.roleRow(n, "direct"))
			}
		}
		for _, b := range x.viaGroup[p.ID] {
			if n, ok := g.Get(b); ok {
				row.roles = append(row.roles, x.roleRow(n, "group"))
			}
		}
		sort.SliceStable(row.roles, func(i, j int) bool {
			ri, rj := row.roles[i].(map[string]any), row.roles[j].(map[string]any)
			return fmt.Sprint(ri["project"], ri["role"], ri["via"]) < fmt.Sprint(rj["project"], rj["role"], rj["via"])
		})
		out = append(out, row)
	}
	return out
}

// groupsKnown says whether the members of every group that holds a GCP role
// were read.
func (x *peopleIndex) groupsKnown() bool {
	for _, gid := range x.groupOf {
		if !x.groupKnown(gid) {
			return false
		}
	}
	return true
}

// unlinkedCounts counts unlinked accounts by system.
func (x *peopleIndex) unlinkedCounts(un []map[string]any) map[string]any {
	counts := map[string]int64{"github": 0, "gcp": 0}
	for _, row := range un {
		counts[row["system"].(string)]++
	}
	return map[string]any{"github": counts["github"], "gcp": counts["gcp"], "total": int64(len(un))}
}

func peopleAccounts(g graph.Reader, a Args) (Result, error) {
	x, err := newPeopleIndex(g, a, "people.accounts")
	if err != nil {
		return Result{}, err
	}
	rows := []any{}
	for _, p := range x.personRows() {
		goog := map[string]any{"present": p.googPresent, "suspended": p.googSusp, "is_admin": p.googAd}
		gh := map[string]any{"present": p.ghPresent, "org_role": p.orgRole,
			"repos_admin": sortedKeys(p.admin), "repos_write": sortedKeys(p.write), "repos_bypass": sortedKeys(p.bypass)}
		rows = append(rows, map[string]any{
			"id": string(p.node.ID), "email": p.email, "systems": p.systems, "external": isTrue(p.node.Attrs["external"]),
			"leaver": x.isLeaver(p.node), "google": goog, "github": gh, "gcp": map[string]any{"roles": p.roles},
		})
	}
	return x.result(map[string]any{
		"found": rows, "systems_read": x.readList, "group_members_known": x.groupsKnown(), "production_basis": x.productionBasis(),
		"unlinked": x.unlinkedCounts(x.unlinkedRows()),
	})
}

// peoplePowers is people.accounts flattened for drills: one row per person
// with what their accounts can do, by system. A drill matches people by id,
// never by email, so no address reaches a verdict's evidence.
func peoplePowers(g graph.Reader, a Args) (Result, error) {
	x, err := newPeopleIndex(g, a, "people.powers")
	if err != nil {
		return Result{}, err
	}
	groups := x.groupsKnown()
	rows := []any{}
	for _, p := range x.personRows() {
		repos := map[string]bool{}
		for r := range p.admin {
			repos[r] = true
		}
		for r := range p.write {
			repos[r] = true
		}
		roles, admin, destructive, prod := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
		known := groups
		for _, r := range p.roles {
			m := r.(map[string]any)
			project := m["project"].(string)
			roles[project+":"+m["role"].(string)] = true
			if m["is_admin"] == true {
				admin[project] = true
			}
			if m["destructive"] == true {
				destructive[project] = true
				if m["production"] == true {
					prod[project] = true
				}
			}
			if m["power_known"] != true {
				known = false
			}
		}
		rows = append(rows, map[string]any{
			"id": string(p.node.ID), "email": p.email, "systems": p.systems, "external": isTrue(p.node.Attrs["external"]),
			"leaver":         x.isLeaver(p.node),
			"github_present": p.ghPresent, "github_org_role": p.orgRole, "github_repos": sortedKeys(repos),
			"github_admin_repos": sortedKeys(p.admin), "github_bypass": sortedKeys(p.bypass),
			"gcp_roles": sortedKeys(roles), "gcp_admin": sortedKeys(admin), "gcp_destructive": sortedKeys(destructive),
			"prod_destructive": sortedKeys(prod), "gcp_power_known": known,
			"google_present": p.googPresent, "google_active": p.googPresent && !p.googSusp, "google_admin": p.googAd,
		})
	}
	un := x.unlinkedRows()
	counts := x.unlinkedCounts(un)
	// Repos where a GitHub account no person answers for can skip review: its
	// cloud power cannot be joined, so a drill on the repo cannot clear it.
	bypass := map[string]bool{}
	for _, row := range un {
		if row["system"] == "github" && row["kind"] == "person" {
			for r := range x.repo[graph.EdgeCanBypass][graph.ID(row["id"].(string))] {
				bypass[r] = true
			}
		}
	}
	counts["bypass_repos"] = sortedKeys(bypass)
	return x.result(map[string]any{
		"found": rows, "systems_read": x.readList, "group_members_known": groups, "bypass_known": x.bypassKnown(),
		"production_basis": x.productionBasis(), "unlinked": counts,
	})
}

// bypassKnown says whether who can bypass review was read for every default
// branch rule. With GitHub not read there is nothing to know.
func (x *peopleIndex) bypassKnown() bool {
	if !x.read["github"] {
		return true
	}
	for _, n := range x.g.Nodes(graph.KindBranchRule) {
		if strings.HasSuffix(string(n.ID), "/default") && !isTrue(n.Attrs["bypass_actors_known"]) {
			return false
		}
	}
	return true
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
	// human marks a person's own account: a GitHub user or a GCP user:
	// member. Firedrill not linking one to a person record is not the same as
	// nobody answering for it.
	add := func(system, kind string, id graph.ID, admin bool, reason string) {
		human := kind == "person" && !strings.HasPrefix(reason, "the member was deleted")
		out = append(out, map[string]any{"system": system, "kind": kind, "id": string(id), "is_admin": admin, "reason": reason, "human": human})
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
// it links to, or its owner in owners.yaml. A human account, a GitHub user or
// a GCP user: member, that links to no person is unverified: someone may
// answer for it, but Firedrill could not tell who. A principal that is not a
// person's account, such as a service account, an app, a deploy key or a group
// whose members are known and empty, with neither a person nor an owner is
// unowned. A group whose known members are not all linked is unverified too.
func peopleAdmins(g graph.Reader, a Args) (Result, error) {
	x, err := newPeopleIndex(g, a, "people.admins")
	if err != nil {
		return Result{}, err
	}
	rows := []any{}
	add := func(system, kind string, id graph.ID, role, project string, production bool, people []graph.ID, linked, powerKnown, membersKnown, human bool, members int) {
		owner := x.owners[id]
		ids := []any{}
		cur := len(people) > 0
		departed := false
		for _, p := range people {
			ids = append(ids, string(p))
			cur = cur && x.current(p)
			departed = departed || x.departed(p)
		}
		person := ""
		if len(people) == 1 {
			person = string(people[0])
		}
		nobody := !linked && owner == ""
		unowned := nobody && !human && (kind != "group" || (membersKnown && members == 0))
		rows = append(rows, map[string]any{
			"system": system, "kind": kind, "id": string(id), "role": role, "project": project, "production": production,
			"linked": linked, "person": person, "people": ids, "owner": owner, "unowned": unowned,
			"human": human, "unverified": nobody && !unowned && membersKnown,
			"current": cur, "current_known": x.read["google"], "power_known": powerKnown,
			"members_known": membersKnown, "departed": departed,
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
			add("google", "person", n.ID, role, "", false, p, len(p) > 0, true, true, true, 0)
		}
	}
	if x.read["github"] {
		for _, n := range g.Nodes(graph.KindGitHubUser) {
			kind := "person"
			if strAttr(n, "type") != "user" {
				kind = "app"
			}
			p := single(n.ID)
			human := kind == "person"
			if strAttr(n, "org_role") == "admin" {
				add("github", kind, n.ID, "org owner of "+strAttr(n, "org"), "", false, p, len(p) > 0, true, true, human, 0)
			}
			for _, repo := range sortedKeys(x.repo[graph.EdgeAdminOf][n.ID]) {
				add("github", kind, n.ID, "admin of "+repo.(string), "", false, p, len(p) > 0, true, true, human, 0)
			}
		}
		for _, n := range g.Nodes(graph.KindGitHubTeam) {
			repos := sortedKeys(x.repo[graph.EdgeAdminOf][n.ID])
			if len(repos) == 0 {
				continue
			}
			var people []graph.ID
			all := true
			members := x.inGroupGitHub(n.ID)
			for _, m := range members {
				if p, ok := x.personOf[m]; ok {
					people = append(people, p)
				} else {
					all = false
				}
			}
			for _, repo := range repos {
				add("github", "group", n.ID, "admin of "+repo.(string)+" through the team", "", false, uniq(people), all && len(people) > 0, true, true, false, len(members))
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
			linked, members, count := false, true, 0
			human := kind == "person" && !strings.HasPrefix(strAttr(b, "member_type"), "deleted_")
			switch kind {
			case "person":
				people = single(b.ID)
				linked = len(people) > 0
			case "group":
				if gid, ok := x.groupOf[b.ID]; ok && x.groupKnown(gid) {
					people = uniq(x.members[b.ID])
					linked = len(people) > 0
					count = len(x.inGroup[gid])
				} else {
					members = false
				}
			}
			// A Google-managed service agent answers to Google, not to the team.
			if kind == "service_account" && isTrue(b.Attrs["google_managed"]) && x.owners[b.ID] == "" {
				x.owners[b.ID] = "google-managed"
			}
			add("gcp", kind, b.ID, strAttr(b, "role"), strAttr(b, "project"), x.production(b), people, linked, known, members, human, count)
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
