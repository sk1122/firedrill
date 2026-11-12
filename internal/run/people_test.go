package run

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/connectors/configsrc"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

var salt = graph.NewHasher("salt")

func personID(email string) graph.ID { return graph.ID("person:" + salt.Email(email)) }

// peopleEstate is a mixed estate for linking, written as the connectors
// write it. In acme.example:
//   - ana is a super admin; GitHub ana-dev maps to her alias in people.yaml,
//     and she is owner of acme-prod directly through that alias;
//   - cy administers a repo, and holds owner of acme-prod through the admins
//     group, as does ext@partner.example through ops, nested in admins (and
//     admins nested back in ops, a cycle);
//   - ghost-owner owns the GitHub org with no people.yaml entry;
//   - ci is an Editor service account with an owners.yaml entry, deployer a
//     Security Admin with none, and the Google APIs service agent is Editor;
//   - readers is a group Google could not read; friend@mail.example, outside
//     the domain, can delete objects; cy holds a custom role nobody could read;
//   - dee left on 2026-10-01 and still has an active account.
type peopleEstate struct {
	groupsErr    string // the groups scan's error, as a missing scope gives
	githubOrgErr string
}

func (e peopleEstate) connectors() []connector.Connector {
	h := salt
	user := func(w graph.Writer, email string, admin, suspended bool, aliases ...string) {
		w.Node(graph.Node{ID: graph.ID("google:user/" + h.Email(email)), Kind: graph.KindIdentityUser, Source: "google", SeenAt: testNow,
			Attrs:   map[string]any{"is_admin": admin, "is_delegated_admin": false, "suspended": suspended},
			Private: map[string]any{"email": email, "aliases": aliases}})
	}
	group := func(w graph.Writer, email string, known, external bool, members ...string) {
		emails := map[string]any{}
		for _, m := range members {
			if g, ok := strings.CutPrefix(m, "group:"); ok {
				w.Edge(graph.Edge{From: graph.ID("google:group/" + h.Email(g)), To: graph.ID("google:group/" + h.Email(email)), Kind: graph.EdgeMemberOf, Source: "google"})
				continue
			}
			emails[h.Email(m)] = m
			w.Edge(graph.Edge{From: graph.ID("google:user/" + h.Email(m)), To: graph.ID("google:group/" + h.Email(email)), Kind: graph.EdgeMemberOf, Source: "google"})
		}
		why := ""
		if !known {
			why = "the members of a group could not be read: 403"
		}
		w.Node(graph.Node{ID: graph.ID("google:group/" + h.Email(email)), Kind: graph.KindGoogleGroup, Source: "google", SeenAt: testNow,
			Attrs:   map[string]any{"members_known": known, "member_count": int64(len(members)), "external_members": external, "all_users": false},
			Private: map[string]any{"email": email, "member_emails": emails, "why": why}})
	}
	google := &fake{name: "google", available: true, write: func(w graph.Writer) {
		user(w, "ana@acme.example", true, false, "ana.s@acme.example")
		user(w, "bo@acme.example", false, true)
		user(w, "cy@acme.example", false, false)
		user(w, "dee@acme.example", false, false)
		graph.WriteScan(w, "google", "google_users", "", 4, "", testNow)
		if e.groupsErr != "" {
			w.Node(graph.Node{ID: graph.ScanID("google_groups", ""), Kind: graph.KindScan, Source: "google", SeenAt: testNow,
				Attrs: map[string]any{"scanner": "google_groups", "scope": "", "inspected": int64(0), "partial": e.groupsErr, "error": e.groupsErr}})
			return
		}
		group(w, "admins@acme.example", true, false, "cy@acme.example", "group:ops@acme.example")
		group(w, "ops@acme.example", true, true, "ext@partner.example", "group:admins@acme.example")
		group(w, "readers@acme.example", false, false)
		w.Node(graph.Node{ID: graph.ScanID("google_groups", ""), Kind: graph.KindScan, Source: "google", SeenAt: testNow,
			Attrs: map[string]any{"scanner": "google_groups", "scope": "", "inspected": int64(2), "partial": "the members of 1 of 3 groups that hold a GCP role could not be read"}})
	}}
	gcp := &fake{name: "gcp", available: true, write: func(w graph.Writer) {
		w.Node(graph.Node{ID: "gcp:project/acme-prod", Kind: graph.KindGCPProject, Source: "gcp", SeenAt: testNow,
			Attrs: map[string]any{"name": "acme-prod", "number": "123", "member_domains": []any{"acme.example"}, "partial": []any{}, "production": true}})
		bind := func(role, member string, admin, destructive, known bool) {
			kind, rest, _ := strings.Cut(member, ":")
			attrs := map[string]any{"project": "acme-prod", "role": role, "member_type": kind, "conditional": false,
				"is_admin": admin, "destructive": destructive, "power_known": known, "production": true,
				"google_managed": strings.HasSuffix(rest, "@cloudservices.gserviceaccount.com"), "default_account": false, "member": ""}
			private := map[string]any{"email": ""}
			if kind == "serviceAccount" {
				attrs["member_type"], attrs["member"] = "service_account", rest
			} else {
				private["email"] = rest
			}
			id := graph.ID("gcp:binding/acme-prod/" + role + "/" + h.Sum(member))
			w.Node(graph.Node{ID: id, Kind: graph.KindGCPBinding, Source: "gcp", SeenAt: testNow, Attrs: attrs, Private: private})
			w.Edge(graph.Edge{From: "gcp:project/acme-prod", To: id, Kind: graph.EdgeOwns, Source: "gcp"})
		}
		bind("roles/owner", "user:ana.s@acme.example", true, true, true)
		bind("roles/owner", "group:admins@acme.example", true, true, true)
		bind("roles/viewer", "group:readers@acme.example", false, false, true)
		bind("roles/editor", "serviceAccount:ci@acme-prod.iam.gserviceaccount.com", true, true, true)
		bind("roles/iam.securityAdmin", "serviceAccount:deployer@acme-prod.iam.gserviceaccount.com", true, false, true)
		bind("roles/editor", "serviceAccount:123@cloudservices.gserviceaccount.com", true, true, true)
		bind("roles/storage.objectAdmin", "user:friend@mail.example", false, true, true)
		bind("projects/acme-prod/roles/deployer", "user:cy@acme.example", false, false, false)
	}}
	github := &fake{name: "github", available: true, write: func(w graph.Writer) {
		attrs := map[string]any{"scanner": "github_people", "scope": "acme", "inspected": int64(3), "org": true}
		if e.githubOrgErr != "" {
			attrs["error"], attrs["partial"] = e.githubOrgErr, e.githubOrgErr
		}
		w.Node(graph.Node{ID: graph.ScanID("github_people", "acme"), Kind: graph.KindScan, Source: "github", SeenAt: testNow, Attrs: attrs})
		u := func(login, role string) graph.ID {
			id := graph.ID("github:user/" + h.Sum(strings.ToLower(login)))
			w.Node(graph.Node{ID: id, Kind: graph.KindGitHubUser, Source: "github", SeenAt: testNow,
				Attrs: map[string]any{"org": "acme", "org_role": role, "type": "user"}, Private: map[string]any{"login": login}})
			return id
		}
		u("Ana-Dev", "admin")
		u("ghost-owner", "admin")
		cy := u("cy-acme", "member")
		w.Edge(graph.Edge{From: cy, To: "github:repo/acme/api", Kind: graph.EdgeAdminOf, Source: "github"})
		w.Node(graph.Node{ID: "github:app/77", Kind: graph.KindGitHubApp, Source: "github", SeenAt: testNow, Attrs: map[string]any{"org": "acme", "name": "release-bot"}})
		w.Edge(graph.Edge{From: "github:app/77", To: "github:repo/acme/api", Kind: graph.EdgeCanBypass, Source: "github"})
	}}
	hr := &fake{name: "hr", available: true, write: func(w graph.Writer) {
		w.Node(graph.Node{ID: personID("dee@acme.example"), Kind: graph.KindLeaver, Source: "hr", SeenAt: testNow,
			Attrs: map[string]any{"leave_date": "2026-10-01"}, Private: map[string]any{"email": "dee@acme.example"}})
	}}
	return []connector.Connector{configsrc.New(), google, gcp, github, hr}
}

func peopleProject() *config.Project {
	p := &config.Project{Config: config.Config{DefaultOwner: "@default"},
		People: map[string]string{"ana-dev": "ana.s@acme.example", "CY-ACME": "cy@acme.example"},
		Owners: []config.Owner{{Principal: "ci@acme-prod.iam.gserviceaccount.com", Owner: "platform-team"}}}
	p.Config.Google.Domain = "acme.example"
	p.Config.Production = []string{"acme-prod"}
	return p
}

// peopleFieldsDrill reads every field of the three people facts, so
// drill.Validate checks each against the facts' shapes.
const peopleFieldsDrill = `firedrill: v0
id: test/people-fields
safeguard: "Every people field can be read."
severity: low
fetch:
  accounts: { fact: people.accounts }
  unlinked: { fact: people.unlinked }
  admins:   { fact: people.admins }
pass_when:
  - >-
    accounts.found.all(p, p.id != "" && p.email != "" && size(p.systems) >= 0 && (p.external || !p.external)
    && (p.leaver || !p.leaver)
    && (p.google.present || !p.google.present) && (p.google.suspended || !p.google.suspended) && (p.google.is_admin || !p.google.is_admin)
    && (p.github.present || !p.github.present) && p.github.org_role != "" && size(p.github.repos_admin) >= 0
    && size(p.github.repos_write) >= 0 && size(p.github.repos_bypass) >= 0
    && p.gcp.roles.all(r, r.project != "" && r.role != "" && r.via != "" && (r.is_admin || !r.is_admin)
      && (r.destructive || !r.destructive) && (r.production || !r.production) && (r.power_known || !r.power_known)
      && (r.conditional || !r.conditional)))
  - size(accounts.systems_read) > 0 && (accounts.group_members_known || !accounts.group_members_known)
  - accounts.production_basis == accounts.production_basis
  - accounts.unlinked.total == accounts.unlinked.github + accounts.unlinked.gcp
  - unlinked.found.all(u, u.system != "" && u.kind != "" && u.id != "" && (u.is_admin || !u.is_admin) && u.reason != "")
  - size(unlinked.systems_read) > 0
  - >-
    admins.found.all(a, a.system != "" && a.kind != "" && a.id != "" && a.role != "" && a.project == a.project
    && (a.production || !a.production) && (a.linked || !a.linked) && a.person == a.person && size(a.people) >= 0
    && a.owner == a.owner && (a.unowned || !a.unowned) && (a.current || !a.current)
    && (a.current_known || !a.current_known) && (a.power_known || !a.power_known))
  - size(admins.systems_read) > 0 && admins.production_basis == admins.production_basis
fix: "Nothing to fix: this drill only reads fields."
`

func peopleDrill(t *testing.T) *drill.Drill {
	t.Helper()
	d, issues := drill.Parse("test.drill.yaml", []byte(peopleFieldsDrill))
	if drill.HasErrors(issues) {
		t.Fatal(issues)
	}
	if issues := drill.Validate(d); drill.HasErrors(issues) {
		t.Fatalf("the people fields validate: %v", issues)
	}
	return d
}

func runPeople(t *testing.T, e peopleEstate) (*Result, Config) {
	t.Helper()
	// The leavers drill brings in the HR connector.
	c := baseConfig(t, []*drill.Drill{peopleDrill(t), loadDrill(t, "access/leavers-locked-out")}, e.connectors()...)
	c.Project = peopleProject()
	c.Scope.Project = c.Project
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fatal != "" || len(res.Failures) > 0 {
		t.Fatalf("%s %v", res.Fatal, res.Failures)
	}
	return res, c
}

func outcome(t *testing.T, res *Result, id string) *Outcome {
	t.Helper()
	for _, o := range res.Outcomes {
		if o.Drill.ID == id {
			return o
		}
	}
	t.Fatalf("no outcome for %s", id)
	return nil
}

func factData(t *testing.T, g graph.Reader, name string) (map[string]any, facts.Result) {
	t.Helper()
	def, _ := facts.Lookup(name)
	r, err := def.Fn(g, facts.Args{Now: testNow})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return r.Data.(map[string]any), r
}

func rows(m map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range m["found"].([]any) {
		out = append(out, r.(map[string]any))
	}
	return out
}

func TestPeopleFactsValidateAndWarnWhenPartial(t *testing.T) {
	bad, _ := drill.Parse("bad.drill.yaml", []byte(strings.Replace(peopleFieldsDrill, "a.owner == a.owner", "a.nobody == a.owner", 1)))
	if issues := drill.Validate(bad); !drill.HasErrors(issues) {
		t.Fatal("an unknown field must fail, so the check above means something")
	}
	// One group could not be read: partial, so WARN, never good news.
	res, _ := runPeople(t, peopleEstate{})
	if o := outcome(t, res, "test/people-fields"); o.Verdict != tag.Warn {
		t.Fatalf("%+v", o)
	}
	// dee left and still has an active account.
	if o := outcome(t, res, "access/leavers-locked-out"); o.Verdict != tag.Fail {
		t.Fatalf("linking must not hide a leaver: %+v", o)
	}
	// The groups scope missing: WARN, and every group binding is unlinked.
	res, _ = runPeople(t, peopleEstate{groupsErr: "could not read Google groups: 403. Add the scope"})
	if o := outcome(t, res, "test/people-fields"); o.Verdict != tag.Warn || !strings.Contains(o.Reason, "Google groups") {
		t.Fatalf("%+v", o)
	}
	un, _ := factData(t, res.Graph, "people.unlinked")
	groups := 0
	for _, r := range rows(un) {
		if r["kind"] == "group" {
			groups++
		}
	}
	if groups != 2 {
		t.Fatalf("both group bindings are unknown, not nobody: %+v", rows(un))
	}
	// The GitHub org could not be read: ERROR.
	res, _ = runPeople(t, peopleEstate{githubOrgErr: "the token cannot read the members of acme"})
	if o := outcome(t, res, "test/people-fields"); o.Verdict != tag.Error {
		t.Fatalf("%+v", o)
	}
}

// The step's done condition: every admin principal either links to a person
// or shows as unowned.
func TestEveryAdminLinksToAPersonOrShowsAsUnowned(t *testing.T) {
	res, _ := runPeople(t, peopleEstate{})
	admins, _ := factData(t, res.Graph, "people.admins")
	un, _ := factData(t, res.Graph, "people.unlinked")
	unlinked := map[string]bool{}
	for _, r := range rows(un) {
		unlinked[r["id"].(string)] = true
	}
	for _, a := range rows(admins) {
		linked, owner, unowned := a["linked"] == true, a["owner"].(string), a["unowned"] == true
		if !linked && owner == "" && (!unowned || !unlinked[a["id"].(string)]) {
			t.Errorf("an admin neither links to a person nor shows as unowned: %+v", a)
		}
		if linked && unowned {
			t.Errorf("a linked admin reads as unowned: %+v", a)
		}
	}
	find := func(system, kind, role string) map[string]any {
		t.Helper()
		var hit []map[string]any
		for _, a := range rows(admins) {
			if a["system"] == system && a["kind"] == kind && strings.HasPrefix(a["role"].(string), role) {
				hit = append(hit, a)
			}
		}
		if len(hit) != 1 {
			t.Fatalf("%s %s %s: %d rows %+v", system, kind, role, len(hit), rows(admins))
		}
		return hit[0]
	}
	ana := string(personID("ana@acme.example"))
	if a := find("google", "person", "super admin"); a["person"] != ana || a["current"] != true || a["current_known"] != true {
		t.Fatalf("a linked human admin: %+v", a)
	}
	// Ana's GitHub login maps to her alias, which resolves to her.
	var anaGitHub, ghost map[string]any
	for _, a := range rows(admins) {
		if a["system"] == "github" && strings.HasPrefix(a["role"].(string), "org owner") {
			if a["person"] == ana {
				anaGitHub = a
			} else {
				ghost = a
			}
		}
	}
	if anaGitHub == nil || anaGitHub["linked"] != true {
		t.Fatalf("ana-dev links to ana through people.yaml and her alias: %+v", rows(admins))
	}
	if ghost == nil || ghost["unowned"] != true || !unlinked[ghost["id"].(string)] {
		t.Fatalf("an unlinked GitHub owner shows as unowned: %+v", ghost)
	}
	var owners []map[string]any
	for _, a := range rows(admins) {
		if a["system"] == "gcp" && a["role"] == "roles/owner" {
			owners = append(owners, a)
		}
	}
	if len(owners) != 2 {
		t.Fatalf("%+v", owners)
	}
	for _, a := range owners {
		switch a["kind"] {
		case "person":
			if a["person"] != ana || a["production"] != true {
				t.Fatalf("ana is owner directly, through her alias: %+v", a)
			}
		case "group":
			want := []any{string(personID("cy@acme.example")), string(personID("ext@partner.example"))}
			slices.SortFunc(want, func(a, b any) int { return strings.Compare(a.(string), b.(string)) })
			if a["linked"] != true || !slices.Equal(a["people"].([]any), want) || a["current"] != false {
				t.Fatalf("an owner through a group links to its people, nested groups and a cycle included: %+v", a)
			}
		}
	}
	sec := find("gcp", "service_account", "roles/iam.securityAdmin")
	if sec["unowned"] != true || !unlinked[sec["id"].(string)] {
		t.Fatalf("an admin service account with no owner shows as unowned: %+v", sec)
	}
	owned := 0
	for _, a := range rows(admins) {
		if a["kind"] == "service_account" && a["role"] == "roles/editor" {
			if a["owner"] == "platform-team" || a["owner"] == "google-managed" {
				owned++
			}
		}
	}
	if owned != 2 {
		t.Fatalf("ci is owned by owners.yaml and the service agent by Google: %+v", rows(admins))
	}
	if a := find("gcp", "person", "projects/acme-prod/roles/deployer"); a["power_known"] != false || a["linked"] != true {
		t.Fatalf("a custom role nobody could read is listed, never harmless: %+v", a)
	}
	if a := find("github", "person", "admin of acme/api"); a["linked"] != true {
		t.Fatalf("cy-acme maps case-insensitively: %+v", a)
	}
}

func TestPeopleAccountsJoinEverySystem(t *testing.T) {
	res, _ := runPeople(t, peopleEstate{})
	acc, _ := factData(t, res.Graph, "people.accounts")
	by := map[string]map[string]any{}
	for _, r := range rows(acc) {
		by[r["email"].(string)] = r
	}
	ana := by["ana@acme.example"]
	if !slices.Equal(ana["systems"].([]any), []any{"gcp", "github", "google"}) || ana["external"] != false {
		t.Fatalf("%+v", ana)
	}
	if gh := ana["github"].(map[string]any); gh["present"] != true || gh["org_role"] != "admin" {
		t.Fatalf("%+v", gh)
	}
	cy := by["cy@acme.example"]
	roles := cy["gcp"].(map[string]any)["roles"].([]any)
	if len(roles) != 2 {
		t.Fatalf("%+v", roles)
	}
	vias := []string{}
	for _, r := range roles {
		m := r.(map[string]any)
		vias = append(vias, m["role"].(string)+" "+m["via"].(string))
	}
	slices.Sort(vias)
	if !slices.Equal(vias, []string{"projects/acme-prod/roles/deployer direct", "roles/owner group"}) {
		t.Fatalf("%v", vias)
	}
	if ext := by["ext@partner.example"]; ext["external"] != true || len(ext["systems"].([]any)) != 0 {
		t.Fatalf("a group member outside the domain is an external person: %+v", ext)
	}
	if fr := by["friend@mail.example"]; fr["external"] != true || !slices.Equal(fr["systems"].([]any), []any{"gcp"}) {
		t.Fatalf("a GCP user outside the domain still gets a person: %+v", fr)
	}
	if dee := by["dee@acme.example"]; dee["leaver"] != true || dee["google"].(map[string]any)["present"] != true {
		t.Fatalf("%+v", dee)
	}
	if !slices.Equal(acc["systems_read"].([]any), []any{"google", "gcp", "github"}) || acc["group_members_known"] != false {
		t.Fatalf("%+v", acc)
	}
	if acc["production_basis"] != "" {
		t.Fatal("acme-prod is named production")
	}
}

// A leaver has the same person ID as their accounts, and linking keeps their
// leaver node, so hr.leavers still sees someone who has an account.
func TestLeaversLineUpWithPeople(t *testing.T) {
	res, _ := runPeople(t, peopleEstate{})
	id := personID("dee@acme.example")
	n, ok := res.Graph.Get(id)
	if !ok || n.Kind != graph.KindLeaver || n.Attrs["leave_date"] != "2026-10-01" {
		t.Fatalf("the leaver node was replaced: %+v", n)
	}
	found := false
	for _, e := range res.Graph.Edges(graph.EdgeSamePerson) {
		found = found || (e.From == id && e.To == graph.ID("google:user/"+salt.Email("dee@acme.example")))
	}
	if !found {
		t.Fatal("the leaver is not linked to their Google account")
	}
	def, _ := facts.Lookup("hr.leavers")
	r, _ := def.Fn(res.Graph, facts.Args{Now: testNow})
	if len(r.Data.([]any)) != 1 {
		t.Fatalf("hr.leavers lost a leaver with an account: %+v", r.Data)
	}
}

// Nothing a person is known by, an email or a GitHub login, lands in a
// snapshot or a diff, and the new ID prefixes pass the record scanner.
func TestNoEmailOrLoginReachesARecord(t *testing.T) {
	res, c := runPeople(t, peopleEstate{})
	c.Scope.Now = testNow.AddDate(0, 0, 7)
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	var files []string
	_ = filepath.WalkDir(c.Records, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !strings.Contains(p, string(filepath.Separator)+"tags"+string(filepath.Separator)) {
			files = append(files, p)
		}
		return err
	})
	if len(files) < 2 {
		t.Fatalf("records: %v", files)
	}
	for _, p := range files {
		b, _ := os.ReadFile(p)
		for _, s := range []string{"ana@acme.example", "ana.s@acme.example", "cy@acme.example", "ext@partner.example", "friend@mail.example",
			"dee@acme.example", "admins@acme.example", "readers@acme.example", "Ana-Dev", "ghost-owner", "cy-acme"} {
			if strings.Contains(string(b), s) {
				t.Errorf("%s holds %s", p, s)
			}
		}
	}
	snap := graph.TakeSnapshot(res.Graph, testNow)
	before, _ := json.Marshal(snap)
	if n := tag.ScanSnapshot(&snap, salt); n != 0 {
		t.Fatalf("the scanner replaced %d values", n)
	}
	after, _ := json.Marshal(snap)
	if string(before) != string(after) {
		t.Fatal("the scanner changed a person, group or owner ID")
	}
	for _, n := range snap.Nodes {
		b, _ := json.Marshal(n.Attrs)
		if strings.Contains(string(b), "@acme.example") || strings.Contains(string(b), "@partner.example") || strings.Contains(string(b), "@mail.example") {
			t.Errorf("%s holds an address in its attributes: %s", n.ID, b)
		}
	}
}
