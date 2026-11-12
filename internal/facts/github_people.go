package facts

import (
	"fmt"
	"sort"
	"strings"

	"github.com/sk1122/firedrill/internal/graph"
)

// The scan records the GitHub people collection writes: one for the org, one
// per listed repo.
const (
	githubPeopleScanner     = "github_people"
	githubRepoPeopleScanner = "github_repo_people"
)

func registerGitHubPeople() {
	Register(Def{
		Name: "github.people", Connector: "github",
		Shape: List(Obj(map[string]*Shape{
			"id": Str, "login": Str, "org_role": Str, "teams": List(Str),
			"repos_admin": List(Str), "repos_write": List(Str), "repos_bypass": List(Str), "is_outside": Bool,
		})),
		Fn: githubPeople,
	})
	Register(Def{
		Name: "github.bypass_actors", Connector: "github", Args: []string{"branch"},
		Shape: Obj(map[string]*Shape{
			"known": Bool,
			"people": List(Obj(map[string]*Shape{
				"id": Str, "login": Str, "via": List(Str), "through": List(Str),
			})),
			"teams": List(Str),
			"apps":  List(Obj(map[string]*Shape{"id": Str, "kind": Str, "name": Str})),
			"count": Int,
		}),
		Fn: bypassActors,
	})
}

// peopleScans reads the people collection's scan records. An org record with
// an error is returned as an error, so drills give ERROR; a repo read only in
// part makes the result partial.
func peopleScans(g graph.Reader, fact string) ([]graph.ID, []string, error) {
	var read []graph.ID
	var partial []string
	orgSeen := false
	for _, n := range g.Nodes(graph.KindScan) {
		switch strAttr(n, "scanner") {
		case githubPeopleScanner:
			if msg := strAttr(n, "error"); msg != "" {
				return nil, nil, fmt.Errorf("%s: %s", fact, msg)
			}
			orgSeen = true
		case githubRepoPeopleScanner:
		default:
			continue
		}
		if p := strAttr(n, "partial"); p != "" {
			partial = append(partial, p)
		}
		read = append(read, n.ID)
	}
	if !orgSeen {
		return nil, nil, notCollected(fact, string(graph.ScanID(githubPeopleScanner, "")))
	}
	return read, partial, nil
}

// teamSlug names a team from its node, or from its ID when the node is missing.
func teamSlug(g graph.Reader, id graph.ID) string {
	if n, ok := g.Get(id); ok {
		if s := strAttr(n, "slug"); s != "" {
			return s
		}
	}
	s := string(id)
	return s[strings.LastIndex(s, "/")+1:]
}

func githubPeople(g graph.Reader, _ Args) (Result, error) {
	read, partial, err := peopleScans(g, "github.people")
	if err != nil {
		return Result{}, err
	}
	r := Result{Source: "api", Read: read, Partial: strings.Join(partial, "; ")}
	type links struct{ teams, admin, write, bypass map[string]bool }
	by := map[graph.ID]*links{}
	get := func(id graph.ID) *links {
		l := by[id]
		if l == nil {
			l = &links{teams: map[string]bool{}, admin: map[string]bool{}, write: map[string]bool{}, bypass: map[string]bool{}}
			by[id] = l
		}
		return l
	}
	for _, e := range g.Edges(graph.EdgeMemberOf) {
		if strings.HasPrefix(string(e.To), "github:team/") {
			get(e.From).teams[teamSlug(g, e.To)] = true
		}
	}
	repoEdges := map[string]func(*links) map[string]bool{
		graph.EdgeAdminOf:   func(l *links) map[string]bool { return l.admin },
		graph.EdgeWritesTo:  func(l *links) map[string]bool { return l.write },
		graph.EdgeCanBypass: func(l *links) map[string]bool { return l.bypass },
	}
	for kind, set := range repoEdges {
		for _, e := range g.Edges(kind) {
			if repo, ok := strings.CutPrefix(string(e.To), "github:repo/"); ok {
				set(get(e.From))[repo] = true
			}
		}
	}
	rows := []any{}
	for _, n := range g.Nodes(graph.KindGitHubUser) {
		if strAttr(n, "type") != "user" {
			continue
		}
		l := get(n.ID)
		login, _ := n.Private["login"].(string)
		rows = append(rows, map[string]any{
			"id": string(n.ID), "login": login, "org_role": strAttr(n, "org_role"),
			"teams": sortedKeys(l.teams), "repos_admin": sortedKeys(l.admin), "repos_write": sortedKeys(l.write),
			"repos_bypass": sortedKeys(l.bypass), "is_outside": strAttr(n, "org_role") == "outside",
		})
		r.Read = append(r.Read, n.ID)
	}
	r.Data = rows
	return r, nil
}

// bypassActors lists who may skip review on the target repo's branch rule,
// teams and roles expanded to people. When the list could not be read, known
// is false and nothing is listed: an empty list never stands for "unknown".
func bypassActors(g graph.Reader, a Args) (Result, error) {
	if _, _, err := peopleScans(g, "github.bypass_actors"); err != nil {
		return Result{}, err
	}
	repo := a.TargetName()
	branch := a.String("branch")
	if branch == "" {
		branch = "default"
	}
	scan, err := scanOrError(g, "github.bypass_actors", githubRepoPeopleScanner, repo)
	if err != nil {
		return Result{}, err
	}
	id := "github:branch-rule/" + repo + "/" + branch
	rule, ok := g.Get(graph.ID(id))
	if !ok {
		return Result{}, notCollected("github.bypass_actors", id)
	}
	src := strAttr(rule, "bypass_detail")
	if src == "" {
		src = "api"
	}
	r := Result{Source: src, Read: []graph.ID{scan.ID, rule.ID}, Partial: strAttr(scan, "partial")}
	known, _ := rule.Attrs["bypass_actors_known"].(bool)
	list, _ := rule.Attrs["bypass_actors"].([]any)
	type person struct{ via, through map[string]bool }
	people := map[string]*person{}
	teams := map[string]bool{}
	apps := []any{}
	seenApp := map[string]bool{}
	if known {
		for _, item := range list {
			row, _ := item.(map[string]any)
			kind, _ := row["kind"].(string)
			rid, _ := row["id"].(string)
			via, _ := row["via"].(string)
			switch kind {
			case "user":
				p := people[rid]
				if p == nil {
					p = &person{via: map[string]bool{}, through: map[string]bool{}}
					people[rid] = p
				}
				p.via[via] = true
				if th, _ := row["through"].(string); th != "" {
					p.through[th] = true
				}
			case "team":
				teams[rid] = true
			default:
				if seenApp[rid] {
					continue
				}
				seenApp[rid] = true
				name := ""
				if n, ok := g.Get(graph.ID(rid)); ok {
					name = strAttr(n, "name")
					r.Read = append(r.Read, n.ID)
				}
				apps = append(apps, map[string]any{"id": rid, "kind": kind, "name": name})
			}
		}
	}
	ids := make([]string, 0, len(people))
	for pid := range people {
		ids = append(ids, pid)
	}
	sort.Strings(ids)
	rows := []any{}
	for _, pid := range ids {
		login := ""
		if n, ok := g.Get(graph.ID(pid)); ok {
			login, _ = n.Private["login"].(string)
			r.Read = append(r.Read, n.ID)
		}
		rows = append(rows, map[string]any{"id": pid, "login": login,
			"via": sortedKeys(people[pid].via), "through": sortedKeys(people[pid].through)})
	}
	r.Data = map[string]any{
		"known": known, "people": rows, "teams": sortedKeys(teams), "apps": apps,
		"count": int64(len(rows) + len(apps)),
	}
	return r, nil
}
