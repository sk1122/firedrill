package run

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
)

// Two patterns from the people facts, for the People and Graph screens. Both
// read the facts drills read, so a screen never disagrees with a verdict.

// CutPoint is a person who alone is a path or a single point of failure.
type CutPoint struct {
	Person  string // person ID
	Subject string // the repo, project or org it is about
	Why     string
}

// OrphanedPower is an admin or destructive principal no person or owner
// answers for.
type OrphanedPower struct {
	System, Kind, ID, Role, Reason string
}

func peopleFact(g graph.Reader, name string, now time.Time) (map[string]any, bool) {
	def, ok := facts.Lookup(name)
	if !ok {
		return nil, false
	}
	r, err := def.Fn(g, facts.Args{Now: now})
	if err != nil {
		return nil, false
	}
	m, ok := r.Data.(map[string]any)
	return m, ok
}

func foundRows(m map[string]any) []map[string]any {
	var out []map[string]any
	list, _ := m["found"].([]any)
	for _, x := range list {
		if row, ok := x.(map[string]any); ok {
			out = append(out, row)
		}
	}
	return out
}

func strList(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// ProductionRepos lists the repos that deploy to an environment named
// production.
func ProductionRepos(g graph.Reader) map[string]bool {
	out := map[string]bool{}
	for _, e := range g.Edges(graph.EdgeDeploysTo) {
		if strings.HasSuffix(string(e.To), "/production") {
			out[strings.TrimPrefix(string(e.From), "github:repo/")] = true
		}
	}
	return out
}

// CutPoints finds people who alone can get code to production, because they
// can bypass review on a repo that deploys there, and people who are the only
// person holding admin over a GCP project, the GitHub org or Google
// Workspace. A subject is left out when any of its admins is unknown or
// answers to nobody, since then nobody can say the person is alone.
func CutPoints(g graph.Reader, now time.Time) []CutPoint {
	var out []CutPoint
	prod := ProductionRepos(g)
	if powers, ok := peopleFact(g, "people.powers", now); ok {
		for _, p := range foundRows(powers) {
			id, _ := p["id"].(string)
			for _, repo := range strList(p["github_bypass"]) {
				if !prod[repo] {
					continue
				}
				why := "can bypass review on " + repo + ", which deploys to production"
				if pd := strList(p["prod_destructive"]); len(pd) > 0 {
					why += ", and can delete data in " + strings.Join(pd, ", ")
				}
				out = append(out, CutPoint{Person: id, Subject: repo, Why: why})
			}
		}
	}
	if admins, ok := peopleFact(g, "people.admins", now); ok {
		type subject struct {
			people  map[string]bool
			unclear bool
		}
		subjects := map[string]*subject{}
		var order []string
		for _, a := range foundRows(admins) {
			name := ""
			switch sys, _ := a["system"].(string); sys {
			case "gcp":
				name = "GCP project " + fmt.Sprint(a["project"])
			case "google":
				name = "Google Workspace"
			case "github":
				role, _ := a["role"].(string)
				org, ok := strings.CutPrefix(role, "org owner of ")
				if !ok {
					continue
				}
				name = "GitHub org " + org
			}
			s := subjects[name]
			if s == nil {
				s = &subject{people: map[string]bool{}}
				subjects[name] = s
				order = append(order, name)
			}
			known := a["power_known"] == true && a["members_known"] == true
			if !known || a["unowned"] == true {
				s.unclear = true
			}
			if a["linked"] != true {
				continue
			}
			for _, p := range strList(a["people"]) {
				s.people[p] = true
			}
		}
		sort.Strings(order)
		for _, name := range order {
			s := subjects[name]
			if s.unclear || len(s.people) != 1 {
				continue
			}
			for p := range s.people {
				out = append(out, CutPoint{Person: p, Subject: name, Why: "the only person with admin over " + name})
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Person != out[j].Person {
			return out[i].Person < out[j].Person
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

// orphanKinds are unlinked principals that hold power by being listed at all:
// people.unlinked lists a service account, an app or a deploy key only when it
// has power, and a domain or public grant only when its role does.
var orphanKinds = map[string]bool{"service_account": true, "app": true, "deploy_key": true, "domain": true, "public": true}

// Orphans lists principals with admin or destructive power that no person and
// no owner answers for. A group whose members could not be read is unknown,
// not orphaned, and is left out.
func Orphans(g graph.Reader, now time.Time) []OrphanedPower {
	seen := map[string]int{}
	var out []OrphanedPower
	add := func(o OrphanedPower) {
		if i, ok := seen[o.ID]; ok {
			if o.Role != "" && !strings.Contains(out[i].Role, o.Role) {
				out[i].Role += ", " + o.Role
			}
			return
		}
		seen[o.ID] = len(out)
		out = append(out, o)
	}
	if admins, ok := peopleFact(g, "people.admins", now); ok {
		for _, a := range foundRows(admins) {
			if a["unowned"] != true || a["members_known"] != true || a["power_known"] != true {
				continue
			}
			role := fmt.Sprint(a["role"])
			if p, _ := a["project"].(string); p != "" {
				role += " in " + p
			}
			add(OrphanedPower{System: fmt.Sprint(a["system"]), Kind: fmt.Sprint(a["kind"]), ID: fmt.Sprint(a["id"]), Role: role,
				Reason: "admin with no person and no owner"})
		}
	}
	if un, ok := peopleFact(g, "people.unlinked", now); ok {
		for _, u := range foundRows(un) {
			kind, _ := u["kind"].(string)
			if !orphanKinds[kind] && u["is_admin"] != true {
				continue
			}
			if kind == "group" {
				continue
			}
			add(OrphanedPower{System: fmt.Sprint(u["system"]), Kind: kind, ID: fmt.Sprint(u["id"]), Reason: fmt.Sprint(u["reason"])})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
