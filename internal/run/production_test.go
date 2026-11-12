package run

import (
	"slices"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/facts"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// markProduction lists repos under production in config, as configsrc writes
// them on the settings node, keeping whatever else the node holds.
func markProduction(g *graph.Graph, repos ...string) {
	attrs := map[string]any{"review_days": int64(180), "min_retention_days": int64(7), "restore_days": int64(90), "production_markers": int64(0)}
	if n, ok := g.Get("config:settings"); ok {
		attrs = n.Attrs
	}
	list := []any{}
	for _, r := range repos {
		list = append(list, r)
	}
	attrs["production_repos"] = list
	node(g, "config:settings", graph.KindConfigSettings, attrs)
}

// namedEnv is a GitHub environment of acme/api with the given name.
func namedEnv(g *graph.Graph, name string, reviewers []any, protected, adminBypass bool) {
	node(g, "github:env/acme/api/"+name, graph.KindEnvironment, map[string]any{
		"required_reviewers": reviewers, "prevent_self_review": len(reviewers) > 0, "admin_bypass": adminBypass,
		"protected_branches_only": protected})
}

// productionCases are the cases for a repo marked production in config, and
// for production environments not named exactly production.
func productionCases() []drillCase {
	return []drillCase{
		{"change/prod-deploy-gated", tag.Pass, "environment named Prod", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			namedEnv(g, "Prod", []any{}, true, false)
		}},
		{"change/prod-deploy-gated", tag.Fail, "marked production with no environment", func(g *graph.Graph) {
			// Nothing in GitHub limits a deploy to protected branches.
			ghRepo(g, "team", true)
			markProduction(g, "acme/api")
		}},
		{"change/prod-deploy-gated", tag.Fail, "the least protected of two production environments", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			namedEnv(g, "production", []any{}, true, false)
			namedEnv(g, "live", []any{}, false, false)
		}},
		{"change/no-solo-ship", tag.Warn, "marked production with no environment, main protected", func(g *graph.Graph) {
			// Nobody can merge alone, but how a deploy is approved cannot be read.
			ghRepo(g, "team", true)
			branchRule(g, 1, "none", false)
			markProduction(g, "acme/api")
		}},
		{"change/no-solo-ship", tag.Fail, "marked production with no environment, bypass allowed", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			branchRule(g, 1, "allowed", false)
			markProduction(g, "acme/api")
		}},
		{"paths/no-single-person-code-to-prod-data", tag.Fail, "marked production with no environment", func(g *graph.Graph) {
			ghRepo(g, "team", true)
			apiRule(g, true, "ana")
			readGitHub(g)
			markProduction(g, "acme/api")
			project(g, "acme-prod", true)
			ana := human(g, "ana", "gcp", "github")
			repoEdge(g, githubUser(g, ana, "ana", "admin"), graph.EdgeCanBypass)
			role(g, ana, "acme-prod", "roles/owner", "user", true, true, true, true)
		}},
	}
}

func envFact(t *testing.T, g *graph.Graph) map[string]any {
	t.Helper()
	def, _ := facts.Lookup("github.environment")
	r, err := def.Fn(g, facts.Args{Values: map[string]any{"name": "production"}, Target: map[string]any{"name": "acme/api"}, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return r.Data.(map[string]any)
}

func reposFact(t *testing.T, g *graph.Graph) map[string]any {
	t.Helper()
	def, _ := facts.Lookup("github.repos")
	r, err := def.Fn(g, facts.Args{Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	return r.Data.([]any)[0].(map[string]any)
}

// Production environments are matched by name, ignoring case, from the
// defaults and github.production_environments, and judged by the weakest.
func TestProductionEnvironmentNames(t *testing.T) {
	g := graph.New()
	ghRepo(g, "enterprise", true)
	namedEnv(g, "staging", []any{}, false, true)
	if env := envFact(t, g); env["exists"] != false || len(env["names"].([]any)) != 0 || reposFact(t, g)["production"] != false {
		t.Fatalf("staging is not production: %+v", env)
	}
	namedEnv(g, "PROD", []any{"@a", "@b"}, true, false)
	namedEnv(g, "Live", []any{"@a"}, true, true)
	env := envFact(t, g)
	if env["exists"] != true || !slices.Equal(env["names"].([]any), []any{"Live", "PROD"}) {
		t.Fatalf("%+v", env)
	}
	if len(env["required_reviewers"].([]any)) != 1 || env["admin_bypass"] != true || env["protected_branches_only"] != true {
		t.Fatalf("judged by the weakest: %+v", env)
	}
	if reposFact(t, g)["production"] != true {
		t.Fatal("a production environment marks the repo production")
	}
	// A name added in config counts too.
	g = graph.New()
	ghRepo(g, "team", true)
	namedEnv(g, "release", []any{}, true, false)
	if envFact(t, g)["exists"] != false {
		t.Fatal("release is not production by default")
	}
	node(g, "config:settings", graph.KindConfigSettings, map[string]any{"production_environments": []any{"production", "prod", "live", "release"}})
	if env := envFact(t, g); env["exists"] != true || !slices.Equal(env["names"].([]any), []any{"release"}) {
		t.Fatalf("%+v", env)
	}
	// A repo listed under production, by any case.
	g = graph.New()
	ghRepo(g, "team", true)
	markProduction(g, "Acme/API")
	if reposFact(t, g)["production"] != true {
		t.Fatal("a repo listed under production is production")
	}
}

// With nothing marked production the reason says how to mark a repo.
func TestNotProductionReasonSaysHowToMarkOne(t *testing.T) {
	for _, id := range []string{"change/prod-deploy-gated", "change/no-solo-ship", "paths/no-single-person-code-to-prod-data"} {
		g := graph.New()
		ghRepo(g, "team", true)
		branchRule(g, 1, "none", false)
		project(g, "acme-prod", true)
		readGitHub(g)
		got := Decide(loadDrill(t, id), g, Options{Now: testNow, Available: allConnectors})
		if got[0].Verdict != tag.NA || !strings.Contains(got[0].Reason, "github.production_environments") ||
			!strings.Contains(got[0].Reason, "production in .firedrill/config.yaml") {
			t.Errorf("%s: %s %q", id, got[0].Verdict, got[0].Reason)
		}
	}
}
