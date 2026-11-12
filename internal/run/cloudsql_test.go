package run

import (
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// sqlOff is a project the gcp connector found has the Cloud SQL Admin API
// turned off: a clean read with nothing in it.
func sqlOff(g *graph.Graph, project string) {
	group := "the Cloud SQL Admin API is not turned on in {projects}, so there is no Cloud SQL instance there to read"
	node(g, string(graph.ScanID("gcp_backups", project)), graph.KindScan, map[string]any{"scanner": "gcp_backups", "scope": project,
		"inspected": int64(0), "note": strings.ReplaceAll(group, "{projects}", project), "note_group": group})
}

// sqlUnread is a project whose Cloud SQL could not be looked at, because the
// API is off in the project calls are billed to.
func sqlUnread(g *graph.Graph, project string) {
	group := "Cloud SQL could not be read in {projects}, where the Cloud SQL Admin API is on: turn on sqladmin.googleapis.com in projects/999, the project Firedrill's calls are billed to"
	node(g, string(graph.ScanID("gcp_backups", project)), graph.KindScan, map[string]any{"scanner": "gcp_backups", "scope": project,
		"inspected": int64(0), "partial": strings.ReplaceAll(group, "{projects}", project), "partial_group": group, "unread": true})
}

// cloudSQLCases are the recovery drills over projects whose Cloud SQL was
// not, or could not be, read.
func cloudSQLCases() []drillCase {
	return []drillCase{
		{"recovery/backups-separate-and-retained", tag.NA, "Cloud SQL off in every project", func(g *graph.Graph) {
			settings(g, 1)
			sqlOff(g, "acme-prod")
			sqlOff(g, "acme-dev")
		}},
		{"recovery/backups-separate-and-retained", tag.Warn, "Cloud SQL could not be read in two projects", func(g *graph.Graph) {
			settings(g, 1)
			sqlUnread(g, "acme-prod")
			sqlUnread(g, "acme-dev")
			sqlOff(g, "acme-web")
		}},
		{"recovery/backups-separate-and-retained", tag.Warn, "one project read clean, another unreadable", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			database(g, "gcp", "ledger", true, 14, "yes", "")
			sqlUnread(g, "acme-dev")
		}},
		{"recovery/restore-exercised", tag.NA, "Cloud SQL off in every project", func(g *graph.Graph) {
			settings(g, 1)
			sqlOff(g, "acme-prod")
		}},
		{"recovery/restore-exercised", tag.Warn, "Cloud SQL could not be read", func(g *graph.Graph) {
			settings(g, 1)
			sqlUnread(g, "acme-prod")
		}},
	}
}

// The reason names every project that could not be read on one line, with
// what to turn on, once.
func TestUnreadCloudSQLIsOneLine(t *testing.T) {
	g := graph.New()
	settings(g, 1)
	sqlUnread(g, "acme-prod")
	sqlUnread(g, "acme-dev")
	sqlOff(g, "acme-web")
	got := Decide(loadDrill(t, "recovery/backups-separate-and-retained"), g, Options{Now: testNow, Available: allConnectors})
	want := "could read only part: Cloud SQL could not be read in acme-dev, acme-prod, where the Cloud SQL Admin API is on: turn on sqladmin.googleapis.com in projects/999, the project Firedrill's calls are billed to"
	if got[0].Verdict != tag.Warn || got[0].Reason != want {
		t.Fatalf("%s %q", got[0].Verdict, got[0].Reason)
	}
	if got := ExitCode(got, ""); got != 0 {
		t.Fatalf("a project Firedrill could not look at warns; it does not stop the run: exit %d", got)
	}
}
