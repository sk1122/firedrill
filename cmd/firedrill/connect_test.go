package main

import (
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/graph"
)

// connect gcp says once which projects Cloud SQL could not be read in, not
// once per project.
func TestConnectGroupsAProblemSharedByProjects(t *testing.T) {
	group := "Cloud SQL could not be read in {projects}, where the Cloud SQL Admin API is on: turn on sqladmin.googleapis.com in acme-quota, the project Firedrill's calls are billed to"
	off := "the Cloud SQL Admin API is not turned on in {projects}, so there is no Cloud SQL instance there to read"
	scan := func(project string, attrs map[string]any) graph.Node {
		attrs["scanner"], attrs["scope"] = "gcp_backups", project
		return graph.Node{ID: graph.ScanID("gcp_backups", project), Kind: graph.KindScan, Attrs: attrs}
	}
	lines := scanLines([]graph.Node{
		scan("acme-a", map[string]any{"partial": strings.ReplaceAll(group, "{projects}", "acme-a"), "partial_group": group}),
		scan("acme-c", map[string]any{"partial": strings.ReplaceAll(group, "{projects}", "acme-c"), "partial_group": group}),
		scan("acme-b", map[string]any{"partial": strings.ReplaceAll(group, "{projects}", "acme-b"), "partial_group": group}),
		scan("acme-d", map[string]any{"note": strings.ReplaceAll(off, "{projects}", "acme-d"), "note_group": off}),
		scan("acme-e", map[string]any{"note": strings.ReplaceAll(off, "{projects}", "acme-e"), "note_group": off}),
		scan("acme-f", map[string]any{"error": "could not read Cloud SQL in acme-f: HTTP 500", "partial": "could not read Cloud SQL in acme-f: HTTP 500"}),
	})
	want := []string{
		"Not readable yet: could not read Cloud SQL in acme-f: HTTP 500",
		"Read only in part: " + strings.ReplaceAll(group, "{projects}", "acme-a, acme-b, acme-c"),
		"Note: " + strings.ReplaceAll(off, "{projects}", "acme-d, acme-e"),
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}
