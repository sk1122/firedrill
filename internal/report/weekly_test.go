package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
)

func weeklyDiff() *run.DiffRecord {
	at := now.Add(-time1h)
	bypass := graph.Edge{From: "github:user/" + graph.ID(viewSalt.Sum("ana-dev")), To: "github:repo/acme/api", Kind: graph.EdgeCanBypass}
	changes := []graph.Change{
		{Type: graph.ChangeBypassActor, Summary: "a GitHub user can now bypass review on acme/api", Subject: bypass.From, Edge: &bypass, System: "github", Weakening: true,
			Actor: "person:" + viewSalt.Email("ana@acme.example"), ActorSource: "github_audit", ActedAt: &at,
			OtherActors: []string{"github:user/" + viewSalt.Sum("bo-dev"), "GitHub app renovate"}, MoreActors: 2,
			CaughtBy: []graph.DrillRef{{Drill: "change/no-solo-ship", Target: "acme/api"}}},
		{Type: graph.ChangeNewAdmin, Summary: "Google user 1a2b3c4d: is_admin false → true", Subject: "google:user/x", System: "google", Weakening: true, Person: "1a2b3c4d"},
	}
	for i := range 60 {
		changes = append(changes, graph.Change{Type: graph.ChangeAdded, Summary: fmt.Sprintf("new repo acme/r%02d", i), Subject: graph.ID(fmt.Sprintf("github:repo/acme/r%02d", i)), System: "github"})
	}
	return &run.DiffRecord{DiffResult: graph.DiffResult{From: now.AddDate(0, 0, -7), To: now, Changes: changes, Skipped: []string{"gcp project acme-prod: failed in the later run"}},
		ToSnapshot: "2026-11-07T09-00-00Z.json.gz", Audit: &run.AuditNote{Cap: 50, Calls: 3, Asked: []string{"github_audit"}, NotReadable: []string{"google_reports: HTTP 403"}}}
}

const time1h = 3600 * 1e9

func TestJSONResultAndSummaryCarryTheDiff(t *testing.T) {
	res := &run.Result{Stream: "ci", Diff: weeklyDiff()}
	j := BuildJSON(res, now, 0)
	if j.Diff == nil || j.Diff.Weakening != 2 || j.Diff.Other != 60 || len(j.Diff.Changes) != 62 || j.Diff.Record != "2026-11-07T09-00-00Z.json" {
		t.Fatalf("%+v", j.Diff)
	}
	var first DiffEntry
	for _, c := range j.Diff.Changes {
		if c.Type == graph.ChangeBypassActor {
			first = c
		}
	}
	if !first.Weakening || first.ActorSource != "github_audit" || first.ActedAt == nil ||
		!strings.HasPrefix(first.Actor, "person ") || !strings.HasSuffix(first.Actor, "and 2 more") || len(first.CaughtBy) != 1 ||
		first.CaughtBy[0].Issue != "Firedrill: change/no-solo-ship on acme/api" {
		t.Fatalf("%+v", first)
	}
	b, _ := json.Marshal(j)
	// Only short hashed IDs: no full hash, no address, no login.
	for _, bad := range []string{"ana@acme.example", "ana-dev", "bo-dev", viewSalt.Email("ana@acme.example"), viewSalt.Sum("bo-dev")} {
		if strings.Contains(string(b), bad) {
			t.Errorf("the JSON result holds %q", bad)
		}
	}
	sum := SummaryWith(j, "https://github.com/acme/firedrill/issues")
	for _, want := range []string{"### What changed since the last run", "**2 weakening**, 60 other", "**Weakenings**", "**Other changes**",
		"by person " + viewSalt.Email("ana@acme.example")[:8], "and 2 more", "(github_audit)", "caught by `change/no-solo-ship` on `acme/api`",
		"([issue](https://github.com/acme/firedrill/issues?q=is%3Aissue+in%3Atitle+%22Firedrill%3A+change%2Fno-solo-ship+on+acme%2Fapi%22))",
		"…and 12 more", "**Not compared (1)**", "Audit source not readable", "person 1a2b3c4d"} {
		if !strings.Contains(sum, want) {
			t.Errorf("summary lacks %q:\n%s", want, sum)
		}
	}
	// Weakenings come first.
	if strings.Index(sum, "**Weakenings**") > strings.Index(sum, "**Other changes**") {
		t.Fatal("weakenings first")
	}
	if strings.Contains(sum, viewSalt.Email("ana@acme.example")) {
		t.Fatal("a full hash in the summary")
	}
	if s := SummaryWith(BuildJSON(&run.Result{}, now, 0), ""); !strings.Contains(s, "No earlier run of this stream to compare with.") {
		t.Fatal(s)
	}
}
