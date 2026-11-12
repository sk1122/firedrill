package run

import (
	"strings"
	"testing"
)

func TestCutPointsAndOrphansOverTheMixedEstate(t *testing.T) {
	res, _ := runPeople(t, peopleEstate{})
	ana := string(personID("ana@acme.example"))
	cuts := CutPoints(res.Graph, testNow)
	var got []string
	for _, c := range cuts {
		if c.Person != ana {
			t.Errorf("only ana is a cut point here: %+v", c)
		}
		got = append(got, c.Subject+": "+c.Why)
	}
	want := []string{
		"Google Workspace: the only person with admin over Google Workspace",
		"acme/api: can bypass review on acme/api, which deploys to production, and can delete data in acme-prod",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// acme-prod has three people through Owner, and a custom role nobody
	// could read; the org has an owner not mapped to a person. Neither is a cut
	// point, since nobody can say one person is alone there.
	for _, c := range cuts {
		if strings.Contains(c.Subject, "acme-prod") || strings.Contains(c.Subject, "GitHub org") {
			t.Errorf("%+v", c)
		}
	}

	orphans := Orphans(res.Graph, testNow)
	kinds := map[string]bool{}
	for _, o := range orphans {
		kinds[o.System+" "+o.Kind] = true
		if strings.Contains(o.ID, "google:group/") || strings.Contains(o.Role, "roles/viewer") {
			t.Errorf("an unread group is unknown, not orphaned: %+v", o)
		}
		if strings.Contains(o.ID, "@") {
			t.Errorf("an orphan is named by ID only: %+v", o)
		}
	}
	for _, k := range []string{"gcp service_account", "github app"} {
		if !kinds[k] {
			t.Errorf("missing orphan %s: %+v", k, orphans)
		}
	}
	// ghost-owner is a person's account Firedrill could not link: unverified,
	// not orphaned.
	if len(orphans) != 2 || kinds["github person"] {
		t.Fatalf("the deployer service account and the release app, got %+v", orphans)
	}
}
