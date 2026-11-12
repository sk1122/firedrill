package graph

import (
	"strings"
	"testing"
	"time"
)

// peopleRun is one run of a linked estate: Google users A and B, the admins
// group G that holds Owner on acme-prod, a group N that holds nothing, and the
// service account ci with an owner in owners.yaml. The second run adds B to G,
// gives G a member outside the domain, gives B a role that can delete data,
// adds A to N, and drops ci's owners.yaml entry.
func peopleRun(second, linkedBefore, classified bool) Snapshot {
	at := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)
	if second {
		at = at.Add(7 * 24 * time.Hour)
	}
	e := &estate{at: at, g: New()}
	userA, userB := ID("google:user/"+hashA), ID("google:user/"+hashB)
	personA, personB := ID("person:"+hashA), ID("person:"+hashB)
	g, n := ID("google:group/cccc3333dddd4444eeee5555ffff6666"), ID("google:group/dddd4444eeee5555ffff6666aaaa7777")
	own, ci := ID("gcp:binding/acme-prod/roles/owner/1111"), ID("gcp:binding/acme-prod/roles/editor/2222")
	e.scan("google", "google_groups", "", 2)
	e.node("config:settings", KindConfigSettings, "config", map[string]any{})
	e.node(userA, KindIdentityUser, "google", map[string]any{"is_admin": false})
	e.node(userB, KindIdentityUser, "google", map[string]any{"is_admin": false})
	e.node(g, KindGoogleGroup, "google", map[string]any{"members_known": true, "external_members": second, "all_users": false})
	e.node(n, KindGoogleGroup, "google", map[string]any{"members_known": true, "external_members": false, "all_users": false})
	e.node("gcp:project/acme-prod", KindGCPProject, "gcp", map[string]any{"name": "acme-prod", "member_domains": []any{}, "production": true})
	binding := func(id ID, role, member string, admin, destructive bool) {
		attrs := map[string]any{"project": "acme-prod", "role": role, "member_type": member, "conditional": false}
		if classified {
			attrs["is_admin"], attrs["destructive"], attrs["power_known"] = admin, destructive, true
		}
		e.node(id, KindGCPBinding, "gcp", attrs)
		e.edge("gcp:project/acme-prod", id, EdgeOwns, "gcp")
	}
	binding(own, "roles/owner", "group", true, true)
	binding(ci, "roles/editor", "service_account", true, true)
	e.edge(userA, g, EdgeMemberOf, "google")
	if linkedBefore || second {
		e.edge(g, own, EdgeBoundTo, "link")
		e.edge(personA, userA, EdgeSamePerson, "link")
		e.edge(personA, own, EdgeViaGroup, "link")
	}
	if !second {
		e.node("config-owner:ci@acme-prod.iam.gserviceaccount.com", KindConfigOwner, "config", map[string]any{"principal": "ci@acme-prod.iam.gserviceaccount.com", "owner": "platform-team"})
		e.edge("config-owner:ci@acme-prod.iam.gserviceaccount.com", ci, EdgeOwns, "link")
		return TakeSnapshot(e.g, at)
	}
	e.edge(personB, userB, EdgeSamePerson, "link")
	e.edge(userB, g, EdgeMemberOf, "google")
	e.edge(personB, own, EdgeViaGroup, "link")
	e.edge(userA, n, EdgeMemberOf, "google")
	del := ID("gcp:binding/acme-prod/roles/storage.objectAdmin/3333")
	binding(del, "roles/storage.objectAdmin", "user", false, true)
	e.edge(personB, del, EdgeSamePerson, "link")
	return TakeSnapshot(e.g, at)
}

func TestDiffPeopleLinking(t *testing.T) {
	d := Diff(peopleRun(false, true, true), peopleRun(true, true, true))
	got := map[string]Change{}
	for _, c := range d.Changes {
		got[c.Summary] = c
		if strings.Contains(c.Summary, "@") {
			t.Errorf("a summary holds an address: %s", c.Summary)
		}
	}
	for summary, typ := range map[string]string{
		"Google user bbbb2222 joined Google group cccc3333, which holds an admin GCP role":                       ChangeNewAdmin,
		"person bbbb2222 now holds roles/owner for a group (1111) in acme-prod through a group":                  ChangeNewAdmin,
		"Google group cccc3333: now has members outside the Workspace domain":                                    ChangeWeakened,
		"new grant that can delete data: roles/storage.objectAdmin for a user (3333) in acme-prod":               ChangeWeakened,
		"gone: owners.yaml entry for ci@acme-prod.iam.gserviceaccount.com; its principal no longer has an owner": ChangeWeakened,
	} {
		summary = noEmails(summary)
		c, ok := got[summary]
		if !ok || c.Type != typ || !c.Weakening {
			t.Errorf("missing weakening %q (%s): %+v", summary, typ, d.Changes)
		}
	}
	// Joining a group with no power is a plain change.
	plain, ok := got["new link: Google user aaaa1111 is a member of Google group dddd4444"]
	if !ok || plain.Weakening {
		t.Errorf("a group with no power: %+v", d.Changes)
	}

	// An earlier run from before linking, or from before roles were
	// classified, reads no link and no role power as new.
	d = Diff(peopleRun(false, false, false), peopleRun(false, true, true))
	if len(d.Changes) != 0 {
		t.Fatalf("an upgrade reads as changes: %+v", d.Changes)
	}

	// Groups not read in the later run: their edges are skipped, not removed.
	later := peopleRun(false, true, true)
	kept := later.Nodes[:0]
	for _, n := range later.Nodes {
		if n.Kind != KindScan {
			kept = append(kept, n)
		}
	}
	later.Nodes = kept
	d = Diff(peopleRun(false, true, true), later)
	for _, c := range d.Changes {
		if c.Edge != nil && (c.Edge.Kind == EdgeViaGroup || c.Edge.Kind == EdgeMemberOf) {
			t.Errorf("an unread group read as removed: %+v", c)
		}
	}
}
