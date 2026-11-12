package run

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
)

// auditing is a GitHub fake that also answers audit questions.
type auditing struct {
	fake
	answer func(connector.AuditQuery) (connector.AuditAnswer, error)
	asked  []connector.AuditQuery
}

func (a *auditing) AuditSource() string               { return connector.AuditGitHub }
func (a *auditing) AuditReady(s connector.Scope) bool { return a.available }
func (a *auditing) Audit(_ context.Context, _ connector.Scope, q connector.AuditQuery) (connector.AuditAnswer, error) {
	a.asked = append(a.asked, q)
	return a.answer(q)
}

// The two runs a week apart: bypass turned on and approvals dropped on
// acme/api, and a new repo, so three changes.
func auditedRuns(t *testing.T, conn func(write func(graph.Writer)) connector.Connector, cap int) (*Result, Config) {
	t.Helper()
	d := []*drill.Drill{loadDrill(t, "change/human-review-required")}
	c := baseConfig(t, d, conn(githubWriter(1, "none")))
	c.Project.Config.GitHub.Org = "acme"
	c.AuditCap = cap
	if _, err := Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Connectors = []connector.Connector{conn(func(w graph.Writer) {
		githubWriter(0, "allowed")(w)
		w.Node(graph.Node{ID: "github:repo/acme/web", Kind: graph.KindGitHubRepo, Source: "github", SeenAt: testNow, Attrs: map[string]any{"name": "acme/web", "private": true}})
	})}
	c.Scope.Now = testNow.AddDate(0, 0, 7)
	res, err := Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return res, c
}

func changesJSON(t *testing.T, rec *DiffRecord) string {
	t.Helper()
	b, err := json.Marshal(rec.Changes)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// With no audit access the diff is what it was, byte for byte, apart from the
// note that says which source was not readable.
func TestNoAuditAccessLeavesTheDiffAsItWas(t *testing.T) {
	plain, _ := auditedRuns(t, func(w func(graph.Writer)) connector.Connector {
		return &fake{name: "github", available: true, write: w}
	}, 0)
	var conn *auditing
	denied, _ := auditedRuns(t, func(w func(graph.Writer)) connector.Connector {
		conn = &auditing{fake: fake{name: "github", available: true, write: w}, answer: func(connector.AuditQuery) (connector.AuditAnswer, error) {
			return connector.AuditAnswer{}, fmt.Errorf("%w: HTTP 404 (the audit log needs GitHub Enterprise Cloud)", connector.ErrAuditUnreadable)
		}}
		return conn
	}, 0)
	if plain.Diff.Audit != nil {
		t.Fatal("no audit source, no note")
	}
	if changesJSON(t, plain.Diff) != changesJSON(t, denied.Diff) {
		t.Fatalf("the diff changed:\n%s\n%s", changesJSON(t, plain.Diff), changesJSON(t, denied.Diff))
	}
	a := denied.Diff.Audit
	if a == nil || len(a.NotReadable) != 1 || !strings.HasPrefix(a.NotReadable[0], "github_audit: audit source not readable: HTTP 404") || a.Calls != 1 {
		t.Fatalf("one call, then the source is known unreadable: %+v", a)
	}
	// Byte for byte once the note is set aside.
	p, d := *plain.Diff, *denied.Diff
	p.Audit, d.Audit, p.SHA256, d.SHA256, p.Previous, d.Previous = nil, nil, "", "", "", ""
	p.FromSHA256, d.FromSHA256, p.ToSHA256, d.ToSHA256 = "", "", "", ""
	pb, _ := json.Marshal(p)
	db, _ := json.Marshal(d)
	if string(pb) != string(db) {
		t.Fatalf("\n%s\n%s", pb, db)
	}
	// Only the window between the two snapshots was asked about, for the repo.
	q := conn.asked[0]
	if !q.From.Equal(denied.Diff.From) || !q.To.Equal(denied.Diff.To) || q.Repo != "acme/api" || q.Org != "acme" {
		t.Fatalf("%+v", q)
	}
}

func TestAuditNamesTheActorWithoutTheirLogin(t *testing.T) {
	var conn *auditing
	res, c := auditedRuns(t, func(w func(graph.Writer)) connector.Connector {
		conn = &auditing{fake: fake{name: "github", available: true, write: func(g graph.Writer) {
			w(g)
			// ana's account, linked to her as the link step does.
			g.Node(graph.Node{ID: graph.ID("github:user/" + graph.NewHasher("salt").Sum("ana-dev")), Kind: graph.KindGitHubUser, Source: "github",
				Attrs: map[string]any{"org": "acme", "org_role": "admin", "type": "user"}, Private: map[string]any{"login": "Ana-Dev"}})
		}}, answer: func(q connector.AuditQuery) (connector.AuditAnswer, error) {
			if q.Action != "repository_ruleset" {
				return connector.AuditAnswer{}, nil
			}
			in := testNow.AddDate(0, 0, 3)
			ev := func(actor string, at time.Time) connector.AuditEvent {
				return connector.AuditEvent{At: at, Actor: actor, ActorKind: "user", Params: map[string][]string{"repo": {"acme/api"}}}
			}
			return connector.AuditAnswer{Events: []connector.AuditEvent{
				ev("Ana-Dev", in), ev("bo-dev", in.Add(-time.Hour)), ev("cy-dev", in.Add(-2*time.Hour)), ev("dee-dev", in.Add(-3*time.Hour)),
				ev("eve-dev", in.Add(-4*time.Hour)),
				// Outside the window: never counted.
				ev("old-admin", testNow.AddDate(0, 0, -30)),
				{At: in, Actor: "renovate[bot]", ActorKind: "bot", Params: map[string][]string{"repo": {"acme/web"}}},
			}}, nil
		}}
		return conn
	}, 0)
	var ruleChanges int
	for _, ch := range res.Diff.Changes {
		if ch.Kind != graph.KindBranchRule {
			if ch.Actor != "" {
				t.Errorf("a change no source covers keeps its window: %+v", ch)
			}
			continue
		}
		ruleChanges++
		want := "github:user/" + graph.NewHasher("salt").Sum("ana-dev")
		if ch.Actor != want || ch.ActorSource != connector.AuditGitHub || ch.ActedAt == nil || len(ch.OtherActors) != 2 || ch.MoreActors != 2 {
			t.Fatalf("%+v", ch)
		}
		if got := ch.Actors(); !strings.HasPrefix(got, "GitHub user ") || !strings.HasSuffix(got, "and 2 more") {
			t.Fatal(got)
		}
	}
	if ruleChanges != 2 {
		t.Fatalf("%d branch rule changes", ruleChanges)
	}
	// Two questions (rulesets and branch protection), each asked once for
	// both changes.
	if len(conn.asked) != 2 || res.Diff.Audit.Calls != 2 {
		t.Fatalf("%d asked, %+v", len(conn.asked), res.Diff.Audit)
	}
	// No login from the audit answer reaches a record.
	_ = filepath.WalkDir(c.Records, func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() || strings.HasSuffix(p, ".gz") {
			return err
		}
		b, _ := os.ReadFile(p)
		for _, login := range []string{"Ana-Dev", "ana-dev", "bo-dev", "cy-dev", "dee-dev", "eve-dev", "old-admin"} {
			if strings.Contains(string(b), login) {
				t.Errorf("%s holds %s", p, login)
			}
		}
		return nil
	})
	snaps, _ := RunSnapshots(filepath.Join(c.Records, "snapshots"))
	for _, s := range snaps {
		snap, _ := graph.ReadSnapshot(s)
		b, _ := json.Marshal(snap)
		if strings.Contains(strings.ToLower(string(b)), "ana-dev") {
			t.Errorf("%s holds a login", s)
		}
	}
}

// Linked to a person, the actor is the person; grouping follows the actor.
func TestAuditActorIsThePersonWhenLinked(t *testing.T) {
	h := graph.NewHasher("salt")
	g := graph.New()
	acct := graph.ID("github:user/" + h.Sum("ana-dev"))
	person := graph.ID("person:" + h.Email("ana@acme.example"))
	g.Edge(graph.Edge{From: person, To: acct, Kind: graph.EdgeSamePerson})
	if got := actorID(connector.AuditEvent{Actor: "Ana-Dev", ActorKind: "user"}, connector.AuditGitHub, g, h); got != string(person) {
		t.Fatal(got)
	}
	gu := graph.ID("google:user/" + h.Email("bo@acme.example"))
	g.Edge(graph.Edge{From: graph.ID("person:" + h.Email("bo@acme.example")), To: gu, Kind: graph.EdgeSamePerson})
	if got := actorID(connector.AuditEvent{Actor: "Bo@Acme.example", ActorKind: "user"}, connector.AuditGoogle, g, h); got != "person:"+h.Email("bo@acme.example") {
		t.Fatal(got)
	}
	if got := actorID(connector.AuditEvent{Actor: "deployer@acme-prod.iam.gserviceaccount.com", ActorKind: "service_account"}, connector.AuditGCP, g, h); got != "service account deployer (acme-prod)" {
		t.Fatal(got)
	}
	if got := actorID(connector.AuditEvent{Actor: "stranger@else.example", ActorKind: "user"}, connector.AuditGCP, g, h); got != "google:user/"+h.Email("stranger@else.example") {
		t.Fatal(got)
	}
	groups := GroupChanges([]graph.Change{
		{Type: graph.ChangeBypassOn, Weakening: true, Actor: string(person)},
		{Type: graph.ChangeNewAdmin, Weakening: true, Person: PersonShortID(person)},
		{Type: graph.ChangeWeakened, Weakening: true, Actor: "service account deployer (acme-prod)"},
	})
	if len(groups) != 2 || len(groups[0].Changes) != 2 || groups[0].Title != "Person "+PersonShortID(person) || groups[1].Title != "Changed by service account deployer (acme-prod)" {
		t.Fatalf("%+v", groups)
	}
}

// The audit step makes at most its cap of calls in a run, and says how many
// questions it left unasked.
func TestAuditCallCap(t *testing.T) {
	var conn *auditing
	res, _ := auditedRuns(t, func(w func(graph.Writer)) connector.Connector {
		conn = &auditing{fake: fake{name: "github", available: true, write: w}, answer: func(connector.AuditQuery) (connector.AuditAnswer, error) {
			return connector.AuditAnswer{}, nil
		}}
		return conn
	}, 1)
	a := res.Diff.Audit
	if len(conn.asked) != 1 || a.Calls != 1 || a.Cap != 1 || a.NotAsked != 1 {
		t.Fatalf("%d asked, %+v", len(conn.asked), a)
	}
	if DefaultAuditCap != 50 {
		t.Fatal("the documented cap is 50")
	}
}

// A source not connected on purpose is never asked, whatever it holds.
func TestAuditAsksOnlyConnectedSources(t *testing.T) {
	var conn *auditing
	res, _ := auditedRuns(t, func(w func(graph.Writer)) connector.Connector {
		conn = &auditing{fake: fake{name: "github", available: false, write: w}, answer: func(connector.AuditQuery) (connector.AuditAnswer, error) {
			t.Fatal("asked before connect")
			return connector.AuditAnswer{}, nil
		}}
		return conn
	}, 0)
	if len(conn.asked) != 0 || (res.Diff != nil && res.Diff.Audit != nil) {
		t.Fatal("no audit before connect")
	}
}
