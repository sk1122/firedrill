package report

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
	"github.com/sk1122/firedrill/packs"
)

// googleFake writes one Workspace user, an admin in the second run, and
// answers the Reports API as Google would, with addresses in the clear.
type googleFake struct{ admin bool }

func (g *googleFake) Name() string { return "google" }
func (g *googleFake) Collections() []connector.Collection {
	return []connector.Collection{{Name: "users"}}
}
func (g *googleFake) Available(connector.Scope) (bool, string) { return true, "" }
func (g *googleFake) Collect(_ context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	id := graph.ID("google:user/" + s.Hasher.Email("bo@acme.example"))
	out.Node(graph.Node{ID: id, Kind: graph.KindIdentityUser, Source: "google", SeenAt: s.Now,
		Attrs: map[string]any{"is_admin": g.admin, "is_delegated_admin": false, "suspended": false}, Private: map[string]any{"email": "bo@acme.example"}})
	graph.WriteScan(out, "google", "google_users", "", 1, "", s.Now)
	return nil
}
func (g *googleFake) AuditSource() string             { return connector.AuditGoogle }
func (g *googleFake) AuditReady(connector.Scope) bool { return true }
func (g *googleFake) Audit(_ context.Context, s connector.Scope, q connector.AuditQuery) (connector.AuditAnswer, error) {
	at := q.From.Add(24 * time.Hour)
	return connector.AuditAnswer{Events: []connector.AuditEvent{
		{At: at, Actor: "ana@acme.example", ActorKind: "user", Params: map[string][]string{"USER_EMAIL": {"bo@acme.example"}}},
		{At: at, Actor: "Mallory.Admin@acme.example", ActorKind: "user", Params: map[string][]string{"USER_EMAIL": {"someone-else@acme.example"}}},
	}}, nil
}

func TestNoAuditAddressReachesRecordsOrPages(t *testing.T) {
	data, _ := packs.FS.ReadFile("access/admins-use-mfa.drill.yaml")
	d, _ := drill.Load("access/admins-use-mfa", data)
	records := t.TempDir()
	c := run.Config{Project: &config.Project{}, Drills: []*drill.Drill{d}, Stream: "local", RanBy: "test", Records: records, WriteRecords: true,
		Scope: connector.Scope{Now: now.AddDate(0, 0, -7), Log: &connector.CallLog{}, Hasher: viewSalt}}
	c.Connectors = []connector.Connector{&googleFake{}}
	if _, err := run.Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	c.Connectors = []connector.Connector{&googleFake{admin: true}}
	c.Scope.Now = now
	res, err := run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	var named bool
	for _, ch := range res.Diff.Changes {
		if ch.ActorSource == connector.AuditGoogle {
			named = true
			if ch.Actor != "google:user/"+viewSalt.Email("ana@acme.example") && ch.Actor != "person:"+viewSalt.Email("ana@acme.example") {
				t.Fatalf("%+v", ch)
			}
			if len(ch.OtherActors) != 0 {
				t.Fatal("an event about someone else is not this change's")
			}
		}
	}
	if !named {
		t.Fatalf("no actor named: %+v", res.Diff.Changes)
	}
	board, err := Build(tag.Store{Root: records}, nil, []*drill.Drill{d}, now, run.Rules{})
	if err != nil {
		t.Fatal(err)
	}
	AddChanges(board, res.Diff)
	AddViews(board, nil, res.Diff, now)
	out := t.TempDir()
	if _, err := Write(out, board); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(read(t, filepath.Join(out, "changes.html")), "by Google user "+viewSalt.Email("ana@acme.example")[:8]+" (google_reports") {
		t.Error("the Changes page names the actor by short ID")
	}
	j := BuildJSON(res, now, 0)
	jsonPath := filepath.Join(out, "result.json")
	if err := WriteJSON(jsonPath, j); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "summary.md"), []byte(SummaryWith(j, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{records, out} {
		_ = filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil || e.IsDir() || strings.HasSuffix(p, ".gz") {
				return err
			}
			b, _ := os.ReadFile(p)
			low := strings.ToLower(string(b))
			for _, addr := range []string{"ana@acme.example", "mallory.admin@acme.example", "bo@acme.example", "someone-else@acme.example"} {
				if strings.Contains(low, addr) {
					t.Errorf("%s holds %s", p, addr)
				}
			}
			return nil
		})
	}
}
