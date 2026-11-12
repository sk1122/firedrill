package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

const saAddress = "deployer@acme-prod.iam.gserviceaccount.com"

// fakeSAKey is a private_key_id: it identifies a key, it is not the key.
const fakeSAKey = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c"

// outsideSnapshot adds to the mixed estate what can be reached from outside:
// a public bucket in production, a service account key in a public bundle and
// in a file the agent reads, a third-party app with Gmail access granted by
// Ana, an outside collaborator with write on acme/api, and an MCP server given
// Ana's token.
func outsideSnapshot(t *testing.T) graph.Snapshot {
	t.Helper()
	s := mixedSnapshot(t)
	add := func(id graph.ID, kind string, attrs map[string]any) {
		s.Nodes = append(s.Nodes, graph.Node{ID: id, Kind: kind, Attrs: attrs})
	}
	edge := func(from, to graph.ID, kind string) {
		s.Edges = append(s.Edges, graph.Edge{From: from, To: to, Kind: kind})
	}
	for i, n := range s.Nodes {
		if n.Kind == graph.KindGCPBinding && n.Attrs["member_type"] == "service_account" {
			s.Nodes[i].Attrs["member"] = saAddress
		}
		if n.Kind == graph.KindAgentConfig {
			servers := n.Attrs["mcp_servers"].([]any)
			servers[0].(map[string]any)["credentials"] = []any{"secret:" + viewSalt.Sum(fakeToken), "var:GITHUB_TOKEN"}
		}
	}
	add("gcp:bucket/acme-prod-exports", graph.KindGCPBucket, map[string]any{"project": "acme-prod", "name": "acme-prod-exports", "public_grants": []any{"allUsers:objectViewer"}})
	edge("gcp:project/acme-prod", "gcp:bucket/acme-prod-exports", graph.EdgeOwns)
	add("host:www.acme.example", graph.KindHost, map[string]any{"domain": "acme.example", "host": "www.acme.example"})
	add("host:old.acme.example", graph.KindHost, map[string]any{"domain": "acme.example", "host": "old.acme.example"})
	add("dns:old.acme.example", graph.KindDNSRecord, map[string]any{"resolves": false})
	keyHash := viewSalt.Sum("fake-sa-key-file")
	add(graph.ID("public-secret:www.acme.example/app.js#"+keyHash), graph.KindPublicSecret, map[string]any{"domain": "acme.example", "host": "www.acme.example",
		"path": "/app.js", "kind": "gcp_service_account_key", "hash": keyHash, "key_id": fakeSAKey, "client_side": false})
	add(graph.ID("gcp:key/acme-prod/"+fakeSAKey), graph.KindGCPKey, map[string]any{"project": "acme-prod", "service_account": saAddress, "key_id": fakeSAKey, "disabled": false})
	add(graph.ID("secret:"+keyHash+"@acme/api/deploy/sa.json:1"), graph.KindSecretSeen, map[string]any{"repo": "acme/api", "kind": "gcp_service_account_key",
		"file": "deploy/sa.json", "hash": keyHash, "agent_readable": true, "key_id": fakeSAKey})
	add(graph.ID("secret:"+keyHash), graph.KindSecret, nil)
	edge(graph.ID("secret:"+keyHash), "file:acme/api/deploy/sa.json", graph.EdgeFoundIn)
	add("google:oauth-app/123.apps.googleusercontent.com", graph.KindOAuthApp, map[string]any{"client_id": "123.apps.googleusercontent.com", "name": "Mail Helper",
		"sensitive_scopes": []any{"https://mail.google.com/"}})
	edge("google:oauth-app/123.apps.googleusercontent.com", pid("ana@acme.example"), graph.EdgeGrantedTo)
	outside := graph.ID("github:user/" + viewSalt.Sum("contractor-x"))
	add(outside, graph.KindGitHubUser, map[string]any{"org": "acme", "org_role": "outside", "type": "user"})
	edge(outside, "github:repo/acme/api", graph.EdgeWritesTo)
	add("page-script:www.acme.example/cdn.example.net", graph.KindPageScript, map[string]any{"host": "www.acme.example", "script_host": "cdn.example.net", "has_integrity": false, "owned": false})
	return s
}

func TestOutsideAndSecretPages(t *testing.T) {
	snap := outsideSnapshot(t)
	dir, b := buildViews(t, &snap, nil)
	if n := checkLinks(t, dir); n < 30 {
		t.Fatalf("only %d links checked", n)
	}
	banned := append(append([]string{}, fakes...), saAddress, "contractor-x", "fake-sa-key-file")
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			body := read(t, p)
			for _, f := range banned {
				if strings.Contains(body, f) {
					t.Errorf("%s shows %s", p, f)
				}
			}
		}
		return err
	})

	out := read(t, filepath.Join(dir, "graph/outside.html"))
	svg := svgOf(t, out)
	for _, want := range []string{"anyone on the internet", "public grant (anyone on the internet)", "acme-prod-exports",
		"Mail Helper", "<title>granted_to</title>", "<title>writes_to</title>", "is this key (matched by key ID)", "acts as this service account"} {
		if !strings.Contains(svg, want) {
			t.Errorf("outside drawing lacks %q", want)
		}
	}
	// A host that no longer resolves, and an external script, reach no
	// production within three hops, so they are not drawn.
	if strings.Contains(svg, "old.acme.example") || strings.Contains(svg, "cdn.example.net") {
		t.Error("only paths that reach production are drawn")
	}
	var page GraphPage
	for _, g := range b.Views.Graphs {
		if g.File == "outside.html" {
			page = g
		}
	}
	if page.Nodes == 0 || page.Nodes > MaxDrawn || page.Zones[0].Nodes < 2 || page.Zones[3].Nodes < 2 || len(page.Notes) < 4 {
		t.Fatalf("%+v", page.Zones)
	}
	if !strings.Contains(out, "outside starting points reach") {
		t.Fatal(page.Lead)
	}

	// Ana's token: seen in two places, readable by the agent, given to an MCP server.
	tok := "graph/secret-" + viewSalt.Sum(fakeToken)[:12] + ".html"
	sp := read(t, filepath.Join(dir, tok))
	ssvg := svgOf(t, sp)
	for _, want := range []string{"acme/web/.env", "can read", "given as a credential", "mcp:acme/api/fs"} {
		if !strings.Contains(ssvg, want) && !strings.Contains(sp, want) {
			t.Errorf("token page lacks %q", want)
		}
	}
	if !strings.Contains(sp, "What accepts it is not known") || !strings.Contains(sp, "given to MCP server acme/api/fs") {
		t.Error("an unmatched token says what accepts it is not known")
	}
	// The service account key: public, agent-readable, accepted by Google Cloud.
	keyHash := viewSalt.Sum("fake-sa-key-file")
	kp := read(t, filepath.Join(dir, "graph/secret-"+keyHash[:12]+".html"))
	ksvg := svgOf(t, kp)
	for _, want := range []string{"served in a public bundle", "is this key", "acts as this service account", "roles/editor"} {
		if !strings.Contains(ksvg, want) {
			t.Errorf("key page drawing lacks %q", want)
		}
	}
	if !strings.Contains(kp, "accepted by Google Cloud as a key of service account deployer in acme-prod") || !strings.Contains(kp, "served publicly at www.acme.example/app.js") {
		t.Error(kp)
	}

	agents := read(t, filepath.Join(dir, "agents.html"))
	for _, want := range []string{"Keys behind them", `href="` + tok + `"`, `href="graph/secret-` + keyHash[:12] + `.html"`, "GCP, service account deployer in acme-prod",
		`<span class="fail">admin</span>`, "can delete: roles/editor on acme-prod"} {
		if !strings.Contains(agents, want) {
			t.Errorf("agents page lacks %q", want)
		}
	}
	// The public secret's item page links to its page.
	item := read(t, filepath.Join(dir, "items", tagSlug("public-secret:www.acme.example/app.js#"+keyHash)+".html"))
	if !strings.Contains(item, `href="../graph/secret-`+keyHash[:12]+`.html"`) {
		t.Errorf("item page lacks the secret link:\n%s", item)
	}
	index := read(t, filepath.Join(dir, "index.html"))
	if !strings.Contains(index, `href="graph/outside.html"`) {
		t.Error("the board links the outside page")
	}
}

// Secrets get pages up to the bound, in fingerprint order; one seen once and
// read by no agent gets none.
func TestSecretPagesAreBounded(t *testing.T) {
	snap := mixedSnapshot(t)
	for i := range MaxSecretPages + 10 {
		h := viewSalt.Sum(fmt.Sprintf("tok-%d", i))
		id := graph.ID("secret:" + h)
		snap.Nodes = append(snap.Nodes, graph.Node{ID: id, Kind: graph.KindSecret})
		snap.Edges = append(snap.Edges, graph.Edge{From: id, To: graph.ID(fmt.Sprintf("file:acme/r%d/.env", i)), Kind: graph.EdgeFoundIn},
			graph.Edge{From: id, To: graph.ID(fmt.Sprintf("file:acme/s%d/.env", i)), Kind: graph.EdgeFoundIn})
	}
	once := viewSalt.Sum("seen-once")
	snap.Nodes = append(snap.Nodes, graph.Node{ID: graph.ID("secret:" + once), Kind: graph.KindSecret})
	snap.Edges = append(snap.Edges, graph.Edge{From: graph.ID("secret:" + once), To: "file:acme/x/.env", Kind: graph.EdgeFoundIn})
	b, _ := json.Marshal(snap)
	var s graph.Snapshot
	_ = json.Unmarshal(b, &s)
	dir, board := buildViews(t, &s, nil)
	pages := 0
	for _, g := range board.Views.Graphs {
		if strings.HasPrefix(g.File, "secret-") {
			pages++
			if g.Nodes > MaxDrawn {
				t.Fatalf("%s drew %d", g.File, g.Nodes)
			}
		}
	}
	if pages != MaxSecretPages || board.Views.SecretPagesCut != 11 {
		t.Fatalf("%d pages, %d cut", pages, board.Views.SecretPagesCut)
	}
	if _, err := os.Stat(filepath.Join(dir, "graph/secret-"+once[:12]+".html")); err == nil {
		t.Fatal("a secret seen once, by no agent, has no page")
	}
	if !strings.Contains(read(t, filepath.Join(dir, "agents.html")), "11 more secrets have no") {
		t.Fatal("the Agents page says the bound cut some")
	}
}

func tagSlug(s string) string { return tag.Slug(s) }
