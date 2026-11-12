package tag

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sk1122/firedrill/internal/graph"
)

func TestScanTagHashesSecretsAndLeavesStructuredFields(t *testing.T) {
	h := graph.NewHasher("salt")
	tg := &Tag{Evidence: Evidence{Facts: map[string]any{
		"doc": map[string]any{"password": "Zx8mQ2pL9vT4rW7yB1nC6dF3", "name": "plain value"},
		"secrets": map[string]any{"found": []any{map[string]any{
			"hash": "0123456789abcdef0123456789abcdef", "key_id": "AKIAIOSFODNN7ABCDEFG", "file": "scripts/domains.sh",
		}}},
	}}}
	ScanTag(tg, h)
	b, _ := json.Marshal(tg)
	s := string(b)
	if strings.Contains(s, "Zx8mQ2pL9vT4rW7yB1nC6dF3") {
		t.Fatal("a raw secret reached the record")
	}
	if !strings.Contains(s, "AKIAIOSFODNN7ABCDEFG") || !strings.Contains(s, "0123456789abcdef0123456789abcdef") {
		t.Fatalf("structured fields must pass untouched: %s", s)
	}
	if len(tg.Header.ScannerNotes) != 1 {
		t.Fatalf("want one scanner note: %v", tg.Header.ScannerNotes)
	}
}

func TestScanSnapshot(t *testing.T) {
	s := graph.Snapshot{Nodes: []graph.Node{{ID: "n", Attrs: map[string]any{"v": "sk_live_abcdefghijklmnop", "ok": "hello"}}}}
	if n := ScanSnapshot(&s, graph.NewHasher("s")); n != 1 {
		t.Fatalf("replaced %d", n)
	}
	if v := s.Nodes[0].Attrs["v"].(string); !strings.HasPrefix(v, "secret:") {
		t.Fatal(v)
	}
	if s.Nodes[0].Attrs["ok"] != "hello" {
		t.Fatal("ordinary values stay")
	}
}

// fakeSecret is not a real credential; it has the shape LooksLikeSecret accepts.
const fakeSecret = "Zx8mQ2pL9vT4rW7yB1nC6dF3"

func TestExemptKeysAreExemptByShapeNotName(t *testing.T) {
	h := graph.NewHasher("salt")
	for _, key := range []string{"keys", "credentials", "id", "hash", "key_id", "read"} {
		var notes []string
		got := ScanValue(map[string]any{key: []any{fakeSecret}, "x": map[string]any{key: fakeSecret}}, h, "w", &notes)
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), fakeSecret) || len(notes) != 2 {
			t.Errorf("%s: secret kept or notes %v: %s", key, notes, b)
		}
	}
	var notes []string
	got := ScanValue(map[string]any{"id": "id:" + fakeSecret, "read": "aws:" + fakeSecret}, h, "w", &notes)
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), fakeSecret) {
		t.Errorf("a prefixed secret passed: %s", b)
	}
}

func TestSafeShapesUnderExemptKeysAreUntouched(t *testing.T) {
	h := graph.NewHasher("salt")
	safe := []string{
		"0123456789abcdef0123456789abcdef",
		"secret:0123456789abcdef0123456789abcdef",
		"var:STRIPE_API_KEY",
		"AKIAIOSFODNN7ABCDEFG", "ASIAIOSFODNN7ABCDEFG",
		"aws:key/AKIAIOSFODNN7ABCDEFG",
		"github:repo/acme/api",
		"file:acme-api/config/prod.env",
		"gcp:key/acme-project/sa@acme-project.iam.gserviceaccount.com/0123456789abcdef0123456789abcdef01234567",
		"agent:acme-api/.mcp.json",
		"scan:secrets/acme-api",
		"host:db.acme.example",
	}
	for _, key := range []string{"keys", "credentials", "id"} {
		for _, v := range safe {
			var notes []string
			got := ScanValue(map[string]any{key: []any{v}}, h, "w", &notes).(map[string]any)[key].([]any)[0]
			if got != v || len(notes) != 0 {
				t.Errorf("%s: %q changed to %v (%v)", key, v, got, notes)
			}
		}
	}
}

func TestScanTagScansReasonAndConditionResults(t *testing.T) {
	h := graph.NewHasher("salt")
	tg := &Tag{
		Header: Header{
			Reason:     "query failed: bad token " + fakeSecret + " for aws:key/AKIAIOSFODNN7ABCDEFG",
			Conditions: []Condition{{Expr: "a", Result: "true"}, {Expr: "b", Result: "error: " + fakeSecret}},
		},
		Evidence: Evidence{Facts: map[string]any{}},
	}
	ScanTag(tg, h)
	b, _ := json.Marshal(tg)
	if strings.Contains(string(b), fakeSecret) {
		t.Fatalf("a secret reached the header: %s", b)
	}
	if !strings.Contains(tg.Header.Reason, "aws:key/AKIAIOSFODNN7ABCDEFG") || tg.Header.Conditions[0].Result != "true" {
		t.Fatalf("safe text changed: %+v", tg.Header)
	}
	if len(tg.Header.ScannerNotes) != 2 {
		t.Fatalf("notes: %v", tg.Header.ScannerNotes)
	}
}

func TestSecretNamesInWorkflowsSurvive(t *testing.T) {
	h := graph.NewHasher("salt")
	// Long names have the entropy of a secret, so they are kept by shape.
	names := []any{"ANTHROPIC_API_KEY", "SUPABASE_SERVICE_ROLE_KEY", "GOOGLE_APPLICATION_CREDENTIALS", "inherit"}
	var notes []string
	got := ScanValue(map[string]any{"secrets": names}, h, "w", &notes).(map[string]any)["secrets"].([]any)
	for i, n := range names {
		if got[i] != n {
			t.Errorf("%s changed to %v", n, got[i])
		}
	}
	if len(notes) != 0 {
		t.Errorf("notes: %v", notes)
	}
	// A secret under the same key is still replaced, whatever its case.
	upper := strings.ToUpper(fakeSecret)
	got = ScanValue(map[string]any{"secrets": []any{fakeSecret, upper, "DEPLOY_" + upper}}, h, "w", &notes).(map[string]any)["secrets"].([]any)
	for _, v := range got {
		if s, _ := v.(string); !strings.HasPrefix(s, "secret:") {
			t.Errorf("a secret passed as a name: %v", v)
		}
	}
}

func TestScanDiffKeepsNodeIDsAndHashesValues(t *testing.T) {
	const raw = "Zx8mQ2pL9vT4rW7yB1nC6dF3"
	ids := []graph.ID{
		"secret:0123456789abcdef0123456789abcdef@acme/api/scripts/deploy.sh:12",
		"github:branch-rule/acme/api/default",
		"github:workflow/acme/api/.github/workflows/release.yml",
		"agent:acme/api/.mcp.json",
		"aws:key/AKIAIOSFODNN7ABCDEFG",
		"google:user/aaaa1111bbbb2222cccc3333dddd4444",
		"gcp:binding/acme-prod/roles/owner/bbbb2222cccc3333dddd4444eeee5555",
	}
	d := graph.DiffResult{Skipped: []string{"aws: failed in the later run"}}
	for _, id := range ids {
		d.Changes = append(d.Changes, graph.Change{Subject: id, Summary: "new " + string(id) + " seen in acme/api/.env, secret 01234567",
			Edge: &graph.Edge{From: id, To: "file:acme/api/scripts/deploy.sh"}})
	}
	d.Changes = append(d.Changes, graph.Change{Subject: "github:env/acme/api/production", Attr: "required_reviewers",
		Summary: "reviewer " + raw + " removed", Before: []any{raw}, After: []any{}})
	if n := ScanDiff(&d, graph.NewHasher("salt")); n != 2 {
		t.Fatalf("replaced %d values, want 2", n)
	}
	for i, id := range ids {
		c := d.Changes[i]
		if c.Subject != id || c.Edge.From != id || c.Edge.To != "file:acme/api/scripts/deploy.sh" {
			t.Errorf("an ID was changed: %q -> %q", id, c.Subject)
		}
		if c.Summary != "new "+string(id)+" seen in acme/api/.env, secret 01234567" {
			t.Errorf("a safe summary was changed: %q", c.Summary)
		}
	}
	b, _ := json.Marshal(d)
	if strings.Contains(string(b), raw) {
		t.Fatalf("a raw value reached the diff: %s", b)
	}
	if d.Skipped[0] != "aws: failed in the later run" {
		t.Fatal(d.Skipped)
	}
}

func TestPackageNamesSurviveAndSecretsDoNot(t *testing.T) {
	h := graph.NewHasher("salt")
	row := map[string]any{
		"package": "@acme/mcp-filesystem-server-tools", "command": "acme-github-mcp-server", "version": "sha256:ab12ab12ab12",
		"host": "mcp.acme-tools.example", "install_scripts": []any{"electron-chromedriver", "@parcel/watcher-darwin-arm64", "node-pre-gyp-github"},
		"new_install_scripts": []any{"ghcr.io/acme/mcp", "acme_mcp_search", "better-sqlite3"},
		"cloud_key_secrets":   []any{"PROD_AWS_SECRET_ACCESS_KEY", "GOOGLE_APPLICATION_CREDENTIALS_JSON"},
	}
	var notes []string
	got := ScanValue(row, h, "w", &notes)
	if len(notes) != 0 {
		t.Fatalf("names were taken for secrets: %v\n%v", notes, got)
	}
	// A secret under the same keys is still replaced, alone, with a prefix or
	// as a UUID-shaped token.
	for _, key := range []string{"package", "command", "install_scripts", "new_install_scripts", "version", "cloud_key_secrets"} {
		for _, v := range []string{fakeSecret, "mcp-" + fakeSecret, "sk_live_abcdefghijklmnop", "6f1b9d2e-7c44-4a10-9e3b-2d5ac81f0e77"} {
			var notes []string
			out := ScanValue(map[string]any{key: []any{v}}, h, "w", &notes)
			b, _ := json.Marshal(out)
			if strings.Contains(string(b), v) {
				t.Errorf("%s: %s passed", key, v)
			}
		}
	}
}

func TestTier1FieldsSurviveAndSecretsDoNot(t *testing.T) {
	h := graph.NewHasher("salt")
	fullKey := "sk-ant-api03-" + "Zx8mQ2pL9vT4rW7yB1nC6dF3Zx8mQ2pL9vT4"
	attrs := map[string]any{
		"key_id": "apikey_01Rj2N8SVvo6BePZj99NhmiT", "workspace": "wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ", "project": "proj_Ab3dEf6hIj9kLm2n",
		"hint": "sk-ant-api03-R2D...igAA", "owner": "anthropic:user/user_01WxYzAbCdEfGhJkMnPqRsTu",
		"client_id": "1234567890-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com", "copy_detail": "cross-account vault 444455556666",
		"name": fullKey,
	}
	s := graph.Snapshot{Nodes: []graph.Node{
		{ID: "anthropic:key/apikey_01Rj2N8SVvo6BePZj99NhmiT", Attrs: attrs},
		{ID: "openai:key/proj_Ab3dEf6hIj9kLm2n/key_Zx8mQ2pL9vT4rW7y", Attrs: map[string]any{"key_id": fullKey}},
	}}
	if n := ScanSnapshot(&s, h); n != 2 {
		t.Fatalf("only the two full keys are replaced, got %d: %+v", n, s.Nodes)
	}
	got := s.Nodes[0].Attrs
	for _, k := range []string{"key_id", "workspace", "project", "hint", "owner", "client_id", "copy_detail"} {
		if got[k] != attrs[k] {
			t.Errorf("%s: %v became %v", k, attrs[k], got[k])
		}
	}
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), fullKey) {
		t.Fatal("a full key reached the snapshot")
	}
	for _, id := range []string{"anthropic:key/apikey_01Rj2N8SVvo6BePZj99NhmiT", "openai:key/proj_Ab3dEf6hIj9kLm2n/key_Zx8mQ2pL9vT4rW7y",
		"config-ai-key:anthropic/workspace/wrkspc_01JwQvzr7rXLA5AGx3HKfFUJ", "aws:db/111122223333/us-east-1/orders"} {
		if !safeShape(id) {
			t.Errorf("%s is a safe ID", id)
		}
	}
}

func TestGitHubLoginsSurviveAndSecretsDoNot(t *testing.T) {
	h := graph.NewHasher("salt")
	logins := []string{"ana-acme", "bo-acme", "x7k2q9vz4m8w", "q8z3m7x2k9v4w6p1r5t0", "dependabot[bot]", "Ana-Acme-2"}
	for _, l := range logins {
		var notes []string
		got := ScanValue(map[string]any{"people": []any{map[string]any{"login": l}}}, h, "w", &notes)
		b, _ := json.Marshal(got)
		if !strings.Contains(string(b), `"`+l+`"`) || len(notes) != 0 {
			t.Errorf("login %q was changed: %s %v", l, b, notes)
		}
	}
	secretsUnderLogin := []string{
		"ghp_" + "Zx8mQ2pL9vT4rW7yB1nC6dF3Zx8mQ2pL9vT4",
		"a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
		fakeSecret,
	}
	for _, v := range secretsUnderLogin {
		var notes []string
		got := ScanValue(map[string]any{"login": v}, h, "w", &notes)
		b, _ := json.Marshal(got)
		if strings.Contains(string(b), v) || len(notes) != 1 {
			t.Errorf("a secret under login passed: %s %v", b, notes)
		}
	}
	// The people collection's graph IDs survive under id.
	for _, id := range []string{"github:user/0123456789abcdef0123456789abcdef", "github:team/acme/platform",
		"github:org/acme", "github:app/123", "github:deploy-key/acme/api", "scan:github_repo_people/acme/api"} {
		if !safeShape(id) {
			t.Errorf("%s is a safe ID", id)
		}
	}
}
