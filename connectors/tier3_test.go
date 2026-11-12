package connectors_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/connectors/configsrc"
	"github.com/sk1122/firedrill/connectors/ctlog"
	"github.com/sk1122/firedrill/connectors/dns"
	"github.com/sk1122/firedrill/connectors/web"
	"github.com/sk1122/firedrill/internal/config"
	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/report"
	"github.com/sk1122/firedrill/internal/run"
	"github.com/sk1122/firedrill/internal/tag"
)

// Fake secrets, built by concatenation so no scanner reads this file as
// holding one.
var (
	fakeKeyID   = "0123456789abcdef" + "0123456789abcdef01234567"
	fakePEMBody = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYw" + "ggSiAgEAAoIBAQC7acmeFakeKeyMaterial"
	fakePEM     = "-----BEGIN " + "PRIVATE KEY-----\\n" + fakePEMBody + "\\n" + fakePEMBody + "\\n-----END " + "PRIVATE KEY-----\\n"
	fakeStripe  = "sk_" + "live_" + "51AcmeAbCdEfGhIjKlMnOp"
	fakeDBPass  = "Hx7pQ2" + "mZ9vL4wR"
	fakeBrowser = "AIza" + "SyA1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tUvw"
)

// tier3Site serves an owned site: a home page loading scripts from other
// hosts, a bundle holding a service account key and a browser key, and its
// source map, whose sources hold a Stripe secret and a database URL.
func tier3Site() http.HandlerFunc {
	home := `<!doctype html><html><head>
<script src="/assets/app.js"></script>
<script async src="https://cdn.adtech.example/tag/v3/loader.js?client=acme&token=` + fakeStripe + `"></script>
<script crossorigin="anonymous" integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC" src='//cdn.jsdelivr.net/npm/acme-widgets@2.1.0/dist/widgets.min.js'></script>
<link rel="modulepreload" href="https://static.acme.com/js/vendor.js">
<!-- <script src="https://old.tracker.example/t.js"></script> -->
</head><body>home</body></html>`
	bundle := `!function(){var c=JSON.parse('{"type":"service_account","project_id":"acme-prod","private_key_id":"` + fakeKeyID +
		`","private_key":"` + fakePEM + `"}');var m={apiKey:"` + fakeBrowser + `"};}();
//# sourceMappingURL=app.js.map`
	src := "const stripe = '" + fakeStripe + "';\nconst DATABASE_URL = 'postgres://app:" + fakeDBPass + "@db.acme.internal:5432/orders';\n"
	srcJSON := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(src)
	sourceMap := `{"version":3,"sources":["src/pay.ts"],"sourcesContent":["` + srcJSON + `"],"mappings":"AAAA"}`
	return site(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, home)
		case "/assets/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = io.WriteString(w, bundle)
		case "/assets/app.js.map":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, sourceMap)
		default:
			http.NotFound(w, nil)
		}
	})
}

// webRun runs drills against the fake site with records written, returning
// the outcomes, every request made, and the run's config.
func webRun(t *testing.T, ids []string, handler http.HandlerFunc, records string, at time.Time) ([]*run.Outcome, []string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	var seen []string
	tr := rewrite{server: srv, seen: &seen}
	ct := ctlog.New()
	ct.Next, ct.Limit, ct.Burst = tr, 1000, 1000
	w := web.New()
	w.Next, w.Limit, w.Burst = tr, 1000, 1000
	d := dns.New()
	d.Resolver = fakeDNS{}
	root := writeRepo(t, "proj", map[string]string{})
	p := &config.Project{Dir: filepath.Join(root, ".firedrill")}
	p.Config.Domains = []string{"acme.com"}
	p.Hosts = []config.Host{{Host: "acme.com", Owner: "@a"}, {Host: "www.acme.com", Owner: "@a"}}
	var drills []*drill.Drill
	for _, id := range ids {
		drills = append(drills, drillOf(t, id))
	}
	c := run.Config{Project: p, Drills: drills,
		Connectors: []connector.Connector{configsrc.New(), ct, d, w},
		Scope: connector.Scope{Project: p, Now: at, Log: &connector.CallLog{}, Hasher: graph.NewHasher("s"),
			VerifiedDomains: []string{"acme.com"}},
		Stream: "local", Records: records, WriteRecords: true}
	res, err := run.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if res.Fatal != "" {
		t.Fatal(res.Fatal)
	}
	return res.Outcomes, seen
}

func outcomeOf(t *testing.T, list []*run.Outcome, id string) *run.Outcome {
	t.Helper()
	for _, o := range list {
		if o.Drill.ID == id {
			return o
		}
	}
	t.Fatalf("no outcome for %s", id)
	return nil
}

// The two web drills read only what the source-map check already fetched: the
// same requests, to the same hosts, and never a script on another host.
func TestTier3WebDrillsMakeNoExtraRequests(t *testing.T) {
	_, before := webRun(t, []string{"doors/no-public-source-maps"}, tier3Site(), t.TempDir(), now)
	outs, after := webRun(t, []string{"doors/no-public-source-maps", "doors/no-live-key-in-public-bundle", "doors/third-party-scripts-pinned"},
		tier3Site(), t.TempDir(), now)
	sort.Strings(before)
	sort.Strings(after)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("the new drills changed the requests:\nbefore %v\nafter  %v", before, after)
	}
	pages := 0
	for _, s := range after {
		host := strings.SplitN(strings.TrimPrefix(s, "GET "), "/", 2)[0]
		if host != "crt.sh" && !connector.UnderDomain(host, "acme.com") {
			t.Errorf("a request left the verified domain: %s", s)
		}
		if !strings.HasPrefix(s, "GET ") {
			t.Errorf("not a GET: %s", s)
		}
		if host != "crt.sh" && !contains(web.APIDocPaths, "/"+strings.SplitN(s, "/", 2)[1]) {
			pages++
		}
	}
	// Two hosts, each: the home page, one same-host bundle and its map. The
	// scripts on other hosts are listed from the page, never requested.
	if pages != 6 {
		t.Fatalf("got %d home, bundle and map requests, want 6: %v", pages, after)
	}

	o := outcomeOf(t, outs, "doors/no-live-key-in-public-bundle")
	if o.Verdict != tag.Fail {
		t.Fatalf("a service account key, a Stripe secret and a database URL in public JavaScript: %s %s", o.Verdict, o.Reason)
	}
	o = outcomeOf(t, outs, "doors/third-party-scripts-pinned")
	if o.Verdict != tag.Fail || !strings.Contains(o.Reason, "cdn.adtech.example") || strings.Contains(o.Reason, "jsdelivr") {
		t.Fatalf("the CDN script with no integrity hash fails it, the pinned one does not: %s %s", o.Verdict, o.Reason)
	}
	if o := outcomeOf(t, outs, "doors/no-public-source-maps"); o.Verdict != tag.Fail {
		t.Fatalf("the source-map drill works as before: %s %s", o.Verdict, o.Reason)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// A secret planted in a public bundle and its source map never reaches a
// record: not a node, tag, snapshot, diff or call log, and not the report.
func TestNoPlantedSecretInAnyRecordOrReport(t *testing.T) {
	records := t.TempDir()
	ids := []string{"doors/no-public-source-maps", "doors/no-live-key-in-public-bundle", "doors/third-party-scripts-pinned"}
	webRun(t, ids, tier3Site(), records, now)
	outs, _ := webRun(t, ids, tier3Site(), records, now.AddDate(0, 0, 7))
	if o := outcomeOf(t, outs, "doors/no-live-key-in-public-bundle"); o.Verdict != tag.Fail {
		t.Fatalf("%s %s", o.Verdict, o.Reason)
	}

	var drills []*drill.Drill
	for _, id := range ids {
		drills = append(drills, drillOf(t, id))
	}
	at := now.AddDate(0, 0, 7)
	est, err := graph.RebuildEstate(filepath.Join(records, "snapshots"), at)
	if err != nil {
		t.Fatal(err)
	}
	board, err := report.Build(tag.Store{Root: records}, est, drills, at, run.RulesOf(config.Config{}))
	if err != nil {
		t.Fatal(err)
	}
	changes, err := run.LatestDiff(records)
	if err != nil {
		t.Fatal(err)
	}
	report.AddChanges(board, changes)
	files, err := run.RunSnapshots(filepath.Join(records, "snapshots"))
	if err != nil || len(files) == 0 {
		t.Fatal(err, files)
	}
	snap, err := graph.ReadSnapshot(files[len(files)-1])
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, n := range snap.Nodes {
		if n.Kind == graph.KindPublicSecret {
			found++
		}
	}
	if found < 4 {
		t.Fatalf("the snapshot holds %d public secrets, want the key, the browser key, the Stripe secret and the database URL", found)
	}
	report.AddViews(board, &snap, changes, at)
	site := t.TempDir()
	if _, err := report.Write(site, board); err != nil {
		t.Fatal(err)
	}

	read := 0
	for _, dir := range []string{records, site} {
		_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			b, _ := os.ReadFile(p)
			if strings.HasSuffix(p, ".gz") {
				z, err := gzip.NewReader(bytes.NewReader(b))
				if err != nil {
					t.Fatal(err)
				}
				b, _ = io.ReadAll(z)
			}
			read++
			for _, s := range []string{fakeStripe, fakePEMBody, fakeDBPass, fakeBrowser, "token=", "client=acme"} {
				if strings.Contains(string(b), s) {
					t.Errorf("%s holds %q", p, s)
				}
			}
			return nil
		})
	}
	if read < 10 {
		t.Fatalf("read only %d files", read)
	}
}
