package hub

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sk1122/firedrill/packs"
)

func starter(t *testing.T, name string) []byte {
	t.Helper()
	b, err := packs.FS.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// hubFiles is a small hub: one good drill, one without fixtures, one whose
// fixtures are wrong, and one at the wrong path.
func hubFiles(t *testing.T) map[string][]byte {
	good := starter(t, "change/no-force-push-main.drill.yaml")
	test := starter(t, "change/no-force-push-main.test.yaml")
	other := starter(t, "change/actions-pinned.drill.yaml")
	return map[string][]byte{
		"hub.yaml": []byte("name: Test hub\nofficial: [change]\n"),
		"drills/change/no-force-push-main.drill.yaml":  good,
		"drills/change/no-force-push-main.test.yaml":   test,
		"drills/change/actions-pinned.drill.yaml":      other,
		"drills/doors/misplaced.drill.yaml":            good,
		"drills/doors/misplaced.test.yaml":             test,
		"drills/agent/no-shared-agent-keys.drill.yaml": starter(t, "agent/no-shared-agent-keys.drill.yaml"),
		"drills/agent/no-shared-agent-keys.test.yaml":  bytes.Replace(starter(t, "agent/no-shared-agent-keys.test.yaml"), []byte("expect: FAIL"), []byte("expect: PASS"), 1),
		"README.md": []byte("not a drill"),
	}
}

func writeHub(t *testing.T, files map[string][]byte) string {
	dir := t.TempDir()
	for p, b := range files {
		full := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadDirChecksEveryDrill(t *testing.T) {
	h, err := LoadDir(writeHub(t, hubFiles(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Entries) != 3 {
		t.Fatalf("entries: %d", len(h.Entries))
	}
	e, ok := h.Get("change/no-force-push-main")
	if !ok || !e.Official || e.Cases != 3 || e.Pack != "change" || len(e.Facts) != 2 {
		t.Fatalf("%+v", e)
	}
	want := map[string]string{
		"drills/change/actions-pinned.drill.yaml":      "has no fixtures file",
		"drills/doors/misplaced.drill.yaml":            "does not match its path",
		"drills/agent/no-shared-agent-keys.drill.yaml": "fixtures: ",
	}
	for p, msg := range want {
		if !strings.Contains(h.Problems[p], msg) {
			t.Errorf("%s: got %q, want %q", p, h.Problems[p], msg)
		}
	}
	if len(h.Problems) != len(want) {
		t.Errorf("problems: %v", h.Problems)
	}
}

func TestLoadDirNeedsHubYAML(t *testing.T) {
	files := hubFiles(t)
	delete(files, "hub.yaml")
	if _, err := LoadDir(writeHub(t, files)); err == nil || !strings.Contains(err.Error(), "hub.yaml") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadTarballMatchesLoadDir(t *testing.T) {
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	tw := tar.NewWriter(z)
	for p, b := range hubFiles(t) {
		_ = tw.WriteHeader(&tar.Header{Name: "sk1122-firedrill-drills-abc123/" + p, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(b)
	}
	evil := []byte("x")
	_ = tw.WriteHeader(&tar.Header{Name: "top/../../etc/drills/x.drill.yaml", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = tw.Write(evil)
	_ = tw.Close()
	_ = z.Close()
	h, err := LoadTarball(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.Entries) != 3 || len(h.Problems) != 3 {
		t.Fatalf("entries %d, problems %v", len(h.Entries), h.Problems)
	}
}

func TestSearchMatchesEveryWord(t *testing.T) {
	h, _ := LoadDir(writeHub(t, hubFiles(t)))
	if got := h.Search("history main"); len(got) != 1 || got[0].ID != "change/no-force-push-main" {
		t.Fatalf("%v", got)
	}
	if got := h.Search("history nothing-like-this"); len(got) != 0 {
		t.Fatalf("%v", got)
	}
	if got := h.Search(""); len(got) != 3 {
		t.Fatalf("an empty query lists all: %d", len(got))
	}
}

func TestLockRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l, err := ReadLock(dir)
	if err != nil || len(l.Drills) != 0 {
		t.Fatalf("a missing lock is empty: %v %v", l, err)
	}
	l.Hub = DefaultRepo
	l.Drills["change/x"] = LockEntry{Source: "hub", Commit: "abc", SHA256: "def"}
	if err := WriteLock(dir, l); err != nil {
		t.Fatal(err)
	}
	back, err := ReadLock(dir)
	if err != nil || back.Drills["change/x"].Commit != "abc" || back.Hub != DefaultRepo {
		t.Fatalf("%+v %v", back, err)
	}
}

func TestDiff(t *testing.T) {
	a := "1\n2\n3\n4\n5\n6\n7\n8\n9\n10"
	b := "1\n2\nthree\n4\n5\n6\n7\n8\n9\n10\n11"
	want := "  1\n  2\n- 3\n+ three\n  4\n  5\n  ...\n  9\n  10\n+ 11\n"
	if got := Diff(a, b); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestSiteWritesIndexAndPages(t *testing.T) {
	h, _ := LoadDir(writeHub(t, hubFiles(t)))
	out := t.TempDir()
	if err := WriteSite(out, h, time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	idx, _ := os.ReadFile(filepath.Join(out, "index.html"))
	page, err := os.ReadFile(filepath.Join(out, "drills", "change--no-force-push-main.html"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Drill Hub", "change/no-force-push-main", "drills/change--no-force-push-main.html", "official"} {
		if !strings.Contains(string(idx), want) {
			t.Errorf("index lacks %q", want)
		}
	}
	for _, want := range []string{"firedrill hub add change/no-force-push-main", "force_push_allowed", "N/A"} {
		if !strings.Contains(string(page), want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(string(idx), "<script") || strings.Contains(string(idx), "http://") || strings.Contains(string(idx), "https://") {
		t.Error("the site loads no script and nothing from the network")
	}
}
