package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)

func write(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

var env = map[string]string{"GITHUB_REPOSITORY": "acme/firedrill", "GITHUB_RUN_ID": "42", "GITHUB_SHA": strings.Repeat("a", 40),
	"GITHUB_WORKFLOW_REF": "acme/firedrill/.github/workflows/firedrill.yml@refs/heads/main"}

func setup(t *testing.T) (records, checksums, tagA, tagB string) {
	t.Helper()
	records = t.TempDir()
	tagA = write(t, filepath.Join(records, "tags/change/no-solo-ship/acme-api/2026-11-09T09-00-00Z.json"), `{"a":1}`)
	tagB = write(t, filepath.Join(records, "tags/change/no-solo-ship/acme-web/2026-11-09T09-00-00Z.json"), `{"b":2}`)
	var err error
	checksums, err = WriteChecksums(records, now, []string{tagB, tagA, tagA})
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestChecksumsFileIsSha256sumFormat(t *testing.T) {
	records, checksums, _, _ := setup(t)
	if checksums != filepath.Join(records, "attest", "2026-11-09T09-00-00Z.sha256") {
		t.Fatal(checksums)
	}
	b, _ := os.ReadFile(checksums)
	want := sum(`{"a":1}`) + "  tags/change/no-solo-ship/acme-api/2026-11-09T09-00-00Z.json\n" +
		sum(`{"b":2}`) + "  tags/change/no-solo-ship/acme-web/2026-11-09T09-00-00Z.json\n"
	if string(b) != want {
		t.Fatalf("got\n%s\nwant\n%s", b, want)
	}
	if p, err := WriteChecksums(records, now, nil); p != "" || err != nil {
		t.Fatal("nothing written, nothing listed")
	}
	if _, err := WriteChecksums(records, now, []string{"/etc/hosts"}); err == nil {
		t.Fatal("a file outside the records is refused")
	}
	// A second file in the same second gets the next name.
	if p, _ := WriteChecksums(records, now, []string{filepath.Join(records, "tags/change/no-solo-ship/acme-api/2026-11-09T09-00-00Z.json")}); filepath.Base(p) != "2026-11-09T09-00-01Z.sha256" {
		t.Fatal(p)
	}
}

func TestUnattestedUntilASidecarRecordsTheAttestation(t *testing.T) {
	records, checksums, _, _ := setup(t)
	st, err := Check(records)
	if err != nil {
		t.Fatal(err)
	}
	if st.State("tags/change/no-solo-ship/acme-api/2026-11-09T09-00-00Z.json") != Unattested || st.Attested != 0 || len(st.Unclaimed) != 1 {
		t.Fatalf("a checksums file alone proves nothing: %+v", st)
	}
	bundle := write(t, filepath.Join(t.TempDir(), "bundle.jsonl"), `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`+"\n")
	path, err := Record(records, checksums, "123456", "https://github.com/acme/firedrill/attestations/123456", bundle, now, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "2026-11-09T09-00-00Z.json" {
		t.Fatal(path)
	}
	if _, err := os.Stat(filepath.Join(records, "attest", "2026-11-09T09-00-00Z.sigstore.json")); err != nil {
		t.Fatal("the bundle is kept beside the sidecar")
	}
	st, _ = Check(records)
	if st.Attested != 2 || len(st.Problems) != 0 || st.State("tags/change/no-solo-ship/acme-web/2026-11-09T09-00-00Z.json") != Attested {
		t.Fatalf("%+v", st)
	}
	if st.State("tags/change/other/x/2026-11-01T00-00-00Z.json") != Unattested {
		t.Fatal("a tag no checksums file lists is unattested")
	}
	sc := st.Sidecars[0]
	if sc.Repository != "acme/firedrill" || sc.RunID != "42" || sc.AttestationID != "123456" || sc.ChecksumsSHA256 == "" {
		t.Fatalf("%+v", sc)
	}
	cmds := OnlineCommands(records, st)
	if len(cmds) != 1 || !strings.Contains(cmds[0], "gh attestation verify") || !strings.Contains(cmds[0], "-R acme/firedrill") {
		t.Fatal(cmds)
	}
}

func TestChecksumsMismatch(t *testing.T) {
	records, checksums, tagA, _ := setup(t)
	if _, err := Record(records, checksums, "1", "", "", now, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	// A tag edited after it was attested.
	write(t, tagA, `{"a":2}`)
	st, _ := Check(records)
	if st.State("tags/change/no-solo-ship/acme-api/2026-11-09T09-00-00Z.json") != Mismatch || st.Attested != 1 || len(st.Problems) != 1 {
		t.Fatalf("%+v", st)
	}
	// A checksums file edited after it was attested: nothing it lists counts.
	write(t, checksums, sum(`{"a":2}`)+"  tags/change/no-solo-ship/acme-api/2026-11-09T09-00-00Z.json\n")
	st, _ = Check(records)
	if st.Attested != 0 || st.State("tags/change/no-solo-ship/acme-api/2026-11-09T09-00-00Z.json") != Mismatch ||
		!strings.Contains(strings.Join(st.Problems, "\n"), "changed since it was attested") {
		t.Fatalf("%+v", st)
	}
}

func TestRecordRefusesWhatIsNotItsOwn(t *testing.T) {
	records, checksums, _, _ := setup(t)
	other := write(t, filepath.Join(t.TempDir(), "x.sha256"), sum("x")+"  a\n")
	if _, err := Record(records, other, "1", "", "", now, os.Getenv); err == nil {
		t.Fatal("a checksums file outside records/attest is refused")
	}
	if _, err := Record(records, checksums, "", "", "", now, os.Getenv); err == nil {
		t.Fatal("an attestation must be named")
	}
	notJSON := write(t, filepath.Join(t.TempDir(), "b"), "not json")
	if _, err := Record(records, checksums, "", "", notJSON, now, os.Getenv); err == nil {
		t.Fatal("a bundle must be JSON")
	}
}
