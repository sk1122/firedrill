// Package attest binds CI tags to a GitHub artifact attestation, kept beside
// the records as a sidecar.
//
// A CI run writes one checksums file listing every tag (and the diff) it
// wrote: one "sha256  path" line each, the format sha256sum prints and the
// actions/attest subject-checksums input reads. The workflow attests that file
// in one attestation, then `firedrill attest record` writes a sidecar naming
// the checksums file's hash and the attestation's ID and URL. Firedrill never
// calls GitHub to check an attestation: verify reports what the local files
// say, and `gh attestation verify`, run by the user, checks the signature.
//
// tag.Header.Attested is never set. The header is hash-chained and written
// before any attestation exists, so a true value there could not be honest.
// The sidecar is the record of attestation; the field stays for compatibility.
package attest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Dir is where checksums files and sidecars live, under the records folder.
const Dir = "attest"

const stamp = "2006-01-02T15-04-05Z"

// ChecksumsName is the checksums file for a run at t.
func ChecksumsName(t time.Time) string { return t.UTC().Format(stamp) + ".sha256" }

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteChecksums writes <records>/attest/<time>.sha256 with one line per file,
// each path relative to records with forward slashes, sorted. It returns the
// file's path, or "" when there is nothing to list.
func WriteChecksums(records string, at time.Time, files []string) (string, error) {
	type line struct{ sum, rel string }
	var lines []line
	seen := map[string]bool{}
	for _, f := range files {
		rel, err := filepath.Rel(records, f)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", fmt.Errorf("%s is not under the records folder", f)
		}
		rel = filepath.ToSlash(rel)
		if seen[rel] {
			continue
		}
		seen[rel] = true
		sum, err := fileSHA256(f)
		if err != nil {
			return "", err
		}
		lines = append(lines, line{sum, rel})
	}
	if len(lines) == 0 {
		return "", nil
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].rel < lines[j].rel })
	var b bytes.Buffer
	for _, l := range lines {
		fmt.Fprintf(&b, "%s  %s\n", l.sum, l.rel)
	}
	dir := filepath.Join(records, Dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, ChecksumsName(at))
	for i := 1; ; i++ {
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			break
		}
		path = filepath.Join(dir, ChecksumsName(at.Add(time.Duration(i)*time.Second)))
	}
	return path, os.WriteFile(path, b.Bytes(), 0o644)
}

// ReadChecksums parses a checksums file into path to sha256.
func ReadChecksums(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		sum, rel, ok := strings.Cut(line, " ")
		if !ok || len(sum) != 64 {
			return nil, fmt.Errorf("%s: not a checksums line: %q", filepath.Base(path), line)
		}
		out[strings.TrimPrefix(strings.TrimSpace(rel), "*")] = sum
	}
	return out, sc.Err()
}

// Sidecar records one attestation over one checksums file. It holds no
// personal data: the repository, run and commit come from the GitHub Actions
// environment.
type Sidecar struct {
	Checksums       string    `json:"checksums_file"`
	ChecksumsSHA256 string    `json:"checksums_sha256"`
	AttestationID   string    `json:"attestation_id,omitempty"`
	AttestationURL  string    `json:"attestation_url,omitempty"`
	Bundle          string    `json:"bundle_file,omitempty"`
	BundleSHA256    string    `json:"bundle_sha256,omitempty"`
	Repository      string    `json:"repository,omitempty"`
	RunID           string    `json:"run_id,omitempty"`
	Workflow        string    `json:"workflow_ref,omitempty"`
	Commit          string    `json:"commit,omitempty"`
	RecordedAt      time.Time `json:"recorded_at"`
}

// Record writes the sidecar for a checksums file, <records>/attest/<time>.json,
// and copies the attestation bundle beside it as <time>.sigstore.json when one
// is given, so it can be checked offline later. getenv supplies the GitHub
// Actions variables. It refuses a checksums file outside the records folder.
func Record(records, checksums, id, url, bundle string, now time.Time, getenv func(string) string) (string, error) {
	dir := filepath.Join(records, Dir)
	abs, err := filepath.Abs(checksums)
	if err != nil {
		return "", err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if filepath.Dir(abs) != absDir || !strings.HasSuffix(abs, ".sha256") {
		return "", fmt.Errorf("%s is not a checksums file in %s", checksums, dir)
	}
	if _, err := ReadChecksums(abs); err != nil {
		return "", err
	}
	if id == "" && url == "" && bundle == "" {
		return "", fmt.Errorf("give the attestation's ID, URL or bundle")
	}
	sum, err := fileSHA256(abs)
	if err != nil {
		return "", err
	}
	base := strings.TrimSuffix(filepath.Base(abs), ".sha256")
	sc := Sidecar{Checksums: filepath.Base(abs), ChecksumsSHA256: sum, AttestationID: id, AttestationURL: url,
		RecordedAt: now.UTC(), Repository: getenv("GITHUB_REPOSITORY"), RunID: getenv("GITHUB_RUN_ID"),
		Workflow: getenv("GITHUB_WORKFLOW_REF"), Commit: getenv("GITHUB_SHA")}
	if bundle != "" {
		b, err := os.ReadFile(bundle)
		if err != nil {
			return "", err
		}
		if !json.Valid(firstJSON(b)) {
			return "", fmt.Errorf("%s is not a JSON attestation bundle", bundle)
		}
		sc.Bundle = base + ".sigstore.json"
		s := sha256.Sum256(b)
		sc.BundleSHA256 = hex.EncodeToString(s[:])
		if err := os.WriteFile(filepath.Join(dir, sc.Bundle), b, 0o644); err != nil {
			return "", err
		}
	}
	out, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, base+".json")
	return path, os.WriteFile(path, out, 0o644)
}

// firstJSON returns the first line of a bundle, which may be JSON Lines.
func firstJSON(b []byte) []byte {
	b = bytes.TrimSpace(b)
	if i := bytes.IndexByte(b, '\n'); i > 0 {
		return b[:i]
	}
	return b
}

// States a tag file can be in.
const (
	Attested   = "attested"
	Unattested = "unattested"
	Mismatch   = "checksums mismatch"
)

// Status is what the local files say about every tag's attestation.
type Status struct {
	// Files maps a path relative to records, with forward slashes, to its
	// state. Only files listed in a checksums file appear; any other tag is
	// unattested.
	Files     map[string]string `json:"-"`
	Attested  int               `json:"attested"`
	Problems  []string          `json:"problems,omitempty"`
	Sidecars  []Sidecar         `json:"sidecars,omitempty"`
	Unclaimed []string          `json:"checksums_without_attestation,omitempty"`
}

// State returns a file's state; a file no attested checksums file lists is
// unattested.
func (s Status) State(rel string) string {
	if st, ok := s.Files[filepath.ToSlash(rel)]; ok {
		return st
	}
	return Unattested
}

// Check reads every checksums file and sidecar under records/attest. A file is
// attested when a sidecar's checksums file still has the recorded hash and
// lists the file with the hash it has now. A changed checksums file, or a
// listed file that changed since, is a mismatch. It reads only local files.
func Check(records string) (Status, error) {
	st := Status{Files: map[string]string{}}
	dir := filepath.Join(records, Dir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	claimed := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") || strings.HasSuffix(name, ".sigstore.json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return st, err
		}
		var sc Sidecar
		if err := json.Unmarshal(b, &sc); err != nil || sc.Checksums == "" {
			st.Problems = append(st.Problems, name+": not a readable attestation record")
			continue
		}
		st.Sidecars = append(st.Sidecars, sc)
		claimed[sc.Checksums] = true
		cpath := filepath.Join(dir, filepath.Base(sc.Checksums))
		sum, err := fileSHA256(cpath)
		if err != nil {
			st.Problems = append(st.Problems, fmt.Sprintf("%s: checksums file %s is missing", name, sc.Checksums))
			continue
		}
		list, err := ReadChecksums(cpath)
		if err != nil {
			st.Problems = append(st.Problems, err.Error())
			continue
		}
		bad := sum != sc.ChecksumsSHA256
		if bad {
			st.Problems = append(st.Problems, fmt.Sprintf("%s: checksums file %s changed since it was attested", name, sc.Checksums))
		}
		rels := make([]string, 0, len(list))
		for rel := range list {
			rels = append(rels, rel)
		}
		sort.Strings(rels)
		for _, rel := range rels {
			now, err := fileSHA256(filepath.Join(records, filepath.FromSlash(rel)))
			switch {
			case bad:
				st.Files[rel] = Mismatch
			case errors.Is(err, os.ErrNotExist):
				st.Problems = append(st.Problems, fmt.Sprintf("%s: %s was attested and is missing", sc.Checksums, rel))
			case err != nil:
				return st, err
			case now != list[rel]:
				st.Files[rel] = Mismatch
				st.Problems = append(st.Problems, fmt.Sprintf("%s: %s changed since it was attested", sc.Checksums, rel))
			case st.Files[rel] != Mismatch:
				st.Files[rel] = Attested
			}
		}
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sha256") && !claimed[e.Name()] {
			st.Unclaimed = append(st.Unclaimed, e.Name())
		}
	}
	for _, v := range st.Files {
		if v == Attested {
			st.Attested++
		}
	}
	sort.Strings(st.Problems)
	return st, nil
}

// OnlineCommands are the commands a user runs to check each attestation's
// signature with the GitHub CLI. Firedrill prints them and runs none.
func OnlineCommands(records string, st Status) []string {
	var out []string
	for _, sc := range st.Sidecars {
		repo := sc.Repository
		if repo == "" {
			repo = "OWNER/REPO"
		}
		list := filepath.ToSlash(filepath.Join(records, Dir, sc.Checksums))
		out = append(out, fmt.Sprintf(`while read -r sum path; do gh attestation verify "%s/$path" -R %s; done < "%s"`,
			filepath.ToSlash(records), repo, list))
	}
	return out
}
