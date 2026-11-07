// Package hub reads a drill hub: a repo of drills, each with a fixtures file,
// under drills/<pack>/<slug>.drill.yaml. It builds the hub index, keeps the
// lock file of installed drills, and diffs a drill against its hub version.
package hub

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sk1122/firedrill/internal/drill"
	"github.com/sk1122/firedrill/internal/run"
)

// DefaultRepo is the hub Firedrill reads unless config names another.
const DefaultRepo = "sk1122/firedrill-drills"

// Meta is the hub's own hub.yaml.
type Meta struct {
	Name     string   `yaml:"name" json:"name"`
	Official []string `yaml:"official" json:"official"` // packs maintained with Firedrill
}

// Entry is one drill in the hub.
type Entry struct {
	ID        string   `json:"id"`
	Pack      string   `json:"pack"`
	Safeguard string   `json:"safeguard"`
	Severity  string   `json:"severity"`
	Author    string   `json:"author,omitempty"`
	Requires  string   `json:"requires,omitempty"`
	Facts     []string `json:"facts"`
	MapsTo    []string `json:"maps_to,omitempty"`
	Fix       string   `json:"fix,omitempty"`
	Official  bool     `json:"official"`
	Cases     int      `json:"cases"`
	SHA256    string   `json:"sha256"`
	Path      string   `json:"path"`

	Source []byte       `json:"-"`
	Test   []byte       `json:"-"`
	Drill  *drill.Drill `json:"-"`
}

// Hub is every drill in one hub checkout.
type Hub struct {
	Meta    Meta
	Commit  string
	Entries []*Entry
	// Problems are drills that failed validation or their fixtures, by path.
	Problems map[string]string
}

// Get returns one drill by ID.
func (h *Hub) Get(id string) (*Entry, bool) {
	for _, e := range h.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return nil, false
}

// Search returns drills whose ID, safeguard, pack, author or mappings contain
// every word of the query, ignoring case.
func (h *Hub) Search(query string) []*Entry {
	words := strings.Fields(strings.ToLower(query))
	var out []*Entry
	for _, e := range h.Entries {
		text := strings.ToLower(strings.Join(append([]string{e.ID, e.Safeguard, e.Pack, e.Author}, e.MapsTo...), " "))
		match := true
		for _, w := range words {
			if !strings.Contains(text, w) {
				match = false
				break
			}
		}
		if match {
			out = append(out, e)
		}
	}
	return out
}

// LoadDir reads a hub from a folder holding hub.yaml and drills/.
func LoadDir(dir string) (*Hub, error) {
	files := map[string][]byte{}
	root := os.DirFS(dir)
	err := fs.WalkDir(root, ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		if p == "hub.yaml" || strings.HasPrefix(p, "drills/") && strings.HasSuffix(p, ".yaml") {
			b, err := fs.ReadFile(root, p)
			if err != nil {
				return err
			}
			files[p] = b
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return build(files)
}

// maxHubBytes caps how much of a hub tarball is read.
const maxHubBytes = 32 << 20

// LoadTarball reads a hub from a GitHub tarball, whose entries sit under one
// top-level folder.
func LoadTarball(r io.Reader) (*Hub, error) {
	z, err := gzip.NewReader(io.LimitReader(r, maxHubBytes))
	if err != nil {
		return nil, fmt.Errorf("the hub download is not a gzip tarball: %w", err)
	}
	tr := tar.NewReader(z)
	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		_, rel, ok := strings.Cut(h.Name, "/")
		if !ok || rel != path.Clean(rel) || strings.HasPrefix(rel, "../") {
			continue
		}
		if rel == "hub.yaml" || strings.HasPrefix(rel, "drills/") && strings.HasSuffix(rel, ".yaml") {
			b, err := io.ReadAll(io.LimitReader(tr, 1<<20))
			if err != nil {
				return nil, err
			}
			files[rel] = b
		}
	}
	return build(files)
}

func build(files map[string][]byte) (*Hub, error) {
	h := &Hub{Problems: map[string]string{}}
	meta, ok := files["hub.yaml"]
	if !ok {
		return nil, errors.New("this is not a drill hub: hub.yaml is missing")
	}
	if err := yaml.Unmarshal(meta, &h.Meta); err != nil {
		return nil, fmt.Errorf("hub.yaml: %w", err)
	}
	official := map[string]bool{}
	for _, p := range h.Meta.Official {
		official[p] = true
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if !strings.HasSuffix(p, ".drill.yaml") {
			continue
		}
		src := files[p]
		d, issues := drill.Load(p, src)
		if drill.HasErrors(issues) {
			h.Problems[p] = "does not validate: " + issues[0].String()
			continue
		}
		want := "drills/" + d.ID + ".drill.yaml"
		if p != want {
			h.Problems[p] = "id " + d.ID + " does not match its path; it belongs at " + want
			continue
		}
		pack, _, _ := strings.Cut(d.ID, "/")
		e := &Entry{
			ID: d.ID, Pack: pack, Safeguard: d.Safeguard, Severity: d.Severity, Author: d.Author, Requires: d.Requires,
			MapsTo: d.MapsTo, Fix: d.Fix, Official: official[pack], SHA256: drill.Hash(src), Path: p,
			Source: src, Drill: d,
		}
		seen := map[string]bool{}
		for _, f := range append([]string{d.ForEach}, factNames(d)...) {
			if f != "" && !seen[f] {
				seen[f] = true
				e.Facts = append(e.Facts, f)
			}
		}
		test, ok := files[run.TestPath(p)]
		if !ok {
			h.Problems[p] = "has no fixtures file " + path.Base(run.TestPath(p))
		} else {
			e.Test = test
			res, err := run.RunTests(d, test)
			e.Cases = len(res)
			for _, c := range res {
				if !c.OK() && err == nil {
					err = fmt.Errorf("case %q: want %s, got %s", c.Name, c.Expect, c.Got)
				}
			}
			if err != nil {
				h.Problems[p] = "fixtures: " + err.Error()
			}
		}
		h.Entries = append(h.Entries, e)
	}
	return h, nil
}

func factNames(d *drill.Drill) []string {
	var out []string
	for _, f := range d.Fetches {
		out = append(out, f.Fact)
	}
	return out
}

// Index is the hub's index.json.
type Index struct {
	Name      string   `json:"name"`
	Commit    string   `json:"commit,omitempty"`
	Generated string   `json:"generated"`
	Drills    []*Entry `json:"drills"`
}

// BuildIndex returns the index of a hub.
func BuildIndex(h *Hub, now time.Time) Index {
	return Index{Name: h.Meta.Name, Commit: h.Commit, Generated: now.UTC().Format(time.RFC3339), Drills: h.Entries}
}

// WriteIndex writes index.json.
func WriteIndex(file string, ix Index) error {
	b, err := json.MarshalIndent(ix, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return err
	}
	return os.WriteFile(file, append(b, '\n'), 0o644)
}

// Lock is .firedrill/hub.lock: where each installed drill came from.
type Lock struct {
	Hub    string               `yaml:"hub"`
	Drills map[string]LockEntry `yaml:"drills"`
}

// LockEntry records one installed drill.
type LockEntry struct {
	Source string `yaml:"source"` // "hub" or "builtin"
	Commit string `yaml:"commit,omitempty"`
	SHA256 string `yaml:"sha256"`
}

// LockPath is the lock file's place in a project folder.
func LockPath(projectDir string) string { return filepath.Join(projectDir, "hub.lock") }

// ReadLock reads the lock file, or returns an empty one.
func ReadLock(projectDir string) (*Lock, error) {
	l := &Lock{Drills: map[string]LockEntry{}}
	b, err := os.ReadFile(LockPath(projectDir))
	if errors.Is(err, fs.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, l); err != nil {
		return nil, fmt.Errorf("hub.lock: %w", err)
	}
	if l.Drills == nil {
		l.Drills = map[string]LockEntry{}
	}
	return l, nil
}

// WriteLock writes the lock file.
func WriteLock(projectDir string, l *Lock) error {
	b, err := yaml.Marshal(l)
	if err != nil {
		return err
	}
	header := "# Written by firedrill hub. Records where each drill came from, so hub update\n# can tell an untouched drill from one you edited.\n"
	return os.WriteFile(LockPath(projectDir), append([]byte(header), b...), 0o644)
}

// DrillPath is where a drill lives in a project.
func DrillPath(projectDir, id string) string {
	return filepath.Join(projectDir, "drills", filepath.FromSlash(id)+".drill.yaml")
}

// Diff returns a line diff of a and b, with - and + markers and two lines of
// context around each change.
func Diff(a, b string) string {
	x, y := strings.Split(a, "\n"), strings.Split(b, "\n")
	n, m := len(x), len(y)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	type line struct {
		op   byte
		text string
	}
	var ops []line
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			ops = append(ops, line{' ', x[i]})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, line{'-', x[i]})
			i++
		default:
			ops = append(ops, line{'+', y[j]})
			j++
		}
	}
	keep := make([]bool, len(ops))
	for k, o := range ops {
		if o.op != ' ' {
			for c := max(0, k-2); c <= min(len(ops)-1, k+2); c++ {
				keep[c] = true
			}
		}
	}
	var sb strings.Builder
	gap := false
	for k, o := range ops {
		if !keep[k] {
			gap = true
			continue
		}
		if gap && sb.Len() > 0 {
			sb.WriteString("  ...\n")
		}
		gap = false
		sb.WriteByte(o.op)
		sb.WriteByte(' ')
		sb.WriteString(o.text)
		sb.WriteByte('\n')
	}
	return sb.String()
}
