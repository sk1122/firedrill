package files

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// MaxFileSize is the largest file scanned.
const MaxFileSize = 1 << 20

// File is one file read from a repo.
type File struct {
	Path string // slash-separated, relative to the repo root
	Data []byte
}

var skipDirs = map[string]bool{".git": true, "vendor": true, "node_modules": true, "third_party": true, "dist": true}

func isBinary(b []byte) bool {
	n := min(len(b), 8000)
	return bytes.IndexByte(b[:n], 0) >= 0
}

// alwaysRead names files read even when .gitignore excludes them, since they are
// where local secrets and agent overrides live.
func alwaysRead(rel string) bool {
	return strings.HasPrefix(path.Base(rel), ".env") || rel == ".claude/settings.local.json"
}

type ignoreRule struct {
	re     *regexp.Regexp
	negate bool
	dir    bool
}

func compileIgnore(base, line string) (ignoreRule, bool) {
	line = strings.TrimRight(line, " \t\r")
	if line == "" || strings.HasPrefix(line, "#") {
		return ignoreRule{}, false
	}
	r := ignoreRule{}
	if strings.HasPrefix(line, "!") {
		r.negate = true
		line = line[1:]
	}
	if strings.HasSuffix(line, "/") {
		r.dir = true
		line = strings.TrimSuffix(line, "/")
	}
	anchored := strings.Contains(line, "/")
	line = strings.TrimPrefix(line, "/")
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		switch c := line[i]; c {
		case '*':
			if i+1 < len(line) && line[i+1] == '*' {
				i++
				if i+1 < len(line) && line[i+1] == '/' {
					i++
					b.WriteString(`(?:.*/)?`)
				} else {
					b.WriteString(`.*`)
				}
			} else {
				b.WriteString(`[^/]*`)
			}
		case '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	prefix := ""
	if base != "" {
		prefix = regexp.QuoteMeta(base) + "/"
	}
	if !anchored {
		prefix += `(?:.*/)?`
	}
	re, err := regexp.Compile("^" + prefix + b.String() + "$")
	if err != nil {
		return ignoreRule{}, false
	}
	r.re = re
	return r, true
}

func ignored(rules []ignoreRule, rel string, isDir bool) bool {
	out := false
	for _, r := range rules {
		if r.dir && !isDir {
			continue
		}
		if r.re.MatchString(rel) {
			out = !r.negate
		}
	}
	return out
}

func parseIgnoreFile(base string, data []byte) []ignoreRule {
	var out []ignoreRule
	for line := range strings.SplitSeq(string(data), "\n") {
		if r, ok := compileIgnore(base, line); ok {
			out = append(out, r)
		}
	}
	return out
}

// Skipped reports whether a file should not be scanned at all.
func keep(rel string, data []byte) bool {
	return len(data) <= MaxFileSize && !isBinary(data)
}

// WalkLocal reads a checkout, respecting .gitignore and .firedrillignore apart
// from the files in alwaysRead.
func WalkLocal(root string) ([]File, error) {
	var out []File
	var walk func(dir string, rules []ignoreRule) error
	walk = func(dir string, rules []ignoreRule) error {
		relDir, _ := filepath.Rel(root, dir)
		relDir = filepath.ToSlash(relDir)
		if relDir == "." {
			relDir = ""
		}
		for _, name := range []string{".gitignore", ".firedrillignore"} {
			if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
				rules = append(append([]ignoreRule(nil), rules...), parseIgnoreFile(relDir, b)...)
			}
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			rel := path.Join(relDir, e.Name())
			if e.IsDir() {
				if (skipDirs[e.Name()] || ignored(rules, rel, true)) && rel != ".claude" {
					continue
				}
				if err := walk(filepath.Join(dir, e.Name()), rules); err != nil {
					return err
				}
				continue
			}
			if !e.Type().IsRegular() {
				continue
			}
			if ignored(rules, rel, false) && !alwaysRead(rel) {
				continue
			}
			info, err := e.Info()
			if err != nil || info.Size() > MaxFileSize {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return err
			}
			if keep(rel, data) {
				out = append(out, File{Path: rel, Data: data})
			}
		}
		return nil
	}
	return out, walk(root, nil)
}

// ReadTarball reads a GitHub repo tarball, which holds committed files under one
// top-level folder.
func ReadTarball(r io.Reader) ([]File, error) {
	z, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer func() { _ = z.Close() }()
	tr := tar.NewReader(z)
	var out []File
	var rules []ignoreRule
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		_, rel, ok := strings.Cut(h.Name, "/")
		if !ok || rel == "" || strings.Contains(rel, "..") {
			continue
		}
		skip := h.Size > MaxFileSize
		for part := range strings.SplitSeq(path.Dir(rel), "/") {
			if skipDirs[part] {
				skip = true
			}
		}
		if skip {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxFileSize+1))
		if err != nil {
			return nil, err
		}
		if rel == ".firedrillignore" {
			rules = parseIgnoreFile("", data)
		}
		if keep(rel, data) {
			out = append(out, File{Path: rel, Data: data})
		}
	}
	if len(rules) == 0 {
		return out, nil
	}
	kept := out[:0]
	for _, f := range out {
		if !ignored(rules, f.Path, false) {
			kept = append(kept, f)
		}
	}
	return kept, nil
}
