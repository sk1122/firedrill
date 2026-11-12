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

// MaxLockfileSize is the largest lockfile read for its install scripts.
const MaxLockfileSize = 32 << 20

// File is one file read from a repo.
type File struct {
	Path    string // slash-separated, relative to the repo root
	Data    []byte
	Ignored bool // .gitignore rules ignore it; a committed file never is
	// Unscanned marks a lockfile over MaxFileSize, or binary, kept because its
	// existence counts. It is never scanned for secrets. Data holds it only
	// when it is text and at most MaxLockfileSize.
	Unscanned bool
}

// lockfileNames are the JavaScript lockfiles.
var lockfileNames = map[string]bool{
	"package-lock.json": true, "npm-shrinkwrap.json": true, "pnpm-lock.yaml": true,
	"yarn.lock": true, "bun.lock": true, "bun.lockb": true,
}

// IsLockfile reports a JavaScript lockfile.
func IsLockfile(rel string) bool {
	return lockfileNames[path.Base(rel)]
}

// bigLockfile keeps a lockfile too large or too binary to scan: its content
// when it is text and small enough to parse, else its path alone.
func bigLockfile(rel string, data []byte, size int64, ignored bool) File {
	f := File{Path: rel, Ignored: ignored, Unscanned: true}
	if size <= MaxLockfileSize && !isBinary(data) {
		f.Data = data
	}
	return f
}

var skipDirs = map[string]bool{".git": true, "vendor": true, "node_modules": true, "third_party": true, "dist": true}

func isBinary(b []byte) bool {
	n := min(len(b), 8000)
	return bytes.IndexByte(b[:n], 0) >= 0
}

// alwaysRead names files read even when .gitignore or .firedrillignore excludes
// them, since they are where local secrets and agent overrides live.
func alwaysRead(rel string) bool {
	return strings.HasPrefix(path.Base(rel), ".env") || rel == ".claude/settings.local.json"
}

// agentDirs hold a coding agent's settings at the repo root. Every file under
// one is agent config, apart from the folders in agentSkip.
var agentDirs = []string{".claude", ".cursor", ".gemini"}

// agentRootFiles are agent config files outside those folders.
var agentRootFiles = map[string]bool{".mcp.json": true, ".vscode/mcp.json": true, ".cursorignore": true}

// agentSkip are folders under an agent folder that hold worktrees, caches,
// logs, transcripts or installed plugins rather than settings. They are never
// read, since they can hold a copy of the whole repo or months of history.
var agentSkip = map[string]bool{
	".claude/worktrees": true, ".claude/projects": true, ".claude/plugins": true, ".claude/cache": true,
	".claude/file-history": true, ".claude/paste-cache": true, ".claude/shell-snapshots": true,
	".claude/session-env": true, ".claude/sessions": true, ".claude/todos": true, ".claude/statsig": true,
	".claude/telemetry": true, ".claude/logs": true, ".claude/debug": true, ".claude/downloads": true,
	".claude/uploads": true, ".claude/backups": true, ".claude/ide": true,
	".cursor/extensions": true, ".cursor/projects": true, ".cursor/plugins": true, ".cursor/ai-tracking": true,
	".gemini/tmp": true, ".gemini/history": true,
}

// IsAgentConfig reports whether a repo path is a coding agent's config file.
func IsAgentConfig(rel string) bool {
	if agentRootFiles[rel] {
		return true
	}
	if agentSkipped(rel) {
		return false
	}
	for _, d := range agentDirs {
		if strings.HasPrefix(rel, d+"/") {
			return true
		}
	}
	return false
}

// agentSkipped reports a path in one of the agentSkip folders, or in a folder
// the walker always skips.
func agentSkipped(rel string) bool {
	parts := strings.Split(rel, "/")
	for i := range parts {
		if agentSkip[strings.Join(parts[:i+1], "/")] || (i < len(parts)-1 && skipDirs[parts[i]]) {
			return true
		}
	}
	return false
}

// agentDir reports a folder the walker enters even when .gitignore excludes it,
// since agent config files may sit in it.
func agentDir(rel string) bool {
	if rel == ".vscode" {
		return true
	}
	for _, d := range agentDirs {
		if rel == d || strings.HasPrefix(rel, d+"/") {
			return !agentSkipped(rel)
		}
	}
	return false
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

// ignoreState holds the ignore rules in force in one folder, and whether a
// parent folder is already ignored. all holds the rules of both files in the
// order they were read; git and fd hold .gitignore and .firedrillignore alone.
type ignoreState struct {
	all, git, fd          []ignoreRule
	allDir, gitDir, fdDir bool
}

func (s ignoreState) match(rel string, isDir bool) (all, git, fd bool) {
	return s.allDir || ignored(s.all, rel, isDir), s.gitDir || ignored(s.git, rel, isDir), s.fdDir || ignored(s.fd, rel, isDir)
}

func (s *ignoreState) add(dir, relDir, name string, only *[]ignoreRule) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return
	}
	r := parseIgnoreFile(relDir, b)
	s.all = append(append([]ignoreRule(nil), s.all...), r...)
	*only = append(append([]ignoreRule(nil), *only...), r...)
}

// WalkLocal reads a checkout, respecting .gitignore and .firedrillignore apart
// from the files in alwaysRead. Agent config files are read even when
// .gitignore excludes them, and marked Ignored; .firedrillignore still
// excludes them.
func WalkLocal(root string) ([]File, error) {
	var out []File
	var walk func(dir string, st ignoreState) error
	walk = func(dir string, st ignoreState) error {
		relDir, _ := filepath.Rel(root, dir)
		relDir = filepath.ToSlash(relDir)
		if relDir == "." {
			relDir = ""
		}
		st.add(dir, relDir, ".gitignore", &st.git)
		st.add(dir, relDir, ".firedrillignore", &st.fd)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		for _, e := range entries {
			rel := path.Join(relDir, e.Name())
			all, git, fd := st.match(rel, e.IsDir())
			if e.IsDir() {
				if skipDirs[e.Name()] || agentSkip[rel] {
					continue
				}
				if all && rel != ".claude" && (!agentDir(rel) || fd) {
					continue
				}
				sub := st
				sub.allDir, sub.gitDir, sub.fdDir = all, git, fd
				if err := walk(filepath.Join(dir, e.Name()), sub); err != nil {
					return err
				}
				continue
			}
			if !e.Type().IsRegular() {
				continue
			}
			// Agent config and lockfiles are read even when gitignored, since
			// whether they are committed is what a drill asks.
			if all && !alwaysRead(rel) && (!(IsAgentConfig(rel) || IsLockfile(rel)) || fd) {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			if info.Size() > MaxFileSize {
				if IsLockfile(rel) {
					var data []byte
					if info.Size() <= MaxLockfileSize {
						if data, err = os.ReadFile(filepath.Join(dir, e.Name())); err != nil {
							return err
						}
					}
					out = append(out, bigLockfile(rel, data, info.Size(), git))
				}
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return err
			}
			if keep(rel, data) {
				out = append(out, File{Path: rel, Data: data, Ignored: git})
			} else if IsLockfile(rel) {
				out = append(out, bigLockfile(rel, data, info.Size(), git))
			}
		}
		return nil
	}
	return out, walk(root, ignoreState{})
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
		skip := agentSkipped(rel)
		for part := range strings.SplitSeq(path.Dir(rel), "/") {
			if skipDirs[part] {
				skip = true
			}
		}
		if skip {
			continue
		}
		if h.Size > MaxFileSize {
			if IsLockfile(rel) {
				var data []byte
				if h.Size <= MaxLockfileSize {
					if data, err = io.ReadAll(io.LimitReader(tr, MaxLockfileSize+1)); err != nil {
						return nil, err
					}
				}
				out = append(out, bigLockfile(rel, data, h.Size, false))
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, MaxFileSize+1))
		if err != nil {
			return nil, err
		}
		if rel == ".firedrillignore" {
			rules = parseIgnoreFile("", data)
		}
		// A file in a tarball is committed, so it is never Ignored.
		if keep(rel, data) {
			out = append(out, File{Path: rel, Data: data})
		} else if IsLockfile(rel) {
			out = append(out, bigLockfile(rel, data, h.Size, false))
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
