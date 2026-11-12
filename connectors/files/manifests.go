package files

import (
	"encoding/json"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is what Firedrill takes from one package.json: which manager it
// uses, the lockfile that locks it, and the dependencies the lockfile marks as
// running install scripts. No other dependency is kept. Only the npm family
// (npm, pnpm, yarn, bun) is read.
type Manifest struct {
	File         string
	Manager      string // npm, pnpm, yarn, bun or unknown
	Lockfile     string // repo-relative, empty when none
	Committed    bool   // the lockfile exists and is not gitignored
	Scripts      []string
	ScriptsKnown bool // false when the lockfile does not record install scripts or is too large
}

// lockOrder is the order lockfiles are looked for in a folder, with the
// manager each belongs to.
var lockOrder = []struct{ name, manager string }{
	{"npm-shrinkwrap.json", "npm"}, {"package-lock.json", "npm"}, {"pnpm-lock.yaml", "pnpm"},
	{"yarn.lock", "yarn"}, {"bun.lock", "bun"}, {"bun.lockb", "bun"},
}

type pkgJSON struct {
	PackageManager string          `json:"packageManager"`
	Workspaces     json.RawMessage `json:"workspaces"`
}

// workspaces reads the workspaces field, as a list or as {packages: [...]}.
func (p pkgJSON) workspaces() []string {
	var list []string
	if json.Unmarshal(p.Workspaces, &list) == nil {
		return list
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	_ = json.Unmarshal(p.Workspaces, &obj)
	return obj.Packages
}

// IsManifest reports a package.json outside node_modules, which the walker
// never enters.
func IsManifest(rel string) bool {
	return path.Base(rel) == "package.json"
}

// ScanManifests reads every package.json and the lockfiles beside them or at
// their workspace root.
func ScanManifests(all []File) []*Manifest {
	byPath := map[string]File{}
	var paths []string
	for _, f := range all {
		byPath[f.Path] = f
		if IsManifest(f.Path) {
			paths = append(paths, f.Path)
		}
	}
	sort.Strings(paths)
	pkgs := map[string]pkgJSON{}
	for _, p := range paths {
		var pj pkgJSON
		_ = json.Unmarshal(byPath[p].Data, &pj) // a broken package.json still counts, with no fields
		pkgs[dirOf(p)] = pj
	}
	// lockIn finds the lockfile in a folder, preferring the declared manager's.
	lockIn := func(dir string) (string, string) {
		declared, _, _ := strings.Cut(pkgs[dir].PackageManager, "@")
		for _, l := range lockOrder {
			if l.manager == declared {
				if _, ok := byPath[path.Join(dir, l.name)]; ok {
					return path.Join(dir, l.name), l.manager
				}
			}
		}
		for _, l := range lockOrder {
			if _, ok := byPath[path.Join(dir, l.name)]; ok {
				return path.Join(dir, l.name), l.manager
			}
		}
		return "", ""
	}
	scripts := map[string]struct {
		names []string
		known bool
	}{}
	var out []*Manifest
	for _, p := range paths {
		dir := dirOf(p)
		m := &Manifest{File: p, Manager: "unknown", Scripts: []string{}}
		lock, manager := lockIn(dir)
		owner := dir
		if lock == "" {
			// A workspace member is locked by its root's lockfile.
			if root, ok := workspaceRoot(dir, pkgs, byPath); ok {
				owner = root
				lock, manager = lockIn(root)
			}
		}
		if lock != "" {
			m.Lockfile, m.Manager = lock, manager
			m.Committed = !byPath[lock].Ignored
		} else if declared, _, _ := strings.Cut(pkgs[dir].PackageManager, "@"); declared != "" {
			m.Manager = declared
		}
		if lock != "" {
			s, ok := scripts[lock]
			if !ok {
				s.names, s.known = InstallScripts(byPath[lock])
				scripts[lock] = s
			}
			m.ScriptsKnown = s.known
			// The scripts are reported once, on the manifest beside the lockfile.
			if owner == dir {
				m.Scripts = s.names
			}
		}
		out = append(out, m)
	}
	return out
}

func dirOf(p string) string {
	d := path.Dir(p)
	if d == "." {
		return ""
	}
	return d
}

// workspaceRoot finds the nearest folder above dir whose package.json or
// pnpm-workspace.yaml lists dir as a workspace.
func workspaceRoot(dir string, pkgs map[string]pkgJSON, byPath map[string]File) (string, bool) {
	for up := dir; up != ""; {
		up = dirOf(up)
		patterns := pkgs[up].workspaces()
		if f, ok := byPath[path.Join(up, "pnpm-workspace.yaml")]; ok {
			var doc struct {
				Packages []string `yaml:"packages"`
			}
			if yaml.Unmarshal(f.Data, &doc) == nil {
				patterns = append(patterns, doc.Packages...)
			}
		}
		rel := strings.TrimPrefix(strings.TrimPrefix(dir, up), "/")
		if workspaceMatch(patterns, rel) {
			return up, true
		}
	}
	return "", false
}

// workspaceMatch says whether a folder matches the workspace globs, with **
// for any depth and ! to exclude.
func workspaceMatch(patterns []string, rel string) bool {
	hit := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p, "!"), "./"), "/")
		if globMatch(strings.Split(p, "/"), strings.Split(rel, "/")) {
			hit = !neg
		}
	}
	return hit
}

func globMatch(pat, parts []string) bool {
	if len(pat) == 0 {
		return len(parts) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(parts); i++ {
			if globMatch(pat[1:], parts[i:]) {
				return true
			}
		}
		return false
	}
	if len(parts) == 0 {
		return false
	}
	if ok, _ := path.Match(pat[0], parts[0]); !ok {
		return false
	}
	return globMatch(pat[1:], parts[1:])
}

// InstallScripts lists the dependencies a lockfile marks as running install
// scripts, sorted, and whether the lockfile records that at all.
// package-lock.json v2 and v3 mark hasInstallScript; pnpm-lock.yaml marks
// requiresBuild, which pnpm 9 stopped writing. yarn and bun lockfiles, npm v1
// lockfiles and lockfiles too large to read do not say.
func InstallScripts(f File) ([]string, bool) {
	if f.Data == nil {
		return []string{}, false
	}
	names := map[string]bool{}
	switch path.Base(f.Path) {
	case "package-lock.json", "npm-shrinkwrap.json":
		var doc struct {
			LockfileVersion int `json:"lockfileVersion"`
			Packages        map[string]struct {
				HasInstallScript bool `json:"hasInstallScript"`
			} `json:"packages"`
		}
		if json.Unmarshal(f.Data, &doc) != nil || doc.LockfileVersion < 2 {
			return []string{}, false
		}
		for key, p := range doc.Packages {
			// Only installed dependencies count; other keys are the repo's own
			// workspace folders.
			i := strings.LastIndex(key, "node_modules/")
			if p.HasInstallScript && i >= 0 {
				names[key[i+len("node_modules/"):]] = true
			}
		}
	case "pnpm-lock.yaml":
		var doc struct {
			LockfileVersion any `yaml:"lockfileVersion"`
			Packages        map[string]struct {
				RequiresBuild *bool `yaml:"requiresBuild"`
			} `yaml:"packages"`
		}
		if yaml.Unmarshal(f.Data, &doc) != nil {
			return []string{}, false
		}
		recorded := pnpmMajor(doc.LockfileVersion) < 9
		for key, p := range doc.Packages {
			if p.RequiresBuild == nil {
				continue
			}
			recorded = true
			if *p.RequiresBuild {
				names[pnpmName(key)] = true
			}
		}
		if !recorded {
			return []string{}, false
		}
	default:
		return []string{}, false
	}
	out := make([]string, 0, len(names))
	for n := range names {
		if n != "" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return slices.Compact(out), true
}

func pnpmMajor(v any) int {
	s := strings.Trim(strings.TrimSpace(toString(v)), "'\"")
	major, _, _ := strings.Cut(s, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		return 0
	}
	return n
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case int:
		return strconv.Itoa(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return ""
}

// pnpmName takes the package name from a pnpm-lock key: /name/1.2.3 (v5),
// /name@1.2.3(peer@1) (v6) or name@1.2.3 (v9), scoped or not.
func pnpmName(key string) string {
	k := strings.TrimPrefix(key, "/")
	if i := strings.Index(k, "("); i >= 0 {
		k = k[:i]
	}
	start := 0
	if strings.HasPrefix(k, "@") {
		start = 1
	}
	if i := strings.Index(k[start:], "@"); i >= 0 {
		return k[:start+i]
	}
	if i := strings.LastIndex(k, "/"); i > 0 {
		return k[:i]
	}
	return k
}
