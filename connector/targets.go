package connector

import (
	"path/filepath"
)

// RepoTarget is one repo a run covers.
type RepoTarget struct {
	Name string // org/repo, or the folder name for a local checkout not in config
	Path string // local checkout, empty for remote only
}

// RepoTargets merges repos in config with local checkouts from --path. A repo in
// config can only be read remotely when a GitHub token is present.
func RepoTargets(s Scope) []RepoTarget {
	org := s.Project.Config.GitHub.Org
	byBase := map[string]string{}
	for _, p := range s.Paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		byBase[filepath.Base(abs)] = abs
	}
	var out []RepoTarget
	for _, r := range s.Project.Config.GitHub.Repos {
		name := r
		if org != "" {
			name = org + "/" + r
		}
		path, local := byBase[r]
		if local {
			delete(byBase, r)
		} else if s.Token == "" {
			continue
		}
		out = append(out, RepoTarget{Name: name, Path: path})
	}
	for _, p := range s.Paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if path, ok := byBase[filepath.Base(abs)]; ok {
			out = append(out, RepoTarget{Name: filepath.Base(abs), Path: path})
			delete(byBase, filepath.Base(abs))
		}
	}
	return out
}
