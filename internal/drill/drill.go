// Package drill holds the drill file format and its validation.
package drill

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Fetch is one named fact a drill reads.
type Fetch struct {
	Alias string
	Fact  string
	Args  map[string]string
	Line  int
}

// Condition is one CEL expression with the line it came from.
type Condition struct {
	Expr string
	Line int
}

// Drill is one parsed drill file.
type Drill struct {
	Firedrill   string
	ID          string
	Safeguard   string
	Source      string
	Owner       string
	Severity    string
	ForEach     string
	Fetches     []Fetch
	AppliesWhen *Condition
	NAReason    string
	PassWhen    []Condition
	WarnWhen    []Condition
	Fix         string
	MapsTo      []string
	File        string
	Hash        string
}

// Issue is one problem found in a drill file.
type Issue struct {
	File    string
	Line    int
	Message string
	Warning bool
}

func (i Issue) String() string {
	level := "error"
	if i.Warning {
		level = "warning"
	}
	if i.Line > 0 {
		return fmt.Sprintf("%s:%d: %s: %s", i.File, i.Line, level, i.Message)
	}
	return fmt.Sprintf("%s: %s: %s", i.File, level, i.Message)
}

// Hash returns the SHA-256 of a drill file's bytes.
func Hash(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

var idPattern = regexp.MustCompile(`^[a-z0-9-]+/[a-z0-9-]+$`)

var knownFields = map[string]bool{
	"firedrill": true, "id": true, "safeguard": true, "source": true, "owner": true, "severity": true,
	"for_each": true, "fetch": true, "applies_when": true, "na_reason": true, "pass_when": true,
	"warn_when": true, "fix": true, "maps_to": true,
}

var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true}

// Parse reads one drill file. Every structural problem is returned as an Issue
// with its line, so a broken file reports all it can in one pass.
func Parse(file string, data []byte) (*Drill, []Issue) {
	d := &Drill{File: file, Hash: Hash(data)}
	var issues []Issue
	add := func(line int, format string, args ...any) {
		issues = append(issues, Issue{File: file, Line: line, Message: fmt.Sprintf(format, args...)})
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		add(0, "not valid YAML: %v. A condition with a colon followed by a space must use a folded block (- >-)", err)
		return nil, issues
	}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		add(1, "a drill file must be a YAML mapping")
		return nil, issues
	}
	lines := strings.Split(string(data), "\n")
	seen := map[string]bool{}
	m := root.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if !knownFields[k.Value] {
			add(k.Line, "unknown field %q", k.Value)
			continue
		}
		if seen[k.Value] {
			add(k.Line, "field %q appears twice", k.Value)
		}
		seen[k.Value] = true
		switch k.Value {
		case "firedrill":
			d.Firedrill = v.Value
		case "id":
			d.ID = v.Value
		case "safeguard":
			d.Safeguard = v.Value
		case "source":
			d.Source = v.Value
		case "owner":
			d.Owner = v.Value
		case "severity":
			d.Severity = v.Value
		case "for_each":
			d.ForEach = v.Value
		case "na_reason":
			d.NAReason = v.Value
		case "fix":
			d.Fix = v.Value
		case "applies_when":
			if v.Kind != yaml.ScalarNode {
				add(v.Line, "applies_when must be one CEL condition")
				continue
			}
			checkScalar(v, lines, add)
			d.AppliesWhen = &Condition{Expr: v.Value, Line: v.Line}
		case "pass_when":
			d.PassWhen = conditions(k.Value, v, lines, add)
		case "warn_when":
			d.WarnWhen = conditions(k.Value, v, lines, add)
		case "maps_to":
			if v.Kind != yaml.SequenceNode {
				add(v.Line, "maps_to must be a list")
				continue
			}
			for _, e := range v.Content {
				d.MapsTo = append(d.MapsTo, e.Value)
			}
		case "fetch":
			d.Fetches = fetches(v, add)
		}
	}
	if !seen["firedrill"] {
		add(1, "missing required field firedrill")
	} else if d.Firedrill != "v0" {
		add(1, "unsupported format version %q, expected v0", d.Firedrill)
	}
	if !seen["id"] {
		add(1, "missing required field id")
	} else if !idPattern.MatchString(d.ID) {
		add(1, "id %q must be pack/slug in lowercase letters, digits and dashes", d.ID)
	}
	if !seen["safeguard"] || strings.TrimSpace(d.Safeguard) == "" {
		add(1, "missing required field safeguard")
	}
	if !seen["severity"] {
		add(1, "missing required field severity")
	} else if !severities[d.Severity] {
		add(1, "severity %q must be critical, high, medium or low", d.Severity)
	}
	if !seen["fetch"] || len(d.Fetches) == 0 {
		add(1, "missing required field fetch: a drill must read at least one fact")
	}
	if !seen["pass_when"] || len(d.PassWhen) == 0 {
		add(1, "missing required field pass_when: a drill needs at least one condition")
	}
	return d, issues
}

func conditions(field string, v *yaml.Node, lines []string, add func(int, string, ...any)) []Condition {
	if v.Kind != yaml.SequenceNode {
		add(v.Line, "%s must be a list of CEL conditions", field)
		return nil
	}
	var out []Condition
	for _, e := range v.Content {
		if e.Kind != yaml.ScalarNode {
			add(e.Line, "%s entries must be single CEL conditions", field)
			continue
		}
		checkScalar(e, lines, add)
		out = append(out, Condition{Expr: e.Value, Line: e.Line})
	}
	return out
}

// checkScalar enforces the one multi-line form the format accepts: a folded
// block. A plain scalar spread over lines reads differently than it looks.
func checkScalar(n *yaml.Node, lines []string, add func(int, string, ...any)) {
	if n.Style&yaml.LiteralStyle != 0 {
		add(n.Line, "a condition must use a folded block (- >-), not a literal block")
		return
	}
	if n.Style&yaml.FoldedStyle != 0 {
		return
	}
	if n.Line >= 1 && n.Line <= len(lines) && !strings.Contains(lines[n.Line-1], n.Value) && n.Style == 0 {
		add(n.Line, "a multi-line condition must use a folded block (- >-)")
	}
}

func fetches(v *yaml.Node, add func(int, string, ...any)) []Fetch {
	if v.Kind != yaml.MappingNode {
		add(v.Line, "fetch must map names to facts")
		return nil
	}
	var out []Fetch
	for i := 0; i+1 < len(v.Content); i += 2 {
		alias, spec := v.Content[i], v.Content[i+1]
		f := Fetch{Alias: alias.Value, Line: alias.Line, Args: map[string]string{}}
		if spec.Kind != yaml.MappingNode {
			add(alias.Line, "fetch %q must be { fact: name, args: {...} }", alias.Value)
			continue
		}
		for j := 0; j+1 < len(spec.Content); j += 2 {
			key, val := spec.Content[j], spec.Content[j+1]
			switch key.Value {
			case "fact":
				f.Fact = val.Value
			case "args":
				if val.Kind != yaml.MappingNode {
					add(val.Line, "args of %q must be a mapping", alias.Value)
					continue
				}
				for a := 0; a+1 < len(val.Content); a += 2 {
					f.Args[val.Content[a].Value] = val.Content[a+1].Value
				}
			default:
				add(key.Line, "fetch %q has unknown key %q", alias.Value, key.Value)
			}
		}
		if f.Fact == "" {
			add(alias.Line, "fetch %q does not name a fact", alias.Value)
			continue
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// LoadDir reads every *.drill.yaml below a directory, sorted by path.
func LoadDir(dir string) ([]*Drill, []Issue, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() && strings.HasSuffix(p, ".drill.yaml") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(paths)
	var drills []*Drill
	var issues []Issue
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, err
		}
		d, iss := Load(p, data)
		issues = append(issues, iss...)
		if d != nil {
			drills = append(drills, d)
		}
	}
	return drills, issues, nil
}

// Load parses and validates one drill.
func Load(file string, data []byte) (*Drill, []Issue) {
	d, issues := Parse(file, data)
	if d == nil {
		return nil, issues
	}
	issues = append(issues, Validate(d)...)
	return d, issues
}

// HasErrors reports whether any issue is an error rather than a warning.
func HasErrors(issues []Issue) bool {
	for _, i := range issues {
		if !i.Warning {
			return true
		}
	}
	return false
}
