// Package secrets finds credentials in text. It is shared by the repo file
// scanner and the scanner that checks records before they are written.
package secrets

import (
	"math"
	"path"
	"regexp"
	"strings"
)

// The entropy rule for a value assigned to a credential-named variable.
const (
	MinEntropy = 3.5
	MinLength  = 20
)

// Finding is one credential in a file. Value is held in memory only, to be
// hashed, and must never be stored.
type Finding struct {
	Kind  string
	Line  int
	Value string
	KeyID string // AWS access key ID, an identifier and never the secret
}

var prefixes = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"aws_access_key", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"stripe_live", regexp.MustCompile(`\bsk_live_[0-9A-Za-z]{10,}\b`)},
	{"github_token", regexp.MustCompile(`\bghp_[0-9A-Za-z]{20,}\b`)},
	{"razorpay_live", regexp.MustCompile(`\brzp_live_[0-9A-Za-z]{10,}\b`)},
}

var assignment = regexp.MustCompile(`(?i)\b([A-Z0-9_.-]*(?:_TOKEN|_KEY|_SECRET|PASSWORD[A-Z0-9_]*))["']?\s*(?:[:=]|:=)\s*["']?([^\s"'#,;]+)`)

// Entropy returns the Shannon entropy of a string in bits per character.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]float64{}
	for _, r := range s {
		counts[r]++
	}
	total := float64(len([]rune(s)))
	h := 0.0
	for _, c := range counts {
		p := c / total
		h -= p * math.Log2(p)
	}
	return h
}

// HighEntropy applies the rule for a value with no known prefix.
func HighEntropy(v string) bool {
	if len(v) < MinLength || strings.HasPrefix(v, "$") || strings.Contains(v, "${") || strings.Contains(v, "{{") {
		return false
	}
	if strings.HasPrefix(v, "<") || strings.Contains(strings.ToLower(v), "example") || strings.Contains(strings.ToLower(v), "changeme") {
		return false
	}
	return Entropy(v) >= MinEntropy
}

// Scan finds credentials in a file's text, by known prefix and by variable name
// with a high-entropy value.
func Scan(text string) []Finding {
	var out []Finding
	for i, line := range strings.Split(text, "\n") {
		seen := map[string]bool{}
		for _, p := range prefixes {
			for _, m := range p.re.FindAllString(line, -1) {
				seen[m] = true
				f := Finding{Kind: p.kind, Line: i + 1, Value: m}
				if p.kind == "aws_access_key" {
					f.KeyID = m
				}
				out = append(out, f)
			}
		}
		for _, m := range assignment.FindAllStringSubmatch(line, -1) {
			v := m[2]
			if seen[v] || !HighEntropy(v) {
				continue
			}
			seen[v] = true
			out = append(out, Finding{Kind: "generic", Line: i + 1, Value: v})
		}
	}
	return out
}

// LooksLikeSecret is the record scanner's test for one value.
func LooksLikeSecret(v string) bool {
	for _, p := range prefixes {
		if p.re.MatchString(v) {
			return true
		}
	}
	if strings.ContainsAny(v, " \t\n/.@:") {
		return false
	}
	return HighEntropy(v)
}

// Classes decide what environment a file belongs to.
type Classes struct {
	ProdWords    []string
	StagingWords []string
	ExamplePaths []string
}

// DefaultClasses are the built-in rules. Config can add to them.
func DefaultClasses() Classes {
	return Classes{
		ProdWords:    []string{"prod", "production"},
		StagingWords: []string{"staging", "stage"},
		ExamplePaths: []string{"testdata/", "fixtures/", "__tests__/", "*.example", "*.sample", "*.template"},
	}
}

var wordSplit = regexp.MustCompile(`[^a-z0-9]+`)

// Class returns prod, staging, example or unknown for a file path. Words match
// whole, so product/ is not prod.
func (c Classes) Class(p string) string {
	p = strings.ToLower(path.Clean(strings.ReplaceAll(p, "\\", "/")))
	for _, pat := range c.ExamplePaths {
		pat = strings.ToLower(pat)
		if strings.HasSuffix(pat, "/") {
			if strings.HasPrefix(p, pat) || strings.Contains(p, "/"+pat) {
				return "example"
			}
			continue
		}
		if ok, _ := path.Match(pat, path.Base(p)); ok {
			return "example"
		}
	}
	words := map[string]bool{}
	for _, w := range wordSplit.Split(p, -1) {
		words[w] = true
	}
	for _, w := range c.ProdWords {
		if words[strings.ToLower(w)] {
			return "prod"
		}
	}
	for _, w := range c.StagingWords {
		if words[strings.ToLower(w)] {
			return "staging"
		}
	}
	return "unknown"
}
