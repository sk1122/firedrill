package run

import (
	"fmt"
	"sort"
	"strings"
)

// summarizeRows gives a reason that counts every row of a list by what it is,
// for lists where the first row alone would mislead. Today that is
// people.admins, whose problems differ in kind: principals nobody owns,
// admins who have left, and people's accounts not mapped to a person. It is
// empty for any other list, or when nothing in it is a problem. Each principal
// is counted once, however many roles it holds.
func summarizeRows(rows []any) string {
	if len(rows) == 0 {
		return ""
	}
	if first, _ := rows[0].(map[string]any); first == nil || first["unverified"] == nil || first["unowned"] == nil {
		return ""
	}
	unowned, unverified := map[string]map[string]bool{}, map[string]map[string]bool{}
	departed := map[string]bool{}
	count := func(m map[string]map[string]bool, key, id string) {
		if m[key] == nil {
			m[key] = map[string]bool{}
		}
		m[key][id] = true
	}
	for _, r := range rows {
		a, _ := r.(map[string]any)
		if a["power_known"] != true {
			continue
		}
		id, _ := a["id"].(string)
		system, _ := a["system"].(string)
		kind, _ := a["kind"].(string)
		switch {
		case a["departed"] == true:
			departed[id] = true
		case a["members_known"] != true:
		case a["unowned"] == true:
			if kind == "person" {
				kind = "deleted"
			}
			count(unowned, system+" "+kind, id)
		case a["unverified"] == true:
			count(unverified, system+" "+kind, id)
		}
	}
	var parts []string
	if s, n := phrase(unowned); n > 0 {
		parts = append(parts, s+" "+plural(n, "has", "have")+" no owner")
	}
	if n := len(departed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d %s to someone who has left or is suspended", n, plural(n, "admin belongs", "admins belong")))
	}
	if s, n := phrase(unverified); n > 0 {
		parts = append(parts, s+" "+plural(n, "is", "are")+" not mapped to a person")
	}
	if len(parts) == 0 {
		return ""
	}
	out := strings.Join(parts, "; ")
	if len(unverified) > 0 {
		out += " (map GitHub logins in .firedrill/people.yaml, or connect Google Workspace)"
	}
	return out
}

// nouns names each system and kind of principal, singular and plural.
var nouns = map[string][2]string{
	"gcp service_account":    {"GCP service account", "GCP service accounts"},
	"gcp group":              {"GCP group", "GCP groups"},
	"gcp domain":             {"GCP domain-wide grant", "GCP domain-wide grants"},
	"gcp public":             {"GCP public grant", "GCP public grants"},
	"gcp deleted":            {"deleted GCP member", "deleted GCP members"},
	"gcp person":             {"GCP member", "GCP members"},
	"github app":             {"GitHub app", "GitHub apps"},
	"github deploy_key":      {"GitHub deploy key", "GitHub deploy keys"},
	"github group":           {"GitHub team", "GitHub teams"},
	"github person":          {"GitHub admin", "GitHub admins"},
	"google person":          {"Google Workspace admin", "Google Workspace admins"},
	"google service_account": {"Google service account", "Google service accounts"},
}

// phrase counts principals by system and kind, as "3 GCP service accounts and
// 1 GitHub app", and returns the total.
func phrase(m map[string]map[string]bool) (string, int) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var words []string
	total := 0
	for _, k := range keys {
		n := len(m[k])
		total += n
		w, ok := nouns[k]
		if !ok {
			w = [2]string{k + " principal", k + " principals"}
		}
		words = append(words, fmt.Sprintf("%d %s", n, plural(n, w[0], w[1])))
	}
	switch len(words) {
	case 0:
		return "", 0
	case 1:
		return words[0], total
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1], total
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
