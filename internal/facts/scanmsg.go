package facts

import (
	"sort"
	"strings"

	"github.com/sk1122/firedrill/internal/graph"
)

// GroupScanMessages joins one kind of message, partial or note, across scan
// records, so a problem shared by many projects reads as one line naming them
// all. A record may carry the message with {projects} in place of its scope,
// under key + "_group"; records with the same such message become one line
// listing their scopes, sorted. A record with only key is kept as it is. Lines
// come back in the order of the records.
func GroupScanMessages(scans []graph.Node, key string) []string {
	var out []string
	groups := map[string][]string{}
	at := map[string]int{}
	for _, n := range scans {
		group := strAttr(n, key+"_group")
		if group == "" {
			if msg := strAttr(n, key); msg != "" {
				out = append(out, msg)
			}
			continue
		}
		if _, ok := groups[group]; !ok {
			at[group] = len(out)
			out = append(out, "")
		}
		groups[group] = append(groups[group], strAttr(n, "scope"))
	}
	for group, scopes := range groups {
		sort.Strings(scopes)
		out[at[group]] = strings.ReplaceAll(group, "{projects}", strings.Join(scopes, ", "))
	}
	return out
}
