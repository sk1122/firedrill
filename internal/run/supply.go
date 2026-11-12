package run

import (
	"maps"
	"sort"

	"github.com/sk1122/firedrill/internal/graph"
)

// markNewInstallScripts fills in each manifest's new_install_scripts: the
// install scripts its lockfile marks now that are not in the baseline. The
// baseline is the previous run's install_scripts less what that run itself
// reported as new, so a new script stays new on every run until it leaves the
// lockfile, and a waiver is how it is accepted meanwhile. There is no baseline,
// and so nothing new, on the first run, for a manifest first seen in this run,
// or when either run's lockfile did not record install scripts.
func markNewInstallScripts(g *graph.Graph, prev graph.Reader) {
	if prev == nil {
		return
	}
	for _, n := range g.Nodes(graph.KindManifest) {
		old, ok := prev.Get(n.ID)
		if !ok || old.Attrs["install_scripts_known"] != true || n.Attrs["install_scripts_known"] != true {
			continue
		}
		if _, ok := old.Attrs["install_scripts"]; !ok {
			continue
		}
		baseline := stringSet(old.Attrs["install_scripts"])
		for name := range stringSet(old.Attrs["new_install_scripts"]) {
			delete(baseline, name)
		}
		var added []string
		for name := range stringSet(n.Attrs["install_scripts"]) {
			if !baseline[name] {
				added = append(added, name)
			}
		}
		sort.Strings(added)
		list := make([]any, len(added))
		for i, a := range added {
			list[i] = a
		}
		attrs := maps.Clone(n.Attrs)
		attrs["new_install_scripts"] = list
		n.Attrs = attrs
		g.Node(n)
	}
}

func stringSet(v any) map[string]bool {
	out := map[string]bool{}
	switch l := v.(type) {
	case []any:
		for _, x := range l {
			if s, ok := x.(string); ok {
				out[s] = true
			}
		}
	case []string:
		for _, s := range l {
			out[s] = true
		}
	}
	return out
}
