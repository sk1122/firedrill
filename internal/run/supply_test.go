package run

import (
	"reflect"
	"testing"

	"github.com/sk1122/firedrill/internal/graph"
)

func TestMarkNewInstallScripts(t *testing.T) {
	m := func(g *graph.Graph, known bool, scripts, newScripts []any) {
		attrs := map[string]any{"repo": "acme/api", "file": "package.json", "install_scripts": scripts,
			"install_scripts_known": known, "new_install_scripts": newScripts}
		node(g, "manifest:acme/api/package.json", graph.KindManifest, attrs)
	}
	newOf := func(g *graph.Graph) []any {
		n, _ := g.Get("manifest:acme/api/package.json")
		return n.Attrs["new_install_scripts"].([]any)
	}
	cases := []struct {
		name      string
		prev      func(*graph.Graph)
		known     bool
		scripts   []any
		want      []any
		noPrevRun bool
	}{
		{"first run", nil, true, []any{"esbuild"}, []any{}, true},
		{"first sighting of the manifest", func(*graph.Graph) {}, true, []any{"esbuild"}, []any{}, false},
		{"unchanged", func(g *graph.Graph) { m(g, true, []any{"esbuild"}, []any{}) }, true, []any{"esbuild"}, []any{}, false},
		{"gained one", func(g *graph.Graph) { m(g, true, []any{"esbuild"}, []any{}) }, true, []any{"acme-colors", "esbuild"}, []any{"acme-colors"}, false},
		{"still new a run later", func(g *graph.Graph) { m(g, true, []any{"acme-colors", "esbuild"}, []any{"acme-colors"}) }, true, []any{"acme-colors", "esbuild"}, []any{"acme-colors"}, false},
		{"was unknown", func(g *graph.Graph) { m(g, false, []any{}, []any{}) }, true, []any{"esbuild"}, []any{}, false},
		{"now unknown", func(g *graph.Graph) { m(g, true, []any{}, []any{}) }, false, []any{}, []any{}, false},
	}
	for _, c := range cases {
		g := graph.New()
		m(g, c.known, c.scripts, []any{})
		var prev graph.Reader
		if !c.noPrevRun {
			p := graph.New()
			c.prev(p)
			prev = p
		}
		markNewInstallScripts(g, prev)
		if got := newOf(g); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
