package hub

import (
	"embed"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/sk1122/firedrill/internal/report"
	"github.com/sk1122/firedrill/internal/run"
)

//go:embed assets
var assets embed.FS

// Slug turns a drill ID into a file name.
func Slug(id string) string { return strings.ReplaceAll(id, "/", "--") }

var funcs = template.FuncMap{
	"slug": Slug,
	"join": strings.Join,
	"verdictClass": func(v string) string {
		switch v {
		case "PASS":
			return "pass"
		case "FAIL":
			return "fail"
		case "WARN":
			return "warn"
		}
		return "na"
	},
}

type sitePack struct {
	Name    string
	Entries []*Entry
}

// WriteSite renders the hub's website into dir: an index of every drill and a
// page per drill. It needs no script and loads nothing from the network.
func WriteSite(dir string, h *Hub, now time.Time) error {
	fonts, err := report.FontCSS()
	if err != nil {
		return err
	}
	cssBytes, err := assets.ReadFile("assets/site.css")
	if err != nil {
		return err
	}
	css := template.CSS(cssBytes) // #nosec G203 -- an embedded file
	index, err := template.New("index.html").Funcs(funcs).ParseFS(assets, "assets/index.html")
	if err != nil {
		return err
	}
	page, err := template.New("drill.html").Funcs(funcs).ParseFS(assets, "assets/drill.html")
	if err != nil {
		return err
	}
	byPack := map[string][]*Entry{}
	for _, e := range h.Entries {
		byPack[e.Pack] = append(byPack[e.Pack], e)
	}
	var packs []sitePack
	for name, list := range byPack {
		sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		packs = append(packs, sitePack{Name: name, Entries: list})
	}
	sort.Slice(packs, func(i, j int) bool { return packs[i].Name < packs[j].Name })
	if err := os.MkdirAll(filepath.Join(dir, "drills"), 0o755); err != nil {
		return err
	}
	commit := h.Commit
	if len(commit) > 12 {
		commit = commit[:12]
	}
	f, err := os.Create(filepath.Join(dir, "index.html"))
	if err != nil {
		return err
	}
	err = index.Execute(f, map[string]any{
		"Fonts": fonts, "CSS": css, "Entries": h.Entries, "Packs": packs, "Commit": commit,
		"Generated": now.UTC().Format("2006-01-02 15:04 UTC"),
	})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	for _, e := range h.Entries {
		var tf run.TestFile
		_ = yaml.Unmarshal(e.Test, &tf)
		f, err := os.Create(filepath.Join(dir, "drills", Slug(e.ID)+".html"))
		if err != nil {
			return err
		}
		err = page.Execute(f, map[string]any{"Fonts": fonts, "CSS": css, "E": e, "Cases": tf.Cases})
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
	}
	return nil
}
