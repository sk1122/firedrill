package files

import (
	"reflect"
	"strings"
	"testing"
)

const npmLock = `{"name":"api","lockfileVersion":3,"packages":{
  "":{"name":"api","hasInstallScript":true},
  "node_modules/esbuild":{"version":"0.21.5","hasInstallScript":true},
  "node_modules/@parcel/watcher":{"version":"2.4.1","hasInstallScript":true},
  "node_modules/a/node_modules/esbuild":{"version":"0.18.0","hasInstallScript":true},
  "node_modules/left-pad":{"version":"1.3.0"},
  "packages/web":{"name":"web","hasInstallScript":true}}}`

func TestInstallScriptsFromEachLockfile(t *testing.T) {
	cases := []struct {
		file, data string
		want       []string
		known      bool
	}{
		{"package-lock.json", npmLock, []string{"@parcel/watcher", "esbuild"}, true},
		{"npm-shrinkwrap.json", `{"lockfileVersion":2,"packages":{}}`, []string{}, true},
		{"package-lock.json", `{"lockfileVersion":1,"dependencies":{"esbuild":{"version":"0.1.0"}}}`, []string{}, false},
		{"pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /esbuild@0.21.5:\n    requiresBuild: true\n  /@swc/core@1.4.0(@swc/helpers@0.5.0):\n    requiresBuild: true\n  /left-pad@1.3.0:\n    dev: false\n", []string{"@swc/core", "esbuild"}, true},
		{"pnpm-lock.yaml", "lockfileVersion: 5.4\npackages:\n  /esbuild/0.15.0:\n    requiresBuild: true\n  /@acme/x/1.0.0:\n    requiresBuild: true\n", []string{"@acme/x", "esbuild"}, true},
		{"pnpm-lock.yaml", "lockfileVersion: '6.0'\npackages:\n  /left-pad@1.3.0:\n    dev: false\n", []string{}, true},
		// pnpm 9 no longer writes requiresBuild, so an absence says nothing.
		{"pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  esbuild@0.21.5:\n    resolution: {integrity: sha512-x}\n", []string{}, false},
		{"yarn.lock", "esbuild@^0.21.0:\n  version \"0.21.5\"\n", []string{}, false},
		{"bun.lock", `{"lockfileVersion":0}`, []string{}, false},
	}
	for _, c := range cases {
		got, known := InstallScripts(File{Path: c.file, Data: []byte(c.data)})
		if !reflect.DeepEqual(got, c.want) || known != c.known {
			t.Errorf("%s %.30q: got %v %v, want %v %v", c.file, c.data, got, known, c.want, c.known)
		}
	}
	if got, known := InstallScripts(File{Path: "package-lock.json", Unscanned: true}); len(got) != 0 || known {
		t.Errorf("a lockfile too large to read is unknown: %v %v", got, known)
	}
}

func TestScanManifests(t *testing.T) {
	all := []File{
		{Path: "package.json", Data: []byte(`{"name":"root","workspaces":["packages/*","!packages/legacy"]}`)},
		{Path: "package-lock.json", Data: []byte(npmLock)},
		{Path: "packages/web/package.json", Data: []byte(`{"name":"web"}`)},
		{Path: "packages/legacy/package.json", Data: []byte(`{"name":"legacy"}`)},
		{Path: "tools/cli/package.json", Data: []byte(`{"packageManager":"pnpm@9.1.0"}`)},
		{Path: "apps/site/package.json", Data: []byte(`{}`)},
		{Path: "apps/site/yarn.lock", Data: []byte("x"), Ignored: true},
		{Path: "mono/package.json", Data: []byte(`{}`)},
		{Path: "mono/pnpm-workspace.yaml", Data: []byte("packages:\n  - 'libs/**'\n")},
		{Path: "mono/pnpm-lock.yaml", Unscanned: true},
		{Path: "mono/libs/a/b/package.json", Data: []byte(`not json`)},
	}
	type row struct {
		manager, lock string
		committed     bool
		scripts       []string
		known         bool
	}
	want := map[string]row{
		"package.json":                 {"npm", "package-lock.json", true, []string{"@parcel/watcher", "esbuild"}, true},
		"packages/web/package.json":    {"npm", "package-lock.json", true, []string{}, true},
		"packages/legacy/package.json": {"unknown", "", false, []string{}, false},
		"tools/cli/package.json":       {"pnpm", "", false, []string{}, false},
		"apps/site/package.json":       {"yarn", "apps/site/yarn.lock", false, []string{}, false},
		"mono/package.json":            {"pnpm", "mono/pnpm-lock.yaml", true, []string{}, false},
		"mono/libs/a/b/package.json":   {"pnpm", "mono/pnpm-lock.yaml", true, []string{}, false},
	}
	got := ScanManifests(all)
	if len(got) != len(want) {
		t.Fatalf("got %d manifests", len(got))
	}
	for _, m := range got {
		w, ok := want[m.File]
		if !ok {
			t.Fatalf("unexpected %s", m.File)
		}
		g := row{m.Manager, m.Lockfile, m.Committed, m.Scripts, m.ScriptsKnown}
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s: got %+v, want %+v", m.File, g, w)
		}
	}
}

func TestWorkspaceGlobs(t *testing.T) {
	for _, c := range []struct {
		pats []string
		rel  string
		want bool
	}{
		{[]string{"packages/*"}, "packages/web", true},
		{[]string{"packages/*"}, "packages/web/sub", false},
		{[]string{"apps/**"}, "apps/a/b", true},
		{[]string{"./tools/cli/"}, "tools/cli", true},
		{[]string{"packages/*", "!packages/old"}, "packages/old", false},
		{nil, "x", false},
	} {
		if got := workspaceMatch(c.pats, c.rel); got != c.want {
			t.Errorf("%v %s: got %v", c.pats, c.rel, got)
		}
	}
}

func TestBigLockfileIsStillSeen(t *testing.T) {
	big := `{"lockfileVersion":3,"packages":{"node_modules/esbuild":{"hasInstallScript":true},"node_modules/pad":{"version":"` +
		strings.Repeat("x", MaxFileSize) + `"}}}`
	root := writeTree(t, map[string]string{
		"package.json":              `{}`,
		"package-lock.json":         big,
		"web/package.json":          `{}`,
		"web/bun.lockb":             "\x00\x01binary",
		".gitignore":                "ignored/package-lock.json\n",
		"ignored/package.json":      `{}`,
		"ignored/package-lock.json": `{"lockfileVersion":3,"packages":{}}`,
	})
	files := walked(t, root)
	lock := files["package-lock.json"]
	if !lock.Unscanned || lock.Data == nil {
		t.Fatalf("a lockfile over MaxFileSize is kept and parsed, never scanned: %v %d", lock.Unscanned, len(lock.Data))
	}
	if b := files["web/bun.lockb"]; !b.Unscanned || b.Data != nil {
		t.Fatalf("a binary lockfile is kept by path alone: %+v", b)
	}
	if ig := files["ignored/package-lock.json"]; !ig.Ignored {
		t.Fatalf("a gitignored lockfile is read and marked: %+v", ig)
	}
	var all []File
	for _, f := range files {
		all = append(all, f)
	}
	for _, m := range ScanManifests(all) {
		switch m.File {
		case "package.json":
			if !m.Committed || !reflect.DeepEqual(m.Scripts, []string{"esbuild"}) || !m.ScriptsKnown {
				t.Errorf("big lockfile: %+v", m)
			}
		case "web/package.json":
			if !m.Committed || m.Manager != "bun" || m.ScriptsKnown {
				t.Errorf("bun.lockb: %+v", m)
			}
		case "ignored/package.json":
			if m.Committed || m.Lockfile != "ignored/package-lock.json" {
				t.Errorf("gitignored lockfile: %+v", m)
			}
		}
	}
}
