package web

import (
	"strings"
	"testing"
)

func TestPageScriptsParsesTagsRobustly(t *testing.T) {
	html := `<html><head>
<SCRIPT type="module" SRC="https://cdn.one.example/a.js?v=1"></SCRIPT>
<script integrity='sha512-AbC/+dEf=' crossorigin src=//cdn.two.example/b.js></script>
<script data-x="a>b" src="https://cdn.three.example/c.js" integrity="md5-nope"></script>
<script src="/local.js"></script>
<script src="data:text/javascript,alert(1)"></script>
<script>inline()</script>
<link rel="modulepreload" href="https://cdn.four.example/d.js">
<link rel="preload" as="script" href="https://cdn.five.example/e.js" integrity="sha256-x sha384-AbCd">
<link rel="preload" as="style" href="https://cdn.six.example/f.css">
<link rel="stylesheet" href="https://cdn.six.example/g.css">
<!-- <script src="https://cdn.gone.example/h.js"></script> -->
</head></html>`
	got := PageScripts("www.acme.com", "/", html)
	want := []Script{
		{URL: "https://cdn.one.example/a.js?v=1", Host: "cdn.one.example", Path: "/a.js"},
		{URL: "https://cdn.two.example/b.js", Host: "cdn.two.example", Path: "/b.js", Integrity: true, CrossOrigin: true},
		{URL: "https://cdn.three.example/c.js", Host: "cdn.three.example", Path: "/c.js"},
		{URL: "https://www.acme.com/local.js", Host: "www.acme.com", Path: "/local.js"},
		{URL: "https://cdn.four.example/d.js", Host: "cdn.four.example", Path: "/d.js"},
		{URL: "https://cdn.five.example/e.js", Host: "cdn.five.example", Path: "/e.js", Integrity: true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestSafePathDropsTokenLikeParts(t *testing.T) {
	if p := safePath("/npm/acme-widgets@2.1.0/dist/widgets.min.js"); p != "/npm/acme-widgets@2.1.0/dist/widgets.min.js" {
		t.Fatal(p)
	}
	if p := safePath("/t/" + "Zx8mQ2pL9vT4rW7y" + "B1nC6dF3/loader.js"); p != "" {
		t.Fatalf("a token in a path is not kept: %s", p)
	}
	if p := safePath("/" + strings.Repeat("a/", 150)); len(p) != maxScriptPath {
		t.Fatal(len(p))
	}
}
