package files

import (
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// MCP server detail. Only the host of a URL, the base name of a command and
// the package it fetches are kept: a URL can carry a token in its path or
// query, and arguments can carry secrets, so neither is ever stored.

// serverURL returns the URL an entry is defined by. Claude Code, Cursor and
// VS Code use url, Gemini uses url (SSE) or httpUrl, and Windsurf serverUrl.
func (e mcpEntry) serverURL() string {
	for _, u := range []string{e.URL, e.HTTPURL, e.ServerURL} {
		if strings.TrimSpace(u) != "" {
			return strings.TrimSpace(u)
		}
	}
	return ""
}

// describe fills in how a server runs: over the network to a host, or as a
// local command, and what package that command fetches.
func describe(s *MCPServer, e mcpEntry) {
	if u := e.serverURL(); u != "" {
		s.Transport, s.Host = "http", HostOf(u)
		s.Pinned = true
		return
	}
	s.Transport = "stdio"
	fields := strings.Fields(e.Command)
	if len(fields) == 0 {
		s.Pinned = true
		return
	}
	s.Command = commandName(fields[0])
	args := append(append([]string{}, fields[1:]...), e.Args...)
	p := fetchedPackage(s.Command, args)
	s.Package, s.Version, s.Pinned = p.name, p.version, p.pinned
	if p.remote != "" {
		// mcp-remote runs locally but only to reach a remote server, so the
		// server is judged by that host.
		s.Transport, s.Host = "http", HostOf(p.remote)
	}
}

// HostOf returns the lowercased hostname of a URL, with no scheme, port,
// path, query or user info, or "" when there is none, as when the host is an
// unresolved ${VAR}.
func HostOf(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if h == "" || strings.ContainsAny(h, "${}% ") {
		return ""
	}
	return h
}

// Loopback reports localhost and loopback addresses.
func Loopback(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// commandName is the executable's base name, or the path for a repo-relative
// script. An absolute path is cut to its base name, since it names a home
// folder.
func commandName(c string) string {
	c = strings.ReplaceAll(c, `\`, "/")
	switch {
	case strings.HasPrefix(c, "/"), strings.HasPrefix(c, "~"), len(c) > 2 && c[1] == ':':
		return path.Base(c)
	case strings.Contains(c, "/"):
		return path.Clean(c)
	}
	return c
}

type pkgSpec struct {
	name, version string
	pinned        bool
	remote        string // the URL given to mcp-remote
}

// localSpec is a path or a file: spec, which runs code from the repo.
func localSpec(s string) bool {
	return s == "." || s == ".." || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") ||
		strings.HasPrefix(s, "/") || strings.HasPrefix(s, "~") || strings.HasPrefix(s, "file:")
}

// fetchedPackage finds the package or image a command fetches and runs.
// Commands that run local code fetch nothing.
func fetchedPackage(cmd string, args []string) pkgSpec {
	base := strings.TrimSuffix(strings.TrimSuffix(path.Base(cmd), ".cmd"), ".exe")
	switch base {
	case "npx", "bunx":
		return npmPackage(args)
	case "npm":
		if len(args) > 0 && (args[0] == "exec" || args[0] == "x") {
			return npmPackage(args[1:])
		}
	case "pnpm", "yarn":
		if len(args) > 0 && args[0] == "dlx" {
			return npmPackage(args[1:])
		}
	case "bun":
		if len(args) > 0 && args[0] == "x" {
			return npmPackage(args[1:])
		}
	case "uvx":
		return pyPackage(args, uvValueFlags, "--from")
	case "uv":
		if len(args) > 1 && args[0] == "tool" && args[1] == "run" {
			return pyPackage(args[2:], uvValueFlags, "--from")
		}
	case "pipx":
		if len(args) > 0 && args[0] == "run" {
			return pyPackage(args[1:], pipxValueFlags, "--spec")
		}
	case "docker", "podman":
		if len(args) > 0 && args[0] == "run" {
			return dockerImage(args[1:])
		}
		if len(args) > 1 && args[0] == "container" && args[1] == "run" {
			return dockerImage(args[2:])
		}
	}
	return pkgSpec{pinned: true}
}

// npmValueFlags take a value in npx, bunx, npm exec, pnpm dlx and yarn dlx.
var npmValueFlags = map[string]bool{"-p": true, "--package": true, "-c": true, "--call": true, "--registry": true, "--cache": true, "--userconfig": true}

// npmPackage reads npx-style arguments. -p/--package names the package
// outright; otherwise it is the first positional argument.
func npmPackage(args []string) pkgSpec {
	var named, first string
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			if first == "" && i+1 < len(args) {
				first, rest = args[i+1], args[i+2:]
			}
			break
		}
		if strings.HasPrefix(a, "-") {
			flag, val, hasVal := strings.Cut(a, "=")
			if !npmValueFlags[flag] {
				continue
			}
			if !hasVal && i+1 < len(args) {
				i++
				val = args[i]
			}
			if (flag == "-p" || flag == "--package") && named == "" {
				named = val
			}
			continue
		}
		first, rest = a, args[i+1:]
		break
	}
	spec := named
	if spec == "" {
		spec = first
	}
	if spec == "" || localSpec(spec) {
		return pkgSpec{pinned: true}
	}
	p := npmSpec(spec)
	if p.name == "mcp-remote" {
		for _, a := range rest {
			if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") {
				p.remote = a
				break
			}
		}
	}
	return p
}

var (
	semverExact = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	fullCommit  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	ghShorthand = regexp.MustCompile(`^(?:github:)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?:#(.*))?$`)
)

// npmSpec splits name@version. A git or URL spec keeps only its host or
// owner/repo, never the URL, and is pinned only by a full commit.
func npmSpec(spec string) pkgSpec {
	if strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") || strings.HasPrefix(spec, "git@") {
		_, ref, _ := strings.Cut(spec, "#")
		host := HostOf(strings.TrimPrefix(spec, "git+"))
		if host == "" {
			host = "unknown"
		}
		return commitPinned("url:"+host, ref)
	}
	if m := ghShorthand.FindStringSubmatch(spec); m != nil && !strings.HasPrefix(spec, "@") {
		return commitPinned("github:"+m[1], m[2])
	}
	name, version := spec, ""
	if at := strings.LastIndex(spec, "@"); at > 0 {
		name, version = spec[:at], spec[at+1:]
	}
	if semverExact.MatchString(version) {
		return pkgSpec{name: name, version: strings.TrimPrefix(version, "v"), pinned: true}
	}
	return pkgSpec{name: name}
}

// commitPinned pins a git spec by a full commit, kept as its first 12
// characters: a 40-character hex string has a secret's shape.
func commitPinned(name, ref string) pkgSpec {
	if fullCommit.MatchString(ref) {
		return pkgSpec{name: name, version: "commit:" + ref[:12], pinned: true}
	}
	return pkgSpec{name: name}
}

var (
	uvValueFlags = map[string]bool{"--from": true, "--with": true, "--with-editable": true, "--with-requirements": true,
		"--python": true, "-p": true, "--index": true, "--index-url": true, "--extra-index-url": true, "--default-index": true}
	pipxValueFlags = map[string]bool{"--spec": true, "--python": true, "--pip-args": true, "--index-url": true}
	pyName         = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?(.*)$`)
	pyExact        = regexp.MustCompile(`^\d+(\.\d+)+((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?$`)
)

// pyPackage reads uvx and pipx run arguments. The from flag (--from or
// --spec) names the package outright; otherwise it is the first positional
// argument.
func pyPackage(args []string, valueFlags map[string]bool, fromFlag string) pkgSpec {
	var named, first string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			flag, val, hasVal := strings.Cut(a, "=")
			if !valueFlags[flag] {
				continue
			}
			if !hasVal && i+1 < len(args) {
				i++
				val = args[i]
			}
			if flag == fromFlag && named == "" {
				named = val
			}
			continue
		}
		first = a
		break
	}
	spec := named
	if spec == "" {
		spec = first
	}
	if spec == "" || localSpec(spec) {
		return pkgSpec{pinned: true}
	}
	if strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+") {
		_, ref, _ := strings.Cut(spec, "@")
		host := HostOf(strings.TrimPrefix(spec, "git+"))
		if host == "" {
			host = "unknown"
		}
		return commitPinned("url:"+host, ref)
	}
	m := pyName.FindStringSubmatch(spec)
	if m == nil {
		return pkgSpec{name: spec}
	}
	name, rest := strings.ToLower(m[1]), strings.TrimSpace(m[3])
	var version string
	switch {
	case strings.HasPrefix(rest, "==="):
		version = rest[3:]
	case strings.HasPrefix(rest, "=="):
		version = rest[2:]
	case strings.HasPrefix(rest, "@"):
		// uvx accepts name@version.
		version = rest[1:]
	}
	if pyExact.MatchString(version) {
		return pkgSpec{name: name, version: version, pinned: true}
	}
	return pkgSpec{name: name}
}

// dockerBoolFlags take no value. Any other flag without = is taken to take one.
var dockerBoolFlags = map[string]bool{
	"-i": true, "-t": true, "-d": true, "-q": true, "-it": true, "-ti": true, "-itd": true, "-dit": true,
	"--interactive": true, "--tty": true, "--detach": true, "--rm": true, "--init": true, "--read-only": true,
	"--privileged": true, "--quiet": true, "--no-healthcheck": true, "--oom-kill-disable": true, "--sig-proxy": true,
	"-P": true, "--publish-all": true,
}

var digestRe = regexp.MustCompile(`@sha256:([0-9a-f]{64})$`)

// dockerImage reads docker run arguments: the image is the first positional
// argument. A digest pins it, kept as sha256 and its first 12 characters,
// since 64 hex characters have a secret's shape. A tag pins it only when it is
// a full x.y.z version.
func dockerImage(args []string) pkgSpec {
	image := ""
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			continue
		}
		if strings.HasPrefix(a, "-") {
			if strings.Contains(a, "=") || dockerBoolFlags[a] {
				continue
			}
			i++ // the flag's value
			continue
		}
		image = a
		break
	}
	if image == "" {
		return pkgSpec{pinned: true}
	}
	image = strings.ToLower(image)
	if m := digestRe.FindStringSubmatch(image); m != nil {
		name := strings.TrimSuffix(image, m[0])
		if slash, colon := strings.LastIndex(name, "/"), strings.LastIndex(name, ":"); colon > slash {
			name = name[:colon]
		}
		return pkgSpec{name: name, version: "sha256:" + m[1][:12], pinned: true}
	}
	name, tag := image, ""
	if slash, colon := strings.LastIndex(image, "/"), strings.LastIndex(image, ":"); colon > slash {
		name, tag = image[:colon], image[colon+1:]
	}
	if semverExact.MatchString(tag) {
		return pkgSpec{name: name, version: tag, pinned: true}
	}
	return pkgSpec{name: name}
}
