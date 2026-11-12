package files

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
)

// Egress values, from most to least restricted. An agent config's egress says
// what its committed settings do to outbound network access:
//
//   - allowlist: a real boundary limits it to listed hosts, such as Claude
//     Code's sandbox or Cursor's sandbox.json.
//   - partial: only tool-level rules exist, such as rules on Claude Code's
//     WebFetch or a deny on curl, which a shell command or a program started
//     another way does not meet; or a sandbox with a way out.
//   - unsupported: the tool has no committed setting that limits hosts.
//   - open: the tool has one and nothing committed uses it.
const (
	EgressAllowlist   = "allowlist"
	EgressPartial     = "partial"
	EgressUnsupported = "unsupported"
	EgressOpen        = "open"
)

var egressRank = map[string]int{EgressAllowlist: 0, EgressPartial: 1, EgressUnsupported: 2, EgressOpen: 3}

// EgressRank orders egress values from most restricted (0) to open (3).
func EgressRank(e string) int { return egressRank[e] }

func worse(a, b string) string {
	if egressRank[b] > egressRank[a] {
		return b
	}
	return a
}

// NetSettings is what one agent settings file says about outbound access.
type NetSettings struct {
	// Claude Code. Sandbox settings and permission rules, from
	// https://code.claude.com/docs/en/sandboxing and
	// https://code.claude.com/docs/en/permissions.
	Claude           bool
	SandboxEnabled   *bool    // sandbox.enabled
	AllowUnsandboxed *bool    // sandbox.allowUnsandboxedCommands; unset means true
	Excluded         []string // sandbox.excludedCommands, which run outside the sandbox
	AllowedDomains   []string // sandbox.network.allowedDomains
	FetchDomains     []string // WebFetch(domain:...) allow rules, which the sandbox also allows
	FetchOpen        bool     // a bare WebFetch allow rule: fetch any URL with no prompt
	ToolRules        bool     // a deny or ask rule on WebFetch or WebSearch, or a deny on curl or wget

	// Cursor's sandbox.json, from https://cursor.com/docs/reference/sandbox.
	Cursor        bool
	CursorType    string   // type; insecure_none turns the sandbox off
	CursorDefault string   // networkPolicy.default; unset means deny
	CursorAllow   []string // networkPolicy.allow
}

// parseClaudeNet reads the sandbox block and the network rules of a Claude
// Code settings file.
func parseClaudeNet(data []byte, allow, deny, ask []string) *NetSettings {
	var doc struct {
		Sandbox struct {
			Enabled                  *bool    `json:"enabled"`
			AllowUnsandboxedCommands *bool    `json:"allowUnsandboxedCommands"`
			ExcludedCommands         []string `json:"excludedCommands"`
			Network                  struct {
				AllowedDomains []string `json:"allowedDomains"`
			} `json:"network"`
		} `json:"sandbox"`
	}
	_ = json.Unmarshal(data, &doc)
	n := &NetSettings{Claude: true, SandboxEnabled: doc.Sandbox.Enabled, AllowUnsandboxed: doc.Sandbox.AllowUnsandboxedCommands,
		Excluded: doc.Sandbox.ExcludedCommands, AllowedDomains: doc.Sandbox.Network.AllowedDomains}
	for _, r := range allow {
		tool, arg := splitRule(r)
		if tool != "WebFetch" {
			continue
		}
		if d, ok := strings.CutPrefix(arg, "domain:"); ok {
			n.FetchDomains = append(n.FetchDomains, d)
		} else if arg == "*" {
			n.FetchOpen = true
		}
	}
	for _, r := range append(append([]string{}, deny...), ask...) {
		switch tool, arg := splitRule(r); tool {
		case "WebFetch", "WebSearch":
			n.ToolRules = true
		case "Bash":
			cmd := strings.TrimSpace(arg)
			if strings.HasPrefix(cmd, "curl") || strings.HasPrefix(cmd, "wget") {
				n.ToolRules = true
			}
		}
	}
	return n
}

// parseCursorSandbox reads Cursor's sandbox.json.
func parseCursorSandbox(rel string, data []byte, scope string) (*AgentConfig, error) {
	var doc struct {
		Type          string `json:"type"`
		NetworkPolicy struct {
			Default string   `json:"default"`
			Allow   []string `json:"allow"`
		} `json:"networkPolicy"`
	}
	if err := json.Unmarshal(stripComments(data), &doc); err != nil {
		return nil, err
	}
	return &AgentConfig{Tool: "cursor", Scope: scope, File: rel, Net: &NetSettings{Cursor: true,
		CursorType: doc.Type, CursorDefault: doc.NetworkPolicy.Default, CursorAllow: doc.NetworkPolicy.Allow}}, nil
}

// Egress is the judged outbound access of one agent config.
type Egress struct {
	Egress    string
	Hosts     []string // hostnames allowed, sorted; wildcard entries as written
	Unbounded bool     // the allowlist holds an entry that allows every host
}

// precedence ranks Claude Code settings files: a local file overrides the
// shared project file, which overrides the user's.
func precedence(c *AgentConfig) int {
	switch {
	case c.Scope == "user":
		return 1
	case localOverride(c.File):
		return 3
	}
	return 2
}

// claudeEgress merges every Claude Code settings file, as Claude Code does:
// lists add up, and a setting comes from the highest file that sets it.
func claudeEgress(files []*AgentConfig) (Egress, bool) {
	var nets []*AgentConfig
	for _, c := range files {
		if c.Net != nil && c.Net.Claude {
			nets = append(nets, c)
		}
	}
	if len(nets) == 0 {
		return Egress{Egress: EgressOpen}, false
	}
	sort.SliceStable(nets, func(i, j int) bool { return precedence(nets[i]) < precedence(nets[j]) })
	var enabled, unsandboxed *bool
	var excluded, hosts []string
	fetchOpen, toolRules := false, false
	for _, c := range nets {
		n := c.Net
		if n.SandboxEnabled != nil {
			enabled = n.SandboxEnabled
		}
		if n.AllowUnsandboxed != nil {
			unsandboxed = n.AllowUnsandboxed
		}
		excluded = append(excluded, n.Excluded...)
		hosts = append(hosts, n.AllowedDomains...)
		hosts = append(hosts, n.FetchDomains...)
		fetchOpen = fetchOpen || n.FetchOpen
		toolRules = toolRules || n.ToolRules
	}
	e := Egress{Hosts: hostList(hosts)}
	e.Unbounded = unbounded(e.Hosts)
	sandboxed := enabled != nil && *enabled
	escape := unsandboxed == nil || *unsandboxed || len(excluded) > 0
	switch {
	case sandboxed && !escape && !fetchOpen:
		// Shell commands and what they start reach only the allowed hosts
		// through the sandbox proxy, with no retry outside it; WebFetch
		// follows its own rules and is not opened to every URL.
		e.Egress = EgressAllowlist
	case sandboxed, toolRules:
		e.Egress = EgressPartial
	default:
		e.Egress = EgressOpen
	}
	return e, true
}

// cursorEgress merges the user's and the repo's sandbox.json: the repo file
// wins, a deny default wins over allow, and allow lists add up.
func cursorEgress(files []*AgentConfig) Egress {
	var nets []*AgentConfig
	for _, c := range files {
		if c.Net != nil && c.Net.Cursor {
			nets = append(nets, c)
		}
	}
	if len(nets) == 0 {
		return Egress{Egress: EgressOpen}
	}
	sort.SliceStable(nets, func(i, j int) bool { return precedence(nets[i]) < precedence(nets[j]) })
	typ, deny := "", false
	var hosts []string
	for _, c := range nets {
		if c.Net.CursorType != "" {
			typ = c.Net.CursorType
		}
		if c.Net.CursorDefault != "allow" {
			deny = true
		}
		hosts = append(hosts, c.Net.CursorAllow...)
	}
	e := Egress{Hosts: hostList(hosts)}
	e.Unbounded = unbounded(e.Hosts)
	switch {
	case typ == "insecure_none", !deny:
		e.Egress = EgressOpen
	default:
		e.Egress = EgressAllowlist
	}
	return e
}

// serverEgress judges the MCP servers in one file. A remote server is reached
// at its host alone. A local server is a program with the user's network
// access: VS Code can sandbox one to listed domains; Claude Code, Cursor and
// Gemini CLI have no setting that limits it.
func serverEgress(c *AgentConfig) Egress {
	e := Egress{Egress: EgressAllowlist}
	var hosts []string
	for _, s := range c.Servers {
		switch {
		case s.Transport == "http" && s.Host != "":
			hosts = append(hosts, s.Host)
		case s.Transport == "http":
			e.Egress = worse(e.Egress, EgressPartial)
		case c.Tool == "vscode" && s.Sandboxed:
			hosts = append(hosts, s.SandboxHosts...)
		case c.Tool == "vscode":
			e.Egress = worse(e.Egress, EgressOpen)
		default:
			e.Egress = worse(e.Egress, EgressUnsupported)
		}
	}
	e.Hosts = hostList(hosts)
	e.Unbounded = unbounded(e.Hosts)
	return e
}

// JudgeEgress fills in each config's egress from every agent config read for
// one repo. A tool's agent settings judge every file of that tool, and a file
// of MCP servers is judged by its servers too.
func JudgeEgress(configs []*AgentConfig) map[*AgentConfig]Egress {
	claude, _ := claudeEgress(configs)
	cursor := cursorEgress(configs)
	out := map[*AgentConfig]Egress{}
	for _, c := range configs {
		var agent Egress
		hasAgent := true
		switch c.Tool {
		case "claude-code":
			agent = claude
		case "cursor":
			agent = cursor
		case "gemini":
			// Gemini CLI's sandbox is chosen by tools.sandbox and a Seatbelt
			// profile in an environment variable; no setting lists hosts.
			agent = Egress{Egress: EgressUnsupported}
		default:
			// VS Code's own agent settings are not in mcp.json and are not
			// read, so only its servers are judged.
			hasAgent = false
		}
		e := serverEgress(c)
		if hasAgent {
			e.Egress = worse(agent.Egress, e.Egress)
			e.Hosts = hostList(append(append([]string{}, agent.Hosts...), e.Hosts...))
			e.Unbounded = agent.Unbounded || e.Unbounded
		}
		out[c] = e
	}
	return out
}

// hostList keeps hostnames only: lower case, with no scheme, port or path,
// sorted and unique. A wildcard entry such as *.acme.com stays as written.
func hostList(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if i := strings.Index(h, "://"); i >= 0 {
			h = h[i+3:]
		}
		if _, _, err := net.ParseCIDR(h); err != nil {
			if i := strings.IndexAny(h, "/?#"); i >= 0 {
				h = h[:i]
			}
		}
		if host, _, err := net.SplitHostPort(h); err == nil {
			h = host
		}
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// unbounded reports an allowlist entry that allows every host: a bare *, or an
// address range covering every address.
func unbounded(hosts []string) bool {
	for _, h := range hosts {
		if h == "*" || h == "0.0.0.0/0" || h == "::/0" {
			return true
		}
	}
	return false
}
