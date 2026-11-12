package files

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// An egress boundary outside the agent is a limit on outbound network access
// that the agent itself cannot change: a firewall on the CI runner or the dev
// container it runs in, or managed settings a user cannot override. Firedrill
// reads it from repo files (and, with --include-home, the machine's managed
// settings). It shows that a boundary is configured, not that it is working
// on a given machine or run.

// Boundary values.
const (
	BoundaryEnforced = "enforced" // every place an agent is configured to run has one
	BoundaryPartial  = "partial"  // some do
	BoundaryNone     = "none"     // none do
	BoundaryUnknown  = "unknown"  // no agent is configured, or no place could be judged
)

// Dev container values.
const (
	DevNone      = "none"       // no dev container
	DevFirewall  = "firewall"   // a firewall script set up outside the agent, with NET_ADMIN
	DevNoNetwork = "no_network" // no network at all
	DevOpen      = "open"       // a dev container with neither
)

// AgentActions are the GitHub Actions that run a coding agent, and
// agentCommands the commands a run step uses to start one. One table, so the
// list is read in one place.
var (
	AgentActions = []string{
		"anthropics/claude-code-action",
		"anthropics/claude-code-base-action",
		"openai/codex-action",
		"google-github-actions/run-gemini-cli",
	}
	agentCommands = map[string]bool{"claude": true, "codex": true, "gemini": true, "cursor-agent": true, "aider": true}
	// agentPackages are the same agents started through npx.
	agentPackages = map[string]bool{"@anthropic-ai/claude-code": true, "@openai/codex": true, "@google/gemini-cli": true}
)

// hardenRunner is the runner-level egress control read. Its inputs, from the
// action's action.yml: egress-policy (audit or block, default block) and
// allowed-endpoints. It must be the first step of the job, and it does not
// work when the whole job runs in a container on a GitHub-hosted runner.
// https://github.com/step-security/harden-runner
const hardenRunner = "step-security/harden-runner"

// AgentJob is one CI job that runs a coding agent.
type AgentJob struct {
	ID string // workflow file#job
	// Bounded is true when the job has an egress control outside the agent:
	// harden-runner blocking egress before the agent starts, or a container
	// with no network.
	Bounded bool
	// Control names it: "harden-runner block", "container --network none".
	Control string
	// AllowedEndpoints is how many endpoints harden-runner allows.
	AllowedEndpoints int
	// Exposed is true for a job with no egress control at all that holds
	// secrets or a token that can write: the workflow references a secret,
	// or the job's token can write.
	Exposed bool
}

// runsAgent reports whether a step starts a coding agent.
func runsAgent(uses, run string) bool {
	action, _, _ := strings.Cut(strings.ToLower(uses), "@")
	for _, a := range AgentActions {
		if action == a {
			return true
		}
	}
	if strings.TrimSpace(run) == "" {
		return false
	}
	run = strings.ReplaceAll(run, "\\\n", " ")
	for _, cmd := range cmdSplit.Split(run, -1) {
		f := strings.Fields(cmd)
		for len(f) > 0 && (envAssign.MatchString(f[0]) || f[0] == "sudo" || f[0] == "env" || f[0] == "time" || f[0] == "exec" || f[0] == "command") {
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		if agentCommands[path.Base(f[0])] {
			return true
		}
		if f[0] == "npx" || f[0] == "bunx" || f[0] == "pnpx" {
			for _, a := range f[1:] {
				if strings.HasPrefix(a, "-") {
					continue
				}
				pkg := a
				if i := strings.LastIndex(a, "@"); i > 0 {
					pkg = a[:i]
				}
				if agentPackages[pkg] {
					return true
				}
				break
			}
		}
	}
	return false
}

var networkNone = regexp.MustCompile(`--net(?:work)?[= ]none\b`)

// AgentJobs lists the jobs of a workflow that run a coding agent, and whether
// each has an egress control the agent cannot change.
func AgentJobs(rel string, data []byte, w *Workflow) []AgentJob {
	var doc struct {
		Permissions yaml.Node `yaml:"permissions"`
		Jobs        map[string]struct {
			RunsOn      yaml.Node `yaml:"runs-on"`
			Permissions yaml.Node `yaml:"permissions"`
			Container   yaml.Node `yaml:"container"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
				Run  string            `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Jobs))
	for n := range doc.Jobs {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []AgentJob
	for _, name := range names {
		job := doc.Jobs[name]
		agentAt := -1
		for i, st := range job.Steps {
			if runsAgent(st.Uses, st.Run) {
				agentAt = i
				break
			}
		}
		if agentAt < 0 {
			continue
		}
		j := AgentJob{ID: rel + "#" + name}
		container, options := containerOf(&job.Container)
		selfHosted := strings.Contains(strings.ToLower(nodeText(&job.RunsOn)), "self-hosted")
		for i, st := range job.Steps[:agentAt] {
			action, _, _ := strings.Cut(strings.ToLower(st.Uses), "@")
			if action != hardenRunner || i != 0 {
				continue
			}
			policy := strings.TrimSpace(st.With["egress-policy"])
			// block is the action's default; audit only logs.
			if (policy == "" || policy == "block") && !container && !selfHosted {
				j.Bounded, j.Control = true, "harden-runner block"
				j.AllowedEndpoints = len(strings.Fields(st.With["allowed-endpoints"]))
			}
		}
		if !j.Bounded && container && networkNone.MatchString(options) {
			j.Bounded, j.Control = true, "container --network none"
		}
		if !j.Bounded && w != nil {
			level := permLevel(&job.Permissions)
			write := level == "write" || (level == "undeclared" && w.Permissions != "read")
			j.Exposed = len(w.Secrets) > 0 || write
		}
		out = append(out, j)
	}
	return out
}

// containerOf reads a job's container: whether it has one, and its options.
func containerOf(n *yaml.Node) (bool, string) {
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value != "", ""
	case yaml.MappingNode:
		opts := ""
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "options" {
				opts = n.Content[i+1].Value
			}
		}
		return true, opts
	}
	return false, ""
}

func nodeText(n *yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		return n.Value
	}
	var parts []string
	for _, c := range n.Content {
		parts = append(parts, nodeText(c))
	}
	return strings.Join(parts, " ")
}

var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

// devcontainerFile matches the dev container definitions the spec allows.
var devcontainerFile = regexp.MustCompile(`^(?:\.devcontainer/(?:[^/]+/)?devcontainer\.json|\.devcontainer\.json)$`)

// Devcontainer judges a repo's dev containers. A firewall counts when a
// lifecycle command runs an init-firewall script, as Claude Code's reference
// container does, and runArgs grant NET_ADMIN so the script can set rules; the
// agent runs as a user who cannot change them. --network=none in runArgs, or
// network_mode: none or only internal networks for the compose service the
// container runs, means no network at all. The worst container decides.
// https://code.claude.com/docs/en/devcontainer
func Devcontainer(all []File) string {
	byPath := map[string][]byte{}
	for _, f := range all {
		byPath[f.Path] = f.Data
	}
	result := DevNone
	rank := map[string]int{DevNone: 0, DevNoNetwork: 1, DevFirewall: 2, DevOpen: 3}
	for _, f := range all {
		if !devcontainerFile.MatchString(f.Path) {
			continue
		}
		v := judgeDevcontainer(f.Path, f.Data, byPath)
		if result == DevNone || rank[v] > rank[result] {
			result = v
		}
	}
	return result
}

func judgeDevcontainer(rel string, data []byte, files map[string][]byte) string {
	var doc struct {
		RunArgs           []string        `json:"runArgs"`
		PostCreate        json.RawMessage `json:"postCreateCommand"`
		PostStart         json.RawMessage `json:"postStartCommand"`
		PostAttach        json.RawMessage `json:"postAttachCommand"`
		DockerComposeFile json.RawMessage `json:"dockerComposeFile"`
		Service           string          `json:"service"`
	}
	if json.Unmarshal(trailingComma.ReplaceAll(stripComments(data), []byte("$1")), &doc) != nil {
		return DevOpen
	}
	args := strings.Join(doc.RunArgs, " ")
	if networkNone.MatchString(args) {
		return DevNoNetwork
	}
	netAdmin := strings.Contains(args, "NET_ADMIN")
	lifecycle := string(doc.PostCreate) + string(doc.PostStart) + string(doc.PostAttach)
	if netAdmin && strings.Contains(lifecycle, "init-firewall") {
		return DevFirewall
	}
	if doc.Service != "" && len(doc.DockerComposeFile) > 0 {
		var list []string
		if json.Unmarshal(doc.DockerComposeFile, &list) != nil {
			var one string
			if json.Unmarshal(doc.DockerComposeFile, &one) == nil {
				list = []string{one}
			}
		}
		for _, c := range list {
			compose := path.Clean(path.Join(path.Dir(rel), c))
			if b, ok := files[compose]; ok && composeIsolated(b, doc.Service) {
				return DevNoNetwork
			}
		}
	}
	return DevOpen
}

// composeIsolated reports a compose service with no network, or attached only
// to networks marked internal.
func composeIsolated(data []byte, service string) bool {
	var doc struct {
		Services map[string]struct {
			NetworkMode string    `yaml:"network_mode"`
			Networks    yaml.Node `yaml:"networks"`
		} `yaml:"services"`
		Networks map[string]struct {
			Internal bool `yaml:"internal"`
		} `yaml:"networks"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return false
	}
	s, ok := doc.Services[service]
	if !ok {
		return false
	}
	if s.NetworkMode == "none" {
		return true
	}
	var nets []string
	switch s.Networks.Kind {
	case yaml.SequenceNode:
		for _, c := range s.Networks.Content {
			nets = append(nets, c.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(s.Networks.Content); i += 2 {
			nets = append(nets, s.Networks.Content[i].Value)
		}
	}
	if len(nets) == 0 {
		return false // the default network reaches out
	}
	for _, n := range nets {
		if !doc.Networks[n].Internal {
			return false
		}
	}
	return true
}

// Managed values, for Claude Code's managed settings on this machine.
const (
	ManagedNotRead   = "not_read"  // home was not included
	ManagedAbsent    = "absent"    // no managed settings file
	ManagedAllowlist = "allowlist" // sandbox on, only managed domains honoured, a host list with no wildcard
	ManagedPartial   = "partial"   // sandbox on, but users or projects may add domains
	ManagedNone      = "none"      // managed settings with no sandbox
)

// ManagedSettingsPaths are where Claude Code reads managed settings, which a
// user cannot override, from https://code.claude.com/docs/en/settings:
// managed-settings.json, then every *.json in managed-settings.d in
// alphabetical order. Tests replace it.
var ManagedSettingsPaths = func() []string {
	var dir string
	switch runtime.GOOS {
	case "darwin":
		dir = "/Library/Application Support/ClaudeCode"
	case "windows":
		dir = `C:\Program Files\ClaudeCode`
	default:
		dir = "/etc/claude-code"
	}
	out := []string{filepath.Join(dir, "managed-settings.json")}
	if m, err := filepath.Glob(filepath.Join(dir, "managed-settings.d", "*.json")); err == nil {
		sort.Strings(m)
		out = append(out, m...)
	}
	return out
}

// Managed reads Claude Code's managed settings: sandbox.enabled,
// sandbox.network.allowedDomains and sandbox.network.allowManagedDomainsOnly,
// which only managed settings honour. Lists merge across files, and a later
// file's single value wins, as the documentation describes.
func Managed(paths []string) string {
	found := false
	var enabled, managedOnly *bool
	var domains []string
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		found = true
		var doc struct {
			Sandbox struct {
				Enabled *bool `json:"enabled"`
				Network struct {
					AllowedDomains          []string `json:"allowedDomains"`
					AllowManagedDomainsOnly *bool    `json:"allowManagedDomainsOnly"`
				} `json:"network"`
			} `json:"sandbox"`
		}
		if json.Unmarshal(stripComments(b), &doc) != nil {
			continue
		}
		if doc.Sandbox.Enabled != nil {
			enabled = doc.Sandbox.Enabled
		}
		if v := doc.Sandbox.Network.AllowManagedDomainsOnly; v != nil && *v {
			managedOnly = v // true in any admin source turns the lock on
		}
		domains = append(domains, doc.Sandbox.Network.AllowedDomains...)
	}
	switch {
	case !found:
		return ManagedAbsent
	case enabled == nil || !*enabled:
		return ManagedNone
	case managedOnly != nil && *managedOnly && len(domains) > 0 && !wildcard(domains):
		return ManagedAllowlist
	}
	return ManagedPartial
}

func wildcard(domains []string) bool {
	for _, d := range domains {
		if d == "*" || strings.TrimSpace(d) == "" {
			return true
		}
	}
	return false
}

// Boundary works out whether every place an agent is configured to run has a
// boundary outside it. Each CI agent job is one place. Agent configs in the
// repo are another, run on developer machines: bounded by a dev container
// with a firewall or no network, or by managed settings with an allowlist;
// open with an open dev container, or managed settings without one; unknown
// when neither a dev container nor managed settings were read.
func Boundary(jobs []AgentJob, localAgents bool, dev, managed string) string {
	bounded, open, unknown := 0, 0, 0
	for _, j := range jobs {
		if j.Bounded {
			bounded++
		} else {
			open++
		}
	}
	if localAgents {
		switch {
		case dev == DevFirewall || dev == DevNoNetwork || managed == ManagedAllowlist:
			bounded++
		case dev == DevOpen || managed == ManagedNone || managed == ManagedPartial || managed == ManagedAbsent:
			open++
		default:
			unknown++
		}
	}
	switch {
	case open > 0 && bounded > 0:
		return BoundaryPartial
	case open > 0:
		return BoundaryNone
	case bounded > 0 && unknown > 0:
		return BoundaryPartial
	case bounded > 0:
		return BoundaryEnforced
	}
	return BoundaryUnknown
}
