package files

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"gopkg.in/yaml.v3"
)

// DestructiveCommands is the approved list. Config can add to it.
var DestructiveCommands = []string{
	"rm -rf", "git push --force", "git push -f", "git reset --hard", "git clean -f",
	"DROP TABLE", "DROP DATABASE", "TRUNCATE", "terraform destroy", "kubectl delete",
	"helm uninstall", "aws * delete-*", "aws s3 rm",
}

// AgentConfig is one parsed agent settings file.
type AgentConfig struct {
	Tool        string
	Scope       string
	File        string
	Allowed     []string
	Denied      []string
	DenyRead    []string
	DefaultMode string
	Servers     []MCPServer
}

// MCPServer is one MCP server and the raw values passed to it. Values are held
// in memory only, to be hashed; the other fields are safe to store.
type MCPServer struct {
	Name      string
	Values    []string
	Transport string // http for a server defined by a URL, stdio for a command
	Host      string // the URL's hostname alone, for http
	Command   string // the executable's base name, for stdio
	Package   string // the package or image the command fetches, if any
	Version   string // its exact version or digest, if given
	Pinned    bool   // no package, or an exact version or digest
}

// ParseAgentFile reads one agent config by its path.
func ParseAgentFile(rel string, data []byte, scope string) (*AgentConfig, error) {
	base := path.Base(rel)
	switch base {
	case ".cursorignore":
		c := &AgentConfig{Tool: "cursor", Scope: scope, File: rel}
		for line := range strings.SplitSeq(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				c.DenyRead = append(c.DenyRead, line)
			}
		}
		return c, nil
	case "settings.json", "settings.local.json":
		if strings.HasPrefix(rel, ".gemini/") {
			// Gemini CLI settings name MCP servers the way .mcp.json does, and
			// may hold comments.
			return parseMCP(rel, stripComments(data), scope, "gemini")
		}
		return parseClaudeSettings(rel, data, scope)
	case "mcp.json", ".mcp.json":
		tool := "claude-code"
		if strings.Contains(rel, ".cursor/") {
			tool = "cursor"
		} else if strings.Contains(rel, ".vscode/") {
			tool = "vscode"
		}
		return parseMCP(rel, data, scope, tool)
	}
	return nil, fmt.Errorf("%s is not an agent config", rel)
}

func parseClaudeSettings(rel string, data []byte, scope string) (*AgentConfig, error) {
	var doc struct {
		Permissions struct {
			Allow       []string `json:"allow"`
			Deny        []string `json:"deny"`
			DefaultMode string   `json:"defaultMode"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	c := &AgentConfig{Tool: "claude-code", Scope: scope, File: rel, DefaultMode: doc.Permissions.DefaultMode}
	for _, a := range doc.Permissions.Allow {
		if tool, arg := splitRule(a); tool == "Bash" || tool == "*" {
			c.Allowed = append(c.Allowed, arg)
		}
	}
	for _, d := range doc.Permissions.Deny {
		tool, arg := splitRule(d)
		switch tool {
		case "Bash":
			c.Denied = append(c.Denied, arg)
		case "Read":
			c.DenyRead = append(c.DenyRead, strings.TrimPrefix(arg, "./"))
		}
	}
	return c, nil
}

var ruleRe = regexp.MustCompile(`^([A-Za-z*]+)(?:\((.*)\))?$`)

// splitRule splits "Bash(git push:*)" into its tool and command. A bare tool
// name means every command.
func splitRule(r string) (tool, arg string) {
	m := ruleRe.FindStringSubmatch(strings.TrimSpace(r))
	if m == nil {
		return "", ""
	}
	arg = m[2]
	if arg == "" {
		arg = "*"
	}
	return m[1], arg
}

func parseMCP(rel string, data []byte, scope, tool string) (*AgentConfig, error) {
	var doc struct {
		MCPServers map[string]mcpEntry `json:"mcpServers"`
		Servers    map[string]mcpEntry `json:"servers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	c := &AgentConfig{Tool: tool, Scope: scope, File: rel}
	all := doc.MCPServers
	if len(all) == 0 {
		all = doc.Servers
	}
	names := make([]string, 0, len(all))
	for n := range all {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		e := all[n]
		s := MCPServer{Name: n}
		for _, m := range []map[string]string{e.Env, e.Headers} {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				s.Values = append(s.Values, m[k])
			}
		}
		s.Values = append(s.Values, e.Args...)
		describe(&s, e)
		c.Servers = append(c.Servers, s)
	}
	return c, nil
}

// stripComments blanks // and /* */ comments outside JSON strings, keeping
// line numbers.
func stripComments(data []byte) []byte {
	out := append([]byte(nil), data...)
	inStr := false
	for i := 0; i < len(out); i++ {
		c := out[i]
		switch {
		case inStr && c == '\\':
			i++
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '/' && i+1 < len(out) && out[i+1] == '/':
			for ; i < len(out) && out[i] != '\n'; i++ {
				out[i] = ' '
			}
		case c == '/' && i+1 < len(out) && out[i+1] == '*':
			out[i], out[i+1] = ' ', ' '
			for i += 2; i < len(out); i++ {
				if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
					out[i], out[i+1] = ' ', ' '
					i++
					break
				}
				if out[i] != '\n' {
					out[i] = ' '
				}
			}
		}
	}
	return out
}

type mcpEntry struct {
	Env       map[string]string `json:"env"`
	Headers   map[string]string `json:"headers"`
	Args      []string          `json:"args"`
	Command   string            `json:"command"`
	URL       string            `json:"url"`
	HTTPURL   string            `json:"httpUrl"`
	ServerURL string            `json:"serverUrl"`
}

var varRef = regexp.MustCompile(`\$\{(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}|^\$([A-Za-z_][A-Za-z0-9_]*)$`)

// VarRefs returns the environment variable names referenced in a value.
func VarRefs(v string) []string {
	var out []string
	for _, m := range varRef.FindAllStringSubmatch(v, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else if m[2] != "" {
			out = append(out, m[2])
		}
	}
	return out
}

// Unguarded returns the destructive commands an agent may run without approval.
func Unguarded(c *AgentConfig, destructive []string) []string {
	out := []string{}
	if c.DefaultMode == "bypassPermissions" {
		out = append(out, "defaultMode: bypassPermissions")
	}
	for _, d := range destructive {
		if commandCovered(c.Denied, d) {
			continue
		}
		if c.DefaultMode == "bypassPermissions" || commandCovered(c.Allowed, d) {
			out = append(out, d)
		}
	}
	return out
}

// commandCovered says whether any rule covers a destructive command: a wildcard,
// a rule whose prefix the command starts with, or a rule naming it.
func commandCovered(rules []string, destructive string) bool {
	d := strings.ToLower(destructive)
	for _, r := range rules {
		rule := strings.ToLower(strings.TrimSpace(r))
		rule = strings.TrimSuffix(strings.TrimSuffix(rule, ":*"), "*")
		rule = strings.TrimSpace(rule)
		if rule == "" {
			return true
		}
		if strings.HasPrefix(d, rule) || strings.Contains(rule, d) {
			return true
		}
		if strings.Contains(d, "*") {
			pat := "^" + strings.ReplaceAll(regexp.QuoteMeta(d), `\*`, `.*`)
			if re, err := regexp.Compile(pat); err == nil && re.MatchString(rule) {
				return true
			}
		}
	}
	return false
}

// DenyMatch says whether a read rule covers a file.
func DenyMatch(patterns []string, rel string) bool {
	rules := []ignoreRule{}
	for _, p := range patterns {
		if r, ok := compileIgnore("", p); ok {
			rules = append(rules, r)
		}
		if r, ok := compileIgnore("", strings.TrimSuffix(strings.TrimSuffix(p, "**"), "/")+"/**"); ok {
			rules = append(rules, r)
		}
	}
	return ignored(rules, rel, false)
}

// Workflow is what Firedrill takes from one workflow file.
type Workflow struct {
	File        string
	Permissions string // read, write or undeclared
	Unpinned    []string
	PRTarget    bool
	Triggers    []string // every event under on:, sorted
	Secrets     []string // names of the secrets it references, never values
	// Unfrozen lists install commands in run steps that may change the
	// lockfile, by their normalised head such as "npm install".
	Unfrozen []string
	// CloudKeys names the secrets that hold a long-lived cloud credential.
	CloudKeys []string
	// OIDC is set when the workflow may mint an OIDC token and a step trades it
	// for cloud credentials.
	OIDC bool
}

var fullSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ParseWorkflow reads one workflow file.
func ParseWorkflow(rel string, data []byte) (*Workflow, error) {
	var doc struct {
		On          yaml.Node `yaml:"on"`
		Permissions yaml.Node `yaml:"permissions"`
		Env         yaml.Node `yaml:"env"`
		Jobs        map[string]struct {
			Permissions yaml.Node `yaml:"permissions"`
			Env         yaml.Node `yaml:"env"`
			Steps       []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
				Run  string            `yaml:"run"`
				Env  yaml.Node         `yaml:"env"`
			} `yaml:"steps"`
			Uses    string    `yaml:"uses"`
			Secrets yaml.Node `yaml:"secrets"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", rel, err)
	}
	w := &Workflow{File: rel, Triggers: triggers(&doc.On), Secrets: secretNames(data)}
	prTarget := triggerHas(&doc.On, "pull_request_target")
	allDeclared := len(doc.Jobs) > 0
	seen := map[string]bool{}
	cloud := cloudScan{keys: map[string]bool{}, idToken: idTokenWrite(&doc.Permissions)}
	cloud.env(&doc.Env)
	unfrozen := map[string]bool{}
	for _, job := range doc.Jobs {
		cloud.idToken = cloud.idToken || idTokenWrite(&job.Permissions)
		cloud.env(&job.Env)
		for _, st := range job.Steps {
			cloud.env(&st.Env)
			cloud.step(st.Uses, st.With)
			for _, c := range UnfrozenInstalls(st.Run) {
				unfrozen[c] = true
			}
		}
		switch permLevel(&job.Permissions) {
		case "undeclared":
			allDeclared = false
		}
		if job.Secrets.Kind == yaml.ScalarNode && job.Secrets.Value == "inherit" && !slices.Contains(w.Secrets, "inherit") {
			// A reusable workflow called this way gets every secret.
			w.Secrets = append(w.Secrets, "inherit")
		}
		uses := []string{job.Uses}
		for _, st := range job.Steps {
			uses = append(uses, st.Uses)
			if prTarget && strings.HasPrefix(st.Uses, "actions/checkout") {
				ref := st.With["ref"]
				if strings.Contains(ref, "github.event.pull_request") || strings.Contains(ref, "github.head_ref") {
					w.PRTarget = true
				}
			}
		}
		for _, u := range uses {
			if unpinned(u) && !seen[u] {
				seen[u] = true
				w.Unpinned = append(w.Unpinned, u)
			}
		}
	}
	sort.Strings(w.Unpinned)
	sort.Strings(w.Secrets)
	w.Unfrozen = sortedSet(unfrozen)
	w.CloudKeys = cloud.names(w.Secrets)
	w.OIDC = cloud.idToken && cloud.federated
	switch top := permLevel(&doc.Permissions); {
	case top == "read":
		w.Permissions = "read"
	case top == "write":
		w.Permissions = "write"
	case allDeclared:
		// Every job declares its own, so the default token is never used.
		w.Permissions = "read"
	default:
		w.Permissions = "undeclared"
	}
	return w, nil
}

func unpinned(uses string) bool {
	if uses == "" || strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return false
	}
	if strings.HasPrefix(uses, "actions/") || strings.HasPrefix(uses, "github/") {
		return false
	}
	_, ref, ok := strings.Cut(uses, "@")
	return !ok || !fullSHA.MatchString(ref)
}

func permLevel(n *yaml.Node) string {
	switch n.Kind {
	case 0:
		return "undeclared"
	case yaml.ScalarNode:
		switch n.Value {
		case "read-all":
			return "read"
		case "write-all":
			return "write"
		}
		return "undeclared"
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			if n.Content[i].Value == "write" {
				return "write"
			}
		}
		return "read"
	}
	return "undeclared"
}

// triggers lists the events under on:, in any of its three forms.
func triggers(n *yaml.Node) []string {
	var out []string
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value != "" {
			out = append(out, n.Value)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			out = append(out, c.Value)
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			out = append(out, n.Content[i].Value)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// expr finds ${{ }} expressions, and secretRef finds secrets.NAME and
// secrets['NAME'] inside one.
var (
	expr      = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)
	secretRef = regexp.MustCompile(`(?:^|[^.\w])secrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_]*)|\[\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*\])`)
)

// secretNames lists the secrets a workflow's expressions name, upper-cased
// since GitHub treats names that way. GITHUB_TOKEN is left out: the permissions
// block says what it can do.
func secretNames(data []byte) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, e := range expr.FindAllStringSubmatch(string(data), -1) {
		for _, m := range secretRef.FindAllStringSubmatch(e[1], -1) {
			name := strings.ToUpper(m[1] + m[2])
			if name == "GITHUB_TOKEN" || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func triggerHas(n *yaml.Node, name string) bool {
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value == name
	case yaml.SequenceNode:
		for _, c := range n.Content {
			if c.Value == name {
				return true
			}
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			if n.Content[i].Value == name {
				return true
			}
		}
	}
	return false
}

// Bucket is one S3 bucket defined in Terraform.
type Bucket struct {
	Name, File                        string
	PublicACL, PublicPolicy, HasBlock bool
}

var publicACLs = map[string]bool{"public-read": true, "public-read-write": true, "website": true}

// ParseTerraform reads the S3 buckets in one or more .tf files, keyed by the
// Terraform resource name, since ACLs and policies are often separate resources.
func ParseTerraform(files []File) ([]*Bucket, error) {
	buckets := map[string]*Bucket{}
	get := func(name, file string) *Bucket {
		if buckets[name] == nil {
			buckets[name] = &Bucket{Name: name, File: file}
		}
		return buckets[name]
	}
	for _, f := range files {
		parsed, diags := hclsyntax.ParseConfig(f.Data, f.Path, hcl.InitialPos)
		if diags.HasErrors() {
			continue // a template or partial file is not a reason to stop a run
		}
		body, ok := parsed.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, b := range body.Blocks {
			if b.Type != "resource" || len(b.Labels) != 2 {
				continue
			}
			kind, name := b.Labels[0], b.Labels[1]
			text := func(attr string) string {
				a, ok := b.Body.Attributes[attr]
				if !ok {
					return ""
				}
				return string(a.Expr.Range().SliceBytes(f.Data))
			}
			switch kind {
			case "aws_s3_bucket":
				bk := get(name, f.Path)
				bk.File = f.Path
				if publicACLs[strings.Trim(text("acl"), `"`)] {
					bk.PublicACL = true
				}
				if policyIsPublic(text("policy")) {
					bk.PublicPolicy = true
				}
			case "aws_s3_bucket_acl":
				if ref := bucketRef(text("bucket")); ref != "" && publicACLs[strings.Trim(text("acl"), `"`)] {
					get(ref, f.Path).PublicACL = true
				}
			case "aws_s3_bucket_policy":
				if ref := bucketRef(text("bucket")); ref != "" && policyIsPublic(text("policy")) {
					get(ref, f.Path).PublicPolicy = true
				}
			case "aws_s3_bucket_public_access_block":
				if ref := bucketRef(text("bucket")); ref != "" {
					get(ref, f.Path).HasBlock = true
				}
			}
		}
	}
	out := make([]*Bucket, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

var refRe = regexp.MustCompile(`aws_s3_bucket\.([A-Za-z0-9_-]+)`)

func bucketRef(expr string) string {
	if m := refRe.FindStringSubmatch(expr); m != nil {
		return m[1]
	}
	return ""
}

var publicPrincipal = regexp.MustCompile(`(?i)principal\S*\s*["'\s:=]*\s*["']?\*["']?`)

func policyIsPublic(text string) bool {
	return publicPrincipal.MatchString(strings.ReplaceAll(text, `\"`, `"`))
}

// ParseCodeowners returns rules in file order.
func ParseCodeowners(data []byte) []any {
	rules := []any{}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		owners := []any{}
		for _, o := range fields[1:] {
			if strings.HasPrefix(o, "#") {
				break
			}
			owners = append(owners, o)
		}
		rules = append(rules, map[string]any{"pattern": fields[0], "owners": owners})
	}
	return rules
}
