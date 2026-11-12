package files

import (
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// cloudKeyName matches a secret or environment variable named as a
// long-lived cloud credential, with any prefix or suffix: PROD_AWS_SECRET_ACCESS_KEY,
// GOOGLE_APPLICATION_CREDENTIALS_JSON, DEPLOY_SERVICE_ACCOUNT_KEY. A session
// token alone is short-lived, so AWS_SESSION_TOKEN is not one.
var cloudKeyName = regexp.MustCompile(`(?:^|_)(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GCP_SA_KEY|GOOGLE_CREDENTIALS|GOOGLE_APPLICATION_CREDENTIALS|SERVICE_ACCOUNT_KEY|AZURE_CLIENT_SECRET|AZURE_CREDENTIALS)(?:_|$)`)

// CloudKeyName reports a secret name that is a long-lived cloud credential.
func CloudKeyName(name string) bool {
	return cloudKeyName.MatchString(strings.ToUpper(name))
}

// cloudScan gathers, across a workflow, the secrets used as cloud keys and
// whether a step trades an OIDC token for cloud credentials.
type cloudScan struct {
	keys      map[string]bool
	idToken   bool // id-token: write is granted somewhere
	federated bool // a step assumes a role, a workload identity provider or an Azure app by OIDC
}

// staticInputs are the inputs of the cloud login actions that take a stored
// key.
var staticInputs = map[string][]string{
	"aws-actions/configure-aws-credentials": {"aws-access-key-id", "aws-secret-access-key"},
	"google-github-actions/auth":            {"credentials_json"},
	"azure/login":                           {"creds"},
}

// step reads one step's uses and with.
func (c *cloudScan) step(uses string, with map[string]string) {
	action, _, _ := strings.Cut(strings.ToLower(uses), "@")
	for _, input := range staticInputs[action] {
		for _, name := range refsIn(with[input]) {
			c.keys[name] = true
		}
	}
	switch action {
	case "aws-actions/configure-aws-credentials":
		if with["role-to-assume"] != "" && with["aws-access-key-id"] == "" {
			c.federated = true
		}
	case "google-github-actions/auth":
		if with["workload_identity_provider"] != "" {
			c.federated = true
		}
	case "azure/login":
		if with["client-id"] != "" && with["tenant-id"] != "" && with["creds"] == "" {
			c.federated = true
		}
	}
}

// env reads an env: block. A secret put in a variable named as a cloud
// credential is a cloud key, whatever the secret is called.
func (c *cloudScan) env(n *yaml.Node) {
	if n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if CloudKeyName(n.Content[i].Value) {
			for _, name := range refsIn(n.Content[i+1].Value) {
				c.keys[name] = true
			}
		}
	}
}

// names returns the cloud key secrets, from usage and from the names of every
// secret the workflow references.
func (c *cloudScan) names(referenced []string) []string {
	for _, s := range referenced {
		if CloudKeyName(s) {
			c.keys[s] = true
		}
	}
	return sortedSet(c.keys)
}

// refsIn lists the secrets named in a value's expressions.
func refsIn(v string) []string {
	if v == "" {
		return nil
	}
	return secretNames([]byte(v))
}

// idTokenWrite reports a permissions block that lets jobs mint an OIDC token.
func idTokenWrite(n *yaml.Node) bool {
	switch n.Kind {
	case yaml.ScalarNode:
		return n.Value == "write-all"
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == "id-token" && n.Content[i+1].Value == "write" {
				return true
			}
		}
	}
	return false
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var (
	// cmdSplit splits a shell line into commands.
	cmdSplit  = regexp.MustCompile(`&&|\|\||[;|&\n()]|\bthen\b|\bdo\b`)
	envAssign = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// UnfrozenInstalls finds JavaScript install commands in a run script that do
// not hold the lockfile fixed, and returns each by its normalised head:
//
//   - npm install, npm i or npm add; npm ci is frozen, and a global tool
//     install (-g, --global, --location=global) touches no lockfile.
//   - pnpm install or pnpm i with --no-frozen-lockfile (or
//     --frozen-lockfile=false). pnpm already refuses to change the lockfile
//     in CI, so a plain pnpm install is frozen there.
//   - yarn install, or a bare yarn, without --immutable or --frozen-lockfile.
//   - bun install or bun i without --frozen-lockfile.
//
// It reads commands as written: a script it calls, or an alias, is not
// followed.
func UnfrozenInstalls(script string) []string {
	if strings.TrimSpace(script) == "" {
		return nil
	}
	script = strings.ReplaceAll(script, "\\\n", " ")
	var out []string
	for _, cmd := range cmdSplit.Split(script, -1) {
		f := strings.Fields(cmd)
		for len(f) > 0 && (envAssign.MatchString(f[0]) || f[0] == "sudo" || f[0] == "env" || f[0] == "time" || f[0] == "exec" || f[0] == "command") {
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		if head := unfrozen(f); head != "" {
			out = append(out, head)
		}
	}
	return out
}

// pmValueFlags take a value before the subcommand, as in npm --prefix web
// install.
var pmValueFlags = map[string]bool{"--prefix": true, "--cwd": true, "-C": true, "--dir": true, "--filter": true, "-F": true, "--workspace": true}

func unfrozen(f []string) string {
	tool := strings.TrimSuffix(f[0], ".cmd")
	var sub string
	var flags []string
	for i := 1; i < len(f); i++ {
		a := f[i]
		switch {
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
			if pmValueFlags[a] && sub == "" {
				i++
			}
		case sub == "":
			sub = a
		}
	}
	has := func(names ...string) bool {
		for _, fl := range flags {
			for _, n := range names {
				if fl == n || strings.HasPrefix(fl, n+"=") && !strings.HasSuffix(fl, "=false") {
					return true
				}
			}
		}
		return false
	}
	switch tool {
	case "npm":
		if (sub == "install" || sub == "i" || sub == "add" || sub == "isntall" || sub == "in") &&
			!has("-g", "--global") && !slicesHas(flags, "--location=global") {
			return "npm install"
		}
	case "pnpm":
		if (sub == "install" || sub == "i") && (slicesHas(flags, "--no-frozen-lockfile") || slicesHas(flags, "--frozen-lockfile=false")) {
			return "pnpm install --no-frozen-lockfile"
		}
	case "yarn":
		if (sub == "" || sub == "install") && !has("--immutable", "--frozen-lockfile") {
			return "yarn install"
		}
	case "bun":
		if (sub == "install" || sub == "i") && !has("--frozen-lockfile") {
			return "bun install"
		}
	}
	return ""
}

func slicesHas(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
