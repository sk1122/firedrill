package facts

// identity is each fact's identity fields (see Def.Identity). A fact missing
// here needs none, such as a GitHub repo fact, whose target names the repo.
// email and login are never identity: a person is named by their hashed id.
var identity = map[string][]string{
	"files.secrets":       {"found.file", "found.line", "found.kind", "found.hash"},
	"files.agent_configs": {"found.file", "found.tool", "found.mcp_servers.name"},
	"files.workflows":     {"found.file"},
	"files.manifests":     {"found.file"},
	"files.terraform":     {"found.file", "found.name"},
	"semgrep.results":     {"found.file", "found.line", "found.rule"},

	"config.hosts":       {"host"},
	"ctlog.hosts":        {"found.host"},
	"dns.cnames":         {"found.host"},
	"web.source_maps":    {"found.host", "found.bundle"},
	"web.public_secrets": {"found.host", "found.path", "found.kind", "found.hash"},
	"web.page_scripts":   {"found.host", "found.page", "found.script_host"},
	"web.api_docs":       {"found.host", "found.path"},

	// A binding's member is left out: it can be an address.
	"gcp.projects":     {"name"},
	"gcp.iam_bindings": {"role", "member_type", "member_domain"},
	"gcp.buckets":      {"name"},
	"gcp.sa_keys":      {"key_id"},

	"recovery.databases": {"found.system", "found.project", "found.account", "found.name"},
	"gcp.backups":        {"found.system", "found.project", "found.account", "found.name"},
	"aws.backups":        {"found.system", "found.project", "found.account", "found.name"},

	"keys.ai":        {"found.provider", "found.key_id"},
	"anthropic.keys": {"found.provider", "found.key_id"},
	"openai.keys":    {"found.provider", "found.key_id"},

	"identity.oauth_apps": {"client_id", "name"},

	"hr.leavers":           {"id"},
	"people.accounts":      {"found.id"},
	"people.powers":        {"found.id"},
	"people.unlinked":      {"found.system", "found.kind", "found.id"},
	"people.admins":        {"found.system", "found.kind", "found.id", "found.role", "found.project"},
	"github.people":        {"id"},
	"github.bypass_actors": {"people.id", "apps.id", "apps.kind"},
}

// applyIdentity sets each registered fact's identity fields.
func applyIdentity() {
	for name, paths := range identity {
		d, ok := registry[name]
		if !ok {
			panic("facts: identity for unknown fact " + name)
		}
		d.Identity = paths
		registry[name] = d
	}
}
