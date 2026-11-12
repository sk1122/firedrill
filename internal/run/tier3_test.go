package run

import (
	"time"

	"github.com/sk1122/firedrill/internal/graph"
	"github.com/sk1122/firedrill/internal/tag"
)

// The Tier 3 drills: what the web connector reads from owned pages, agent
// egress from repo files, and restores from Cloud SQL and restores.yaml.

// liveKeyID is a made-up Google Cloud service account key ID.
const liveKeyID = "0123456789abcdef0123456789abcdef01234567"

// publicSecret is a credential the web connector found in a public body, by
// fingerprint, kind and key ID.
func publicSecret(g *graph.Graph, path, kind, keyID string, clientSide bool) {
	hash := "5a1f0c3e9b7d2a4c6e8f0b1d3a5c7e9f"
	node(g, "public-secret:www.acme.com"+path+"#"+hash, graph.KindPublicSecret, map[string]any{"domain": "acme.com",
		"host": "www.acme.com", "path": path, "kind": kind, "hash": hash, "key_id": keyID, "client_side": clientSide})
}

// saKey is a Google Cloud service account key as the gcp connector writes it.
func saKey(g *graph.Graph, id string, disabled bool) {
	node(g, "gcp:key/acme-prod/"+id, graph.KindGCPKey, map[string]any{
		"project": "acme-prod", "service_account": "web@acme-prod.iam.gserviceaccount.com", "key_id": id,
		"created": "2026-01-10T00:00:00Z", "last_used": "", "last_use_known": false, "disabled": disabled})
}

// pageScript is a script the home page of www.acme.com loads from another host.
func pageScript(g *graph.Graph, scriptHost, path string, integrity, owned bool) {
	hash := "7c2e4a6b8d0f1a3c5e7b9d1f3a5c7e9b"
	if owned {
		hash = "1b3d5f7a9c2e4a6c8e0b2d4f6a8c0e2d"
	}
	node(g, "page-script:www.acme.com/@"+hash, graph.KindPageScript, map[string]any{"domain": "acme.com", "host": "www.acme.com",
		"page": "/", "script_host": scriptHost, "script_path": path, "script_hash": hash, "has_integrity": integrity,
		"crossorigin": integrity, "owned": owned})
}

// claudeSettings is a committed .claude/settings.json with its judged egress.
func claudeSettings(g *graph.Graph, egress string, hosts []any, unbounded bool) {
	node(g, "agent:acme/api/.claude/settings.json", graph.KindAgentConfig, map[string]any{"repo": "acme/api", "tool": "claude-code",
		"scope": "repo", "file": ".claude/settings.json", "allowed_commands": []any{}, "denied_commands": []any{}, "deny_read_paths": []any{},
		"unguarded_destructive": []any{}, "mcp_servers": []any{}, "gitignored": false, "local_override": false,
		"egress": egress, "egress_hosts": hosts, "egress_unbounded": unbounded})
}

// cloudSQL is a production Cloud SQL instance with what its operations showed:
// the time of the latest restore that counts for it, and whether every
// instance's operations in the project were read.
func cloudSQL(g *graph.Graph, name string, production bool, lastRestore time.Time, readable bool) {
	at, scope, detail := "", "", ""
	if !lastRestore.IsZero() {
		at, scope = lastRestore.UTC().Format(time.RFC3339), "instance"
		detail = "a clone of " + name + " finished " + at[:10] + "; a clone shows its data can be brought up elsewhere"
	}
	if !readable {
		detail = "operations could not be read for " + name + " (403)"
	}
	node(g, "gcp:db/acme-prod/"+name, graph.KindDatabase, map[string]any{"system": "gcp", "account": "", "project": "acme-prod",
		"profile": "", "region": "europe-west1", "name": name, "engine": "POSTGRES_16", "db_kind": "instance",
		"production": production, "production_marked": production, "automated_backups": true, "retention_days": int64(14),
		"deletion_protection": true, "separate_copy": "unknown", "copy_detail": "",
		"last_restore": at, "restore_scope": scope, "restore_detail": detail, "restores_readable": readable})
}

func tier3Cases() []drillCase {
	daysAgo := func(n int) time.Time { return testNow.AddDate(0, 0, -n) }
	return []drillCase{
		// Manchester Airports: a key that was live in the cloud sat in page
		// JavaScript.
		{"doors/no-live-key-in-public-bundle", tag.Fail, "service account key in a bundle matches a live GCP key", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_public_secrets", "acme.com", 4)
			saKey(g, liveKeyID, false)
			publicSecret(g, "/assets/app.js", "gcp_sa_key", liveKeyID, false)
		}},
		{"doors/no-live-key-in-public-bundle", tag.Fail, "server-side secret, GCP not connected", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_public_secrets", "acme.com", 4)
			publicSecret(g, "/assets/app.js.map", "stripe_live", "", false)
		}},
		{"doors/no-live-key-in-public-bundle", tag.Warn, "browser API key", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_public_secrets", "acme.com", 4)
			publicSecret(g, "/assets/maps.js", "google_api_key", "", true)
		}},
		{"doors/no-live-key-in-public-bundle", tag.Pass, "nothing found", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_public_secrets", "acme.com", 4)
		}},
		{"doors/no-live-key-in-public-bundle", tag.Pass, "client-side key known disabled", func(g *graph.Graph) {
			// No browser key kind carries a key ID today, so this guards the
			// rule rather than a shape the scanner writes.
			domain(g)
			scan(g, "web_public_secrets", "acme.com", 4)
			saKey(g, liveKeyID, true)
			publicSecret(g, "/assets/app.js", "generic", liveKeyID, true)
		}},
		{"doors/no-live-key-in-public-bundle", tag.NA, "no bundle inspected", func(g *graph.Graph) { domain(g) }},

		// Adform: one third-party CDN script was swapped, and every site
		// loading it ran the new code.
		{"doors/third-party-scripts-pinned", tag.Fail, "CDN script with no integrity hash", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_page_scripts", "acme.com", 2)
			pageScript(g, "cdn.adtech.example", "/tag/v3/loader.js", false, false)
		}},
		{"doors/third-party-scripts-pinned", tag.Pass, "integrity hash present", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_page_scripts", "acme.com", 2)
			pageScript(g, "cdn.jsdelivr.net", "/npm/acme-widgets@2.1.0/dist/widgets.min.js", true, false)
		}},
		{"doors/third-party-scripts-pinned", tag.Pass, "owned CDN host", func(g *graph.Graph) {
			domain(g)
			scan(g, "web_page_scripts", "acme.com", 2)
			pageScript(g, "static.acme.com", "/js/app.js", false, true)
		}},
		{"doors/third-party-scripts-pinned", tag.NA, "no page read", func(g *graph.Graph) { domain(g) }},

		// UK AISI: agents acted on the live internet outside their scope, and
		// nothing outside the agent stopped them.
		{"agent/egress-allowlisted", tag.Fail, "no restriction", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			claudeSettings(g, "open", []any{}, false)
		}},
		{"agent/egress-allowlisted", tag.Fail, "wildcard allowlist", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			claudeSettings(g, "allowlist", []any{"*"}, true)
		}},
		{"agent/egress-allowlisted", tag.Warn, "web tools restricted only", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			claudeSettings(g, "partial", []any{}, false)
		}},
		{"agent/egress-allowlisted", tag.Pass, "sandbox allowlist", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			claudeSettings(g, "allowlist", []any{"*.npmjs.org", "github.com"}, false)
		}},
		{"agent/egress-allowlisted", tag.NA, "no agent config", func(g *graph.Graph) {
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 0)
		}},
		{"agent/egress-allowlisted", tag.NA, "only a .cursorignore", func(g *graph.Graph) {
			// It only lists what Cursor may not read: it opens and limits nothing.
			targetRepo(g)
			scan(g, "agent_configs", "acme/api", 1)
			scan(g, "egress_boundary", "acme/api", 0)
			node(g, "agent:acme/api/.cursorignore", graph.KindAgentConfig, map[string]any{"repo": "acme/api", "tool": "cursor",
				"scope": "repo", "file": ".cursorignore", "allowed_commands": []any{}, "denied_commands": []any{}, "deny_read_paths": []any{".env"},
				"unguarded_destructive": []any{}, "mcp_servers": []any{}, "gitignored": false, "local_override": false,
				"egress": "none", "egress_hosts": []any{}, "egress_unbounded": false})
			node(g, "egress-boundary:acme/api", graph.KindEgressBoundary, map[string]any{"repo": "acme/api", "ci_agent_jobs": []any{},
				"ci_agent_jobs_bounded": []any{}, "ci_agent_jobs_exposed": []any{}, "devcontainer": "none", "managed": "not_read",
				"agents_configured": false, "boundary": "unknown"})
		}},

		// The recurring audit finding: backups nobody has ever restored.
		{"recovery/restore-exercised", tag.Pass, "API restore 20 days ago", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			cloudSQL(g, "orders", true, daysAgo(20), true)
		}},
		{"recovery/restore-exercised", tag.Pass, "declared restore", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			cloudSQL(g, "orders", true, time.Time{}, true)
			node(g, "config-restore:orders", graph.KindConfigRestore, map[string]any{"database": "orders",
				"restored": "2026-09-30", "by": "platform-team", "note": "restored into a scratch instance; row counts checked"})
		}},
		{"recovery/restore-exercised", tag.Fail, "last restore older than the window", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			cloudSQL(g, "orders", true, daysAgo(200), true)
		}},
		{"recovery/restore-exercised", tag.Fail, "never restored, operations readable", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			cloudSQL(g, "orders", true, time.Time{}, true)
		}},
		{"recovery/restore-exercised", tag.Warn, "operations unreadable", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			cloudSQL(g, "orders", true, time.Time{}, false)
		}},
		{"recovery/restore-exercised", tag.NA, "no production database", func(g *graph.Graph) {
			settings(g, 1)
			scan(g, "gcp_backups", "acme-prod", 1)
			cloudSQL(g, "scratch", false, time.Time{}, true)
		}},
	}
}
