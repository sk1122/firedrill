// Package configsrc writes what the config files name: targets, domains and
// host owners.
package configsrc

import (
	"context"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// Connector reads .firedrill files.
type Connector struct{ connector.Base }

// New returns the connector.
func New() *Connector {
	return &Connector{ConnectorName: "config"}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{Name: "config", Nodes: []string{graph.KindTargetRepo, graph.KindConfigDomain, graph.KindConfigHost,
		graph.KindConfigSettings, graph.KindConfigApp, graph.KindConfigBackup, graph.KindConfigAIKey}}}
}

// Available is always true.
func (c *Connector) Available(connector.Scope) (bool, string) { return true, "" }

// Collect writes the config nodes.
func (c *Connector) Collect(_ context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	for _, t := range connector.RepoTargets(s) {
		out.Node(graph.Node{ID: graph.ID("repo:" + t.Name), Kind: graph.KindTargetRepo, Source: "config", SeenAt: s.Now,
			Attrs: map[string]any{"name": t.Name, "local": t.Path != ""}})
	}
	verified := map[string]bool{}
	for _, d := range s.VerifiedDomains {
		verified[d] = true
	}
	for _, d := range s.Project.Config.Domains {
		out.Node(graph.Node{ID: graph.ID("domain:" + d), Kind: graph.KindConfigDomain, Source: "config", SeenAt: s.Now,
			Attrs: map[string]any{"domain": d, "verified": verified[d]}})
	}
	for _, h := range s.Project.Hosts {
		out.Node(graph.Node{ID: graph.ID("config-host:" + h.Host), Kind: graph.KindConfigHost, Source: "config", SeenAt: s.Now,
			Attrs: map[string]any{"host": h.Host, "owner": h.Owner}})
		out.Edge(graph.Edge{From: graph.ID("config-host:" + h.Host), To: graph.ID("host:" + h.Host), Kind: graph.EdgeOwns, Source: "config"})
	}
	writeRegisters(s, out)
	return nil
}

// SettingsID is the node holding the thresholds facts read, so no number lives
// in a drill.
const SettingsID = graph.ID("config:settings")

// writeRegisters writes the thresholds and the registers a team keeps: owners
// and reviews of third-party apps, copies of databases, and owners and limits
// of AI keys.
func writeRegisters(s connector.Scope, out graph.Writer) {
	cfg := s.Project.Config
	out.Node(graph.Node{ID: SettingsID, Kind: graph.KindConfigSettings, Source: "config", SeenAt: s.Now,
		Attrs: map[string]any{
			"review_days": int64(cfg.AppReviewDays()), "min_retention_days": int64(cfg.MinRetentionDays()),
			"production_markers": int64(len(cfg.Production)),
		}})
	for _, a := range s.Project.Apps {
		out.Node(graph.Node{ID: graph.ID("config-app:" + a.ClientID), Kind: graph.KindConfigApp, Source: "config", SeenAt: s.Now,
			Attrs: map[string]any{"client_id": a.ClientID, "name": a.Name, "owner": a.Owner, "reviewed": a.Reviewed, "note": a.Note}})
	}
	for _, b := range s.Project.Backups {
		out.Node(graph.Node{ID: graph.ID("config-backup:" + b.Database), Kind: graph.KindConfigBackup, Source: "config", SeenAt: s.Now,
			Attrs: map[string]any{"database": b.Database, "copy_location": b.CopyLocation, "owner": b.Owner, "verified": b.Verified}})
	}
	for _, k := range s.Project.AIKeys {
		ref := k.KeyID
		switch {
		case ref != "":
			ref = "key/" + ref
		case k.Workspace != "":
			ref = "workspace/" + k.Workspace
		default:
			ref = "project/" + k.Project
		}
		limit := -1.0
		if k.MonthlyLimitUSD != nil {
			limit = *k.MonthlyLimitUSD
		}
		out.Node(graph.Node{ID: graph.ID("config-ai-key:" + k.Provider + "/" + ref), Kind: graph.KindConfigAIKey, Source: "config", SeenAt: s.Now,
			Attrs: map[string]any{"provider": k.Provider, "key_id": k.KeyID, "workspace": k.Workspace, "project": k.Project,
				"owner": k.Owner, "monthly_limit_usd": limit, "verified": k.Verified}})
	}
}
