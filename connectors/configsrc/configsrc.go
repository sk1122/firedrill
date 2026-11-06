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
	return &Connector{Base: connector.Base{ConnectorName: "config"}}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{Name: "config", Nodes: []string{graph.KindTargetRepo, graph.KindConfigDomain, graph.KindConfigHost}}}
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
	return nil
}
