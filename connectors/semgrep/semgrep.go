// Package semgrep reads a results file from semgrep --json. It runs nothing.
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// Connector reads the results file.
type Connector struct{ connector.Base }

// New returns the connector.
func New() *Connector {
	return &Connector{ConnectorName: "semgrep"}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{Name: "results", Nodes: []string{graph.KindSemgrep}, Calls: []string{"read the Semgrep results file"}}}
}

func path(s connector.Scope) string {
	p := s.Project.Config.Semgrep.Results
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(filepath.Dir(s.Project.Dir), p)
}

// Available is true when the file exists.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	p := path(s)
	if p == "" {
		return false, "a Semgrep results file"
	}
	if _, err := os.Stat(p); err != nil {
		return false, "a Semgrep results file at " + s.Project.Config.Semgrep.Results
	}
	return true, ""
}

// Collect reads findings.
func (c *Connector) Collect(_ context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	data, err := os.ReadFile(path(s))
	if err != nil {
		return err
	}
	var doc struct {
		Results *[]struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Start   struct {
				Line int64 `json:"line"`
			} `json:"start"`
			Extra struct {
				Severity string `json:"severity"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("semgrep results: %w", err)
	}
	if doc.Results == nil {
		return fmt.Errorf("semgrep results: no results field, is this semgrep --json output?")
	}
	for _, r := range *doc.Results {
		out.Node(graph.Node{
			ID:   graph.ID(fmt.Sprintf("semgrep:%s/%s:%d", r.CheckID, r.Path, r.Start.Line)),
			Kind: graph.KindSemgrep, Source: "semgrep", SeenAt: s.Now,
			Attrs: map[string]any{"rule": r.CheckID, "severity": r.Extra.Severity, "file": r.Path, "line": r.Start.Line},
		})
	}
	graph.WriteScan(out, "semgrep", "semgrep", "", 1, "", s.Now)
	return nil
}
