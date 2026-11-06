// Package hrcsv reads a leavers file exported from the HR system.
package hrcsv

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// Connector reads the CSV.
type Connector struct{ connector.Base }

// New returns the connector.
func New() *Connector {
	return &Connector{Base: connector.Base{ConnectorName: "hr"}}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{Name: "leavers", Nodes: []string{graph.KindLeaver}, Calls: []string{"read the HR leavers CSV"}}}
}

// path resolves the configured file against the repo root, the parent of .firedrill.
func path(s connector.Scope) string {
	p := s.Project.Config.HR.LeaversCSV
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(filepath.Dir(s.Project.Dir), p)
}

// Available is true when the file exists. A configured file that is missing
// gives SKIP, the same as an unconnected system.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	p := path(s)
	if p == "" {
		return false, "an HR leavers CSV"
	}
	if _, err := os.Stat(p); err != nil {
		return false, "an HR leavers CSV at " + s.Project.Config.HR.LeaversCSV
	}
	return true, ""
}

// Collect reads leavers.
func (c *Connector) Collect(_ context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	f, err := os.Open(path(s))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	r := csv.NewReader(f)
	header, err := r.Read()
	if err != nil {
		return fmt.Errorf("leavers CSV: %w", err)
	}
	emailCol, dateCol := -1, -1
	for i, h := range header {
		switch strings.ToLower(strings.TrimSpace(h)) {
		case "email":
			emailCol = i
		case "leave_date":
			dateCol = i
		}
	}
	if emailCol < 0 || dateCol < 0 {
		return fmt.Errorf("leavers CSV needs the columns email,leave_date")
	}
	for line := 2; ; line++ {
		row, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("leavers CSV line %d: %w", line, err)
		}
		email, date := strings.TrimSpace(row[emailCol]), strings.TrimSpace(row[dateCol])
		if _, err := time.Parse("2006-01-02", date); err != nil {
			return fmt.Errorf("leavers CSV line %d: leave_date must be YYYY-MM-DD", line)
		}
		out.Node(graph.Node{ID: graph.ID("person:" + s.Hasher.Email(email)), Kind: graph.KindLeaver, Source: "hr", SeenAt: s.Now,
			Attrs: map[string]any{"leave_date": date}, Private: map[string]any{"email": email}})
	}
}
