package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// BackupScanner names the scan record of one project's databases.
const BackupScanner = "gcp_backups"

type sqlInstance struct {
	Name               string   `json:"name"`
	Region             string   `json:"region"`
	DatabaseVersion    string   `json:"databaseVersion"`
	InstanceType       string   `json:"instanceType"`
	MasterInstanceName string   `json:"masterInstanceName"`
	ReplicaNames       []string `json:"replicaNames"`
	Settings           struct {
		UserLabels                map[string]string `json:"userLabels"`
		DeletionProtectionEnabled bool              `json:"deletionProtectionEnabled"`
		RetainBackupsOnDelete     bool              `json:"retainBackupsOnDelete"`
		BackupConfiguration       struct {
			Enabled                    bool   `json:"enabled"`
			Location                   string `json:"location"`
			PointInTimeRecoveryEnabled bool   `json:"pointInTimeRecoveryEnabled"`
			BackupTier                 string `json:"backupTier"`
			BackupRetentionSettings    *struct {
				RetentionUnit   string `json:"retentionUnit"`
				RetainedBackups *int64 `json:"retainedBackups"`
			} `json:"backupRetentionSettings"`
		} `json:"backupConfiguration"`
		FinalBackupConfig *struct {
			Enabled       bool  `json:"enabled"`
			RetentionDays int64 `json:"retentionDays"`
		} `json:"finalBackupConfig"`
	} `json:"settings"`
}

// collectCloudSQL reads every listed project's Cloud SQL instances. A project
// that cannot be read, or an API that is not turned on, is recorded on its scan
// record, so only the backup drills give ERROR and the other GCP drills run.
func (c *Connector) collectCloudSQL(ctx context.Context, a *api, s connector.Scope, out graph.Writer) error {
	for _, project := range s.Project.Config.GCP.Projects {
		insts, err := listInstances(ctx, a, project)
		attrs := map[string]any{"scanner": BackupScanner, "scope": project, "inspected": int64(0)}
		var ae *apiError
		switch {
		case errors.Is(err, connector.ErrBlocked):
			return err
		case err != nil && errors.As(err, &ae) && (ae.Reason == "SERVICE_DISABLED" || ae.Reason == "accessNotConfigured"):
			// Calls are billed to the reader's own project, so this is that
			// project's setup, not the drilled one's.
			msg := "could not read Cloud SQL in " + project + ": the Cloud SQL Admin API (sqladmin.googleapis.com) is not turned on in the project Firedrill's calls are billed to; turn it on there"
			attrs["error"], attrs["partial"] = msg, msg
		case err != nil:
			msg := fmt.Sprintf("could not read Cloud SQL in %s: %v", project, err)
			attrs["error"], attrs["partial"] = msg, msg
		default:
			n := 0
			for _, in := range insts {
				if in.MasterInstanceName != "" || in.InstanceType == "READ_REPLICA_INSTANCE" {
					continue // a read replica is judged through its primary
				}
				writeInstance(in, project, s, out)
				n++
			}
			attrs["inspected"] = int64(n)
		}
		out.Node(graph.Node{ID: graph.ScanID(BackupScanner, project), Kind: graph.KindScan, Source: "gcp", SeenAt: s.Now, Attrs: attrs})
	}
	return nil
}

func listInstances(ctx context.Context, a *api, project string) ([]sqlInstance, error) {
	var out []sqlInstance
	tok := ""
	for {
		var page struct {
			Items []sqlInstance `json:"items"`
			Next  string        `json:"nextPageToken"`
		}
		u := "https://" + sqlHost + "/v1/projects/" + url.PathEscape(project) + "/instances?maxResults=500"
		if tok != "" {
			u += "&pageToken=" + url.QueryEscape(tok)
		}
		if err := a.do(ctx, http.MethodGet, u, nil, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if page.Next == "" {
			return out, nil
		}
		tok = page.Next
	}
}

// writeInstance writes one Cloud SQL instance. Cloud SQL keeps automated
// backups in the instance's own project, so the API never shows a copy in a
// different project: separate_copy is unknown unless backups.yaml declares one.
// Retention is a count of daily backups, so it reads as days.
func writeInstance(in sqlInstance, project string, s connector.Scope, out graph.Writer) {
	bc := in.Settings.BackupConfiguration
	retention := int64(-1)
	if rs := bc.BackupRetentionSettings; rs != nil && rs.RetainedBackups != nil && (rs.RetentionUnit == "" || rs.RetentionUnit == "COUNT") {
		retention = *rs.RetainedBackups
	}
	if !bc.Enabled {
		retention = 0
	}
	var detail []string
	if bc.BackupTier == "ENHANCED" {
		detail = append(detail, "managed by the Backup and DR service")
	}
	if bc.Location != "" {
		detail = append(detail, "backups stored in "+bc.Location)
	}
	if in.Settings.RetainBackupsOnDelete {
		detail = append(detail, "backups kept after the instance is deleted, in the same project")
	}
	if f := in.Settings.FinalBackupConfig; f != nil && f.Enabled {
		detail = append(detail, fmt.Sprintf("final backup kept %d days", f.RetentionDays))
	}
	if len(in.ReplicaNames) > 0 {
		r := append([]string(nil), in.ReplicaNames...)
		sort.Strings(r)
		detail = append(detail, "replicas "+strings.Join(r, ", ")+" (a replica is not a backup)")
	}
	tagged := false
	for k, v := range in.Settings.UserLabels {
		k, v = strings.ToLower(k), strings.ToLower(v)
		if (k == "env" || k == "environment") && (v == "prod" || v == "production") {
			tagged = true
		}
	}
	marked := s.Project.Config.IsProduction(project)
	out.Node(graph.Node{ID: graph.ID("gcp:db/" + project + "/" + in.Name), Kind: graph.KindDatabase, Source: "gcp", SeenAt: s.Now,
		Attrs: map[string]any{
			"system": "gcp", "account": "", "project": project, "profile": "", "region": in.Region, "name": in.Name,
			"engine": in.DatabaseVersion, "db_kind": "instance",
			"production": marked || tagged, "production_marked": marked,
			"automated_backups": bc.Enabled, "retention_days": retention, "deletion_protection": in.Settings.DeletionProtectionEnabled,
			"point_in_time_recovery": bc.PointInTimeRecoveryEnabled,
			"separate_copy":          "unknown", "copy_detail": strings.Join(detail, "; "),
		}})
}
