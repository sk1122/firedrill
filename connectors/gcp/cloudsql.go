package gcp

import (
	"context"
	"encoding/json"
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
			var primaries []sqlInstance
			for _, in := range insts {
				if in.MasterInstanceName != "" || in.InstanceType == "READ_REPLICA_INSTANCE" {
					continue // a read replica is judged through its primary
				}
				primaries = append(primaries, in)
			}
			restores, err := readRestores(ctx, a, project, primaries)
			if err != nil {
				return err
			}
			for _, in := range primaries {
				writeInstance(in, project, s, out, restores.of(in.Name))
			}
			attrs["inspected"] = int64(len(primaries))
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
func writeInstance(in sqlInstance, project string, s connector.Scope, out graph.Writer, rs restoreEvidence) {
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
			"last_restore": rs.at, "restore_scope": rs.scope, "restore_detail": rs.detail, "restores_readable": rs.readable,
		}})
}

// sqlOperation is one Cloud SQL operation, as operations.list returns it.
// https://docs.cloud.google.com/sql/docs/mysql/admin-api/rest/v1/operations
type sqlOperation struct {
	OperationType string `json:"operationType"`
	Status        string `json:"status"`
	EndTime       string `json:"endTime"`
	TargetID      string `json:"targetId"`
	Error         *struct {
		Errors []json.RawMessage `json:"errors"`
	} `json:"error"`
}

// Operation types that show a restore was exercised. RESTORE_VOLUME
// "restores an instance backup" into the instance it runs on; the operation
// does not say whose backup it was. CLONE runs on the instance being cloned,
// the source, and brings its data up as a new instance. An import, an export
// and a backup are not restores.
const (
	opRestore = "RESTORE_VOLUME"
	opClone   = "CLONE"
)

// maxOpPages caps how many pages of 500 operations are read per instance.
const maxOpPages = 10

// restoreEvidence is what the operations show for one database.
type restoreEvidence struct {
	at       string // when the latest restore that counts for it finished, RFC 3339, or ""
	scope    string // instance, project, or "" when none was found
	detail   string
	readable bool // every instance's operations in the project were read
}

// projectRestores holds what one project's operations show.
type projectRestores struct {
	project    string
	clones     map[string]string // instance to its latest finished clone
	restore    string            // latest finished backup restore anywhere in the project
	restoredTo string            // the instance it ran on
	unreadable []string
	capped     []string
}

func (p projectRestores) of(instance string) restoreEvidence {
	r := restoreEvidence{readable: len(p.unreadable) == 0}
	var notes []string
	clone := p.clones[instance]
	switch {
	case clone != "" && clone >= p.restore:
		r.at, r.scope = clone, "instance"
		notes = append(notes, "a clone of "+instance+" finished "+clone[:10]+"; a clone shows its data can be brought up elsewhere")
	case p.restore != "":
		r.at, r.scope = p.restore, "project"
		notes = append(notes, "a backup restore into "+p.restoredTo+" finished "+p.restore[:10]+
			"; the operation does not name the backup it came from, so it counts for every database in "+p.project)
	}
	if len(p.unreadable) > 0 {
		notes = append(notes, "operations could not be read for "+strings.Join(p.unreadable, ", "))
	}
	if len(p.capped) > 0 {
		notes = append(notes, fmt.Sprintf("only the latest %d operations were read for %s", maxOpPages*500, strings.Join(p.capped, ", ")))
	}
	r.detail = strings.Join(notes, "; ")
	return r
}

// readRestores reads each instance's operations and keeps the latest restore
// and clone that finished without an error. An instance whose operations
// cannot be read is named, so nothing found there never reads as never
// restored.
func readRestores(ctx context.Context, a *api, project string, insts []sqlInstance) (projectRestores, error) {
	p := projectRestores{project: project, clones: map[string]string{}}
	for _, in := range insts {
		ops, capped, err := listOperations(ctx, a, project, in.Name)
		if errors.Is(err, connector.ErrBlocked) {
			return p, err
		}
		if err != nil {
			p.unreadable = append(p.unreadable, fmt.Sprintf("%s (%v)", in.Name, err))
			continue
		}
		if capped {
			p.capped = append(p.capped, in.Name)
		}
		for _, op := range ops {
			if op.Status != "DONE" || op.Error != nil {
				continue
			}
			end := normTime(op.EndTime)
			if end == "" {
				continue
			}
			target := op.TargetID
			if target == "" {
				target = in.Name
			}
			switch op.OperationType {
			case opClone:
				if end > p.clones[target] {
					p.clones[target] = end
				}
			case opRestore:
				if end > p.restore {
					p.restore, p.restoredTo = end, target
				}
			}
		}
	}
	return p, nil
}

func listOperations(ctx context.Context, a *api, project, instance string) ([]sqlOperation, bool, error) {
	var out []sqlOperation
	tok := ""
	for page := 0; page < maxOpPages; page++ {
		var res struct {
			Items []sqlOperation `json:"items"`
			Next  string         `json:"nextPageToken"`
		}
		u := "https://" + sqlHost + "/v1/projects/" + url.PathEscape(project) + "/operations?instance=" + url.QueryEscape(instance) + "&maxResults=500"
		if tok != "" {
			u += "&pageToken=" + url.QueryEscape(tok)
		}
		if err := a.do(ctx, http.MethodGet, u, nil, &res); err != nil {
			return nil, false, err
		}
		out = append(out, res.Items...)
		if res.Next == "" {
			return out, false, nil
		}
		tok = res.Next
	}
	return out, true, nil
}
