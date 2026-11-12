package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// CopyWindowDays is how far back a completed AWS Backup copy job counts as
// evidence that a copy exists.
const CopyWindowDays = 35

// BackupScanner names the scan record of one profile's databases.
const BackupScanner = "aws_backups"

// RDSClientFor returns an RDS client behind the guard.
func RDSClientFor(cfg awssdk.Config, log *connector.CallLog) *rds.Client {
	return rds.NewFromConfig(cfg, func(o *rds.Options) {
		o.APIOptions = append(o.APIOptions, guardMiddleware(log))
	})
}

// BackupClientFor returns an AWS Backup client behind the guard.
func BackupClientFor(cfg awssdk.Config, log *connector.CallLog) *backup.Client {
	return backup.NewFromConfig(cfg, func(o *backup.Options) {
		o.APIOptions = append(o.APIOptions, guardMiddleware(log))
	})
}

// dbRow is one database as read, before it is written.
type dbRow struct {
	id, arn, name, engine, kind string
	retention                   int32
	deletionProtection          bool
	tags                        map[string]string
	replicatedTo                []string
}

// collectBackups reads every connected profile's databases in each region. A
// profile or region that cannot be read is recorded on the profile's scan
// record, so only the backup drills see it: IAM drills still run.
func (c *Connector) collectBackups(ctx context.Context, s connector.Scope, out graph.Writer) error {
	for _, acct := range s.Project.Config.AWS.Accounts {
		cfg, err := c.Load(ctx, acct.Profile)
		if err != nil {
			return fmt.Errorf("aws profile %s: %w", acct.Profile, err)
		}
		if err := c.collectProfileBackups(ctx, cfg, acct.Profile, s, out); err != nil {
			return err
		}
	}
	return nil
}

func (c *Connector) collectProfileBackups(ctx context.Context, cfg awssdk.Config, profile string, s connector.Scope, out graph.Writer) error {
	regions := s.Project.Config.AWS.Regions
	if len(regions) == 0 && cfg.Region != "" {
		regions = []string{cfg.Region}
	}
	scan := graph.ScanID(BackupScanner, profile)
	if len(regions) == 0 {
		msg := "no region to read: set aws.regions in config.yaml or a region in profile " + profile
		out.Node(graph.Node{ID: scan, Kind: graph.KindScan, Source: "aws", SeenAt: s.Now, Attrs: map[string]any{
			"scanner": BackupScanner, "scope": profile, "inspected": int64(0), "partial": msg, "error": msg}})
		return nil
	}
	var failed, partial []string
	count := 0
	for _, region := range regions {
		rcfg := cfg.Copy()
		rcfg.Region = region
		dbs, err := readRDS(ctx, RDSClientFor(rcfg, s.Log))
		if err != nil {
			if errors.Is(err, connector.ErrBlocked) {
				return err
			}
			failed = append(failed, fmt.Sprintf("%s: %v", region, err))
			continue
		}
		copies, copyErr := copyJobs(ctx, BackupClientFor(rcfg, s.Log), s.Now)
		if copyErr != nil && errors.Is(copyErr, connector.ErrBlocked) {
			return copyErr
		}
		if copyErr != nil && len(dbs) > 0 {
			partial = append(partial, region+": AWS Backup copy jobs not readable, so separate copies are unknown")
		}
		for _, db := range dbs {
			count++
			writeDB(db, profile, region, copies, copyErr == nil, s, out)
		}
	}
	attrs := map[string]any{"scanner": BackupScanner, "scope": profile, "inspected": int64(count)}
	switch {
	case len(failed) == len(regions):
		msg := "could not read RDS in profile " + profile + ": " + strings.Join(failed, "; ")
		attrs["error"], attrs["partial"] = msg, msg
	case len(failed) > 0 || len(partial) > 0:
		attrs["partial"] = strings.Join(append(append([]string{}, failed...), partial...), "; ")
	}
	out.Node(graph.Node{ID: scan, Kind: graph.KindScan, Source: "aws", SeenAt: s.Now, Attrs: attrs})
	return nil
}

// readRDS lists DB clusters and stand-alone DB instances. An instance that
// belongs to a cluster is judged through its cluster, where retention and
// deletion protection live, and a read replica through its source.
func readRDS(ctx context.Context, cl *rds.Client) ([]dbRow, error) {
	var out []dbRow
	cp := rds.NewDescribeDBClustersPaginator(cl, &rds.DescribeDBClustersInput{})
	for cp.HasMorePages() {
		page, err := cp.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, cluster := range page.DBClusters {
			if awssdk.ToString(cluster.ReplicationSourceIdentifier) != "" {
				continue
			}
			out = append(out, dbRow{
				id: awssdk.ToString(cluster.DBClusterIdentifier), arn: awssdk.ToString(cluster.DBClusterArn),
				name: awssdk.ToString(cluster.DBClusterIdentifier), engine: awssdk.ToString(cluster.Engine), kind: "cluster",
				retention: awssdk.ToInt32(cluster.BackupRetentionPeriod), deletionProtection: awssdk.ToBool(cluster.DeletionProtection),
				tags: tagMap(cluster.TagList),
			})
		}
	}
	ip := rds.NewDescribeDBInstancesPaginator(cl, &rds.DescribeDBInstancesInput{})
	for ip.HasMorePages() {
		page, err := ip.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, inst := range page.DBInstances {
			if awssdk.ToString(inst.DBClusterIdentifier) != "" || awssdk.ToString(inst.ReadReplicaSourceDBInstanceIdentifier) != "" ||
				awssdk.ToString(inst.ReadReplicaSourceDBClusterIdentifier) != "" {
				continue
			}
			row := dbRow{
				id: awssdk.ToString(inst.DBInstanceIdentifier), arn: awssdk.ToString(inst.DBInstanceArn),
				name: awssdk.ToString(inst.DBInstanceIdentifier), engine: awssdk.ToString(inst.Engine), kind: "instance",
				retention: awssdk.ToInt32(inst.BackupRetentionPeriod), deletionProtection: awssdk.ToBool(inst.DeletionProtection),
				tags: tagMap(inst.TagList),
			}
			for _, r := range inst.DBInstanceAutomatedBackupsReplications {
				if region := regionOf(awssdk.ToString(r.DBInstanceAutomatedBackupsArn)); region != "" {
					row.replicatedTo = append(row.replicatedTo, region)
				}
			}
			out = append(out, row)
		}
	}
	return out, nil
}

// copyJobs maps each resource ARN to the accounts its completed AWS Backup copy
// jobs went to in the copy window.
func copyJobs(ctx context.Context, cl *backup.Client, now time.Time) (map[string]map[string]bool, error) {
	after := now.AddDate(0, 0, -CopyWindowDays)
	out := map[string]map[string]bool{}
	p := backup.NewListCopyJobsPaginator(cl, &backup.ListCopyJobsInput{ByState: backuptypes.CopyJobStateCompleted, ByCreatedAfter: &after})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, j := range page.CopyJobs {
			res := awssdk.ToString(j.ResourceArn)
			dest := accountOf(awssdk.ToString(j.DestinationBackupVaultArn))
			if res == "" || dest == "" {
				continue
			}
			if out[res] == nil {
				out[res] = map[string]bool{}
			}
			out[res][dest] = true
		}
	}
	return out, nil
}

func writeDB(db dbRow, profile, region string, copies map[string]map[string]bool, copiesKnown bool, s connector.Scope, out graph.Writer) {
	account := accountOf(db.arn)
	var elsewhere, sameAccount []string
	for dest := range copies[db.arn] {
		if dest != account {
			elsewhere = append(elsewhere, dest)
		} else {
			sameAccount = append(sameAccount, dest)
		}
	}
	sort.Strings(elsewhere)
	separate := "no"
	var detail []string
	switch {
	case len(elsewhere) > 0:
		separate = "yes"
		detail = append(detail, "cross-account vault "+strings.Join(elsewhere, ", "))
	case !copiesKnown:
		separate = "unknown"
		detail = append(detail, "AWS Backup copy jobs not readable")
	case len(sameAccount) > 0:
		detail = append(detail, "AWS Backup copies stay in the same account")
	}
	if len(db.replicatedTo) > 0 {
		sort.Strings(db.replicatedTo)
		detail = append(detail, "automated backups replicated to "+strings.Join(db.replicatedTo, ", ")+" (same account)")
	}
	cfg := s.Project.Config
	out.Node(graph.Node{ID: graph.ID("aws:db/" + account + "/" + region + "/" + db.id), Kind: graph.KindDatabase, Source: "aws", SeenAt: s.Now,
		Attrs: map[string]any{
			"system": "aws", "account": account, "project": "", "profile": profile, "region": region, "name": db.name,
			"engine": db.engine, "db_kind": db.kind,
			"production": cfg.IsProduction(account, profile) || prodTagged(db.tags), "production_marked": cfg.IsProduction(account, profile),
			"automated_backups": db.retention > 0, "retention_days": int64(db.retention), "deletion_protection": db.deletionProtection,
			"separate_copy": separate, "copy_detail": strings.Join(detail, "; "),
		}})
}

func tagMap(tags []rdstypes.Tag) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		out[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	return out
}

// prodTagged says whether tags or labels mark a database as production:
// env or environment set to prod or production, in any case.
func prodTagged(tags map[string]string) bool {
	for k, v := range tags {
		k, v = strings.ToLower(k), strings.ToLower(v)
		if (k == "env" || k == "environment") && (v == "prod" || v == "production") {
			return true
		}
	}
	return false
}

// regionOf reads the region out of an ARN.
func regionOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 3 {
		return parts[3]
	}
	return ""
}
