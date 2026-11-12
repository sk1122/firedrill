package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/sk1122/firedrill/connector"
)

// Power is what one IAM role can do, as far as Firedrill judges it.
type Power struct {
	// Admin is a role that can change who has access, mint or use another
	// identity's credentials, or administer a whole service.
	Admin bool
	// Destructive is a role that can delete data or its backups.
	Destructive bool
	// Known is false for a custom role whose permissions could not be read.
	Known bool
}

// Predefined roles, from Google's role reference:
// https://cloud.google.com/iam/docs/roles-overview and the per-service pages
// under https://cloud.google.com/iam/docs/roles-permissions. Each group says
// which permissions put it there. Any predefined role whose last segment is
// admin or ends in Admin (roles/storage.admin, roles/iam.securityAdmin,
// roles/resourcemanager.projectIamAdmin) is an admin role too, by rule rather
// than by table, so a new service's admin role is never read as harmless.
var adminRoles = map[string]bool{
	// Basic roles. Owner manages roles and permissions on the project; Editor
	// creates and deletes resources in most services. roles/admin is the newer
	// name Google recommends in place of Owner.
	"roles/owner": true, "roles/editor": true, "roles/admin": true,
	// Identity: set any IAM policy, mint tokens or keys for a service
	// account, or act as one (iam.serviceAccounts.actAs, getAccessToken,
	// signJwt, serviceAccountKeys.create).
	"roles/iam.securityAdmin":              true,
	"roles/iam.serviceAccountTokenCreator": true,
	"roles/iam.serviceAccountKeyAdmin":     true,
	"roles/iam.serviceAccountAdmin":        true,
	"roles/iam.serviceAccountUser":         true,
	"roles/iam.workloadIdentityUser":       true,
	"roles/iam.editor":                     true,
	"roles/iam.roleAdmin":                  true,
	// Compute instance admins can set metadata and SSH keys on any instance,
	// and so act as the service account it runs as.
	"roles/compute.instanceAdmin.v1": true, "roles/compute.instanceAdmin": true,
	"roles/resourcemanager.projectIamAdmin": true,
}

var destructiveRoles = map[string]bool{
	// Basic roles: Editor and Owner delete resources in most services.
	"roles/owner": true, "roles/editor": true, "roles/admin": true,
	// Cloud Storage: storage.objects.delete, and buckets.delete for admin.
	"roles/storage.admin": true, "roles/storage.objectAdmin": true, "roles/storage.objectUser": true,
	// Cloud SQL: instances.delete, databases.delete, backupRuns.delete.
	// roles/cloudsql.editor is left out: Google's reference says it cannot
	// delete instances or backups.
	"roles/cloudsql.admin": true,
	// BigQuery: tables.delete and datasets.delete.
	"roles/bigquery.admin": true, "roles/bigquery.dataOwner": true, "roles/bigquery.dataEditor": true,
	// Datastore and Firestore: entities.delete. Not checked against the
	// fetched reference, whose page could not be read.
	"roles/datastore.owner": true, "roles/datastore.user": true,
	// Spanner: databases.drop, and backups.delete for admin.
	"roles/spanner.admin": true, "roles/spanner.databaseAdmin": true,
	// Bigtable: tables.delete and backups.delete.
	"roles/bigtable.admin": true,
	// Compute Engine: disks.delete, snapshots.delete, images.delete.
	// storageAdmin and instanceAdmin.v1 were not in the part of the reference
	// read; they are listed from what they are documented to manage.
	"roles/compute.admin": true, "roles/compute.storageAdmin": true, "roles/compute.instanceAdmin.v1": true,
	// Backup and DR: backup vaults, plans and backups deleted.
	"roles/backupdr.admin": true,
}

// adminPermissions are permissions that make a custom role an admin role:
// any setIamPolicy, and those that let it act as or mint credentials for a
// service account.
var adminPermissions = map[string]bool{
	"iam.serviceAccountKeys.create":              true,
	"iam.serviceAccounts.actAs":                  true,
	"iam.serviceAccounts.getAccessToken":         true,
	"iam.serviceAccounts.getOpenIdToken":         true,
	"iam.serviceAccounts.signBlob":               true,
	"iam.serviceAccounts.signJwt":                true,
	"iam.serviceAccounts.implicitDelegation":     true,
	"iam.roles.create":                           true,
	"iam.roles.update":                           true,
	"resourcemanager.projects.setIamPolicy":      true,
	"resourcemanager.folders.setIamPolicy":       true,
	"resourcemanager.organizations.setIamPolicy": true,
}

// IsCustomRole says whether a role is a project's or organization's own.
func IsCustomRole(role string) bool {
	return strings.HasPrefix(role, "projects/") || strings.HasPrefix(role, "organizations/")
}

// PredefinedPower classifies a basic or predefined role.
func PredefinedPower(role string) Power {
	p := Power{Known: true, Admin: adminRoles[role], Destructive: destructiveRoles[role]}
	last := role[strings.LastIndex(role, ".")+1:]
	if strings.HasPrefix(role, "roles/") && (last == "admin" || strings.HasSuffix(last, "Admin")) {
		p.Admin = true
	}
	return p
}

// PermissionsPower classifies a custom role by its permissions: setIamPolicy
// or credential minting makes it admin, and any delete or drop makes it
// destructive.
func PermissionsPower(perms []string) Power {
	p := Power{Known: true}
	for _, perm := range perms {
		if adminPermissions[perm] || strings.HasSuffix(perm, ".setIamPolicy") {
			p.Admin = true
		}
		if strings.HasSuffix(perm, ".delete") || strings.HasSuffix(perm, ".drop") {
			p.Destructive = true
		}
	}
	return p
}

// customRoles reads the permissions of each custom role a project's bindings
// name, once per role per run. A role that cannot be read stays unknown and
// is listed in the project's partial notes, never read as harmless.
type customRoles struct {
	seen map[string]Power
}

func (c *customRoles) power(ctx context.Context, a *api, role string, partial *[]any) (Power, error) {
	if p, ok := c.seen[role]; ok {
		return p, nil
	}
	var res struct {
		IncludedPermissions []string `json:"includedPermissions"`
	}
	err := a.do(ctx, http.MethodGet, roleURL(role), nil, &res)
	var p Power
	switch {
	case errors.Is(err, connector.ErrBlocked):
		return Power{}, err
	case err != nil:
		*partial = append(*partial, fmt.Sprintf("custom role %s: its permissions could not be read (%v); give the reader iam.roles.get, in Role Viewer", role, err))
	default:
		p = PermissionsPower(res.IncludedPermissions)
	}
	c.seen[role] = p
	return p, nil
}

// roleURL is roles.get for a project's or organization's custom role:
// https://cloud.google.com/iam/docs/reference/rest/v1/projects.roles/get
func roleURL(role string) string {
	parts := strings.Split(role, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	return "https://" + iamHost + "/v1/" + strings.Join(parts, "/")
}
