// Package google reads the Workspace directory through a service account with
// domain-wide delegation.
package google

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	googleoauth "golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// CredentialsEnv names the variable holding the key file's path.
const CredentialsEnv = "GOOGLE_APPLICATION_CREDENTIALS"

// Connector reads Google Workspace.
type Connector struct{ connector.Base }

// New returns the connector.
func New() *Connector {
	return &Connector{ConnectorName: "google", Policy: connector.GooglePolicy(), Limit: 10, Burst: 10}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{
		Name:       "directory users",
		Nodes:      []string{graph.KindIdentityUser},
		Permission: admin.AdminDirectoryUserReadonlyScope,
		Calls: []string{
			"POST https://oauth2.googleapis.com/token",
			"GET https://admin.googleapis.com/admin/directory/v1/users?domain={domain}",
		},
	}}
}

func keyPath(s connector.Scope) string {
	if s.Getenv != nil {
		return s.Getenv(CredentialsEnv)
	}
	return ""
}

// Available is true when the domain, the admin and the key are all set.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	g := s.Project.Config.Google
	if g.Domain == "" || g.AdminEmail == "" || keyPath(s) == "" {
		return false, "connect google"
	}
	return true, ""
}

// Collect reads every user in the domain.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	key, err := os.ReadFile(keyPath(s))
	if err != nil {
		return fmt.Errorf("read the service account key: %w", errors.Unwrap(err))
	}
	conf, err := googleoauth.JWTConfigFromJSON(key, admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		return fmt.Errorf("the service account key could not be parsed")
	}
	conf.Subject = s.Project.Config.Google.AdminEmail
	guarded := c.HTTP(s.Log)
	authed := conf.Client(context.WithValue(ctx, oauth2.HTTPClient, guarded))
	svc, err := admin.NewService(ctx, option.WithHTTPClient(authed))
	if err != nil {
		return err
	}
	return svc.Users.List().Domain(s.Project.Config.Google.Domain).MaxResults(500).OrderBy("email").
		Pages(ctx, func(page *admin.Users) error {
			for _, u := range page.Users {
				write(u, s, out)
			}
			return nil
		})
}

func write(u *admin.User, s connector.Scope, out graph.Writer) {
	out.Node(graph.Node{
		ID:   graph.ID("google:user/" + s.Hasher.Email(u.PrimaryEmail)),
		Kind: graph.KindIdentityUser, Source: "google", SeenAt: s.Now,
		Attrs: map[string]any{
			"suspended": u.Suspended, "is_admin": u.IsAdmin, "is_delegated_admin": u.IsDelegatedAdmin,
			"mfa_enrolled": u.IsEnrolledIn2Sv, "mfa_enforced": u.IsEnforcedIn2Sv,
			"last_login": normalizeTime(u.LastLoginTime), "created": normalizeTime(u.CreationTime),
		},
		Private: map[string]any{"email": strings.ToLower(u.PrimaryEmail)},
	})
}

// normalizeTime turns Google's zero time, meaning never, into empty.
func normalizeTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil || t.Unix() <= 0 {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
