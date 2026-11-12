// Package google reads the Workspace directory, and the OAuth grants users gave
// third-party apps, through a service account with domain-wide delegation.
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

// Collection names.
const (
	CollectionUsers  = "directory users"
	CollectionTokens = "oauth tokens"
)

// TokensScope is the scope tokens.list needs. Google offers no read-only
// scope for it; the guard allows only GET on the Admin SDK, so the delete
// method it also covers is never called.
// https://developers.google.com/workspace/admin/directory/reference/rest/v1/tokens/list
const TokensScope = admin.AdminDirectoryUserSecurityScope

// TokenScanner names the scan record of the OAuth grants read.
const TokenScanner = "oauth_tokens"

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{
		Name:       CollectionUsers,
		Nodes:      []string{graph.KindIdentityUser},
		Permission: admin.AdminDirectoryUserReadonlyScope,
		Calls: []string{
			"POST https://oauth2.googleapis.com/token",
			"GET https://admin.googleapis.com/admin/directory/v1/users?domain={domain}",
		},
	}, {
		Name:       CollectionTokens,
		Nodes:      []string{graph.KindOAuthApp},
		Permission: admin.AdminDirectoryUserReadonlyScope + " and " + TokensScope,
		Calls: []string{
			"POST https://oauth2.googleapis.com/token",
			"GET https://admin.googleapis.com/admin/directory/v1/users?domain={domain}",
			"GET https://admin.googleapis.com/admin/directory/v1/users/{user ID}/tokens, once per user",
		},
	}}
}

func keyPath(s connector.Scope) string {
	if s.Getenv != nil {
		return s.Getenv(CredentialsEnv)
	}
	return ""
}

// Available is true when Google was connected on purpose and the domain, the
// admin and the key are all set. A key alone is never enough.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	g := s.Project.Config.Google
	if !s.Project.Config.IsConnected("google") || g.Domain == "" || g.AdminEmail == "" || keyPath(s) == "" {
		return false, "connect google"
	}
	return true, ""
}

// service returns an Admin SDK client acting as the configured admin with one
// scope. Each scope gets its own token, so a scope the delegation lacks fails
// only the collection that needs it.
func (c *Connector) service(ctx context.Context, s connector.Scope, scope string) (*admin.Service, error) {
	key, err := os.ReadFile(keyPath(s))
	if err != nil {
		return nil, fmt.Errorf("read the service account key: %w", errors.Unwrap(err))
	}
	conf, err := googleoauth.JWTConfigFromJSON(key, scope)
	if err != nil {
		return nil, fmt.Errorf("the service account key could not be parsed")
	}
	conf.Subject = s.Project.Config.Google.AdminEmail
	guarded := c.HTTP(s.Log)
	authed := conf.Client(context.WithValue(ctx, oauth2.HTTPClient, guarded))
	return admin.NewService(ctx, option.WithHTTPClient(authed))
}

// Collect reads every user in the domain, or every user's OAuth grants.
func (c *Connector) Collect(ctx context.Context, col connector.Collection, s connector.Scope, out graph.Writer) error {
	if col.Name == CollectionTokens {
		return c.collectTokens(ctx, s, out)
	}
	svc, err := c.service(ctx, s, admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		return err
	}
	return listUsers(ctx, svc, s, func(u *admin.User) { write(u, s, out) })
}

func listUsers(ctx context.Context, svc *admin.Service, s connector.Scope, each func(*admin.User)) error {
	return svc.Users.List().Domain(s.Project.Config.Google.Domain).MaxResults(500).OrderBy("email").
		Pages(ctx, func(page *admin.Users) error {
			for _, u := range page.Users {
				each(u)
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
