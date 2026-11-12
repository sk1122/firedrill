package google

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"

	"golang.org/x/oauth2"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// TokenWorkers bounds how many users' grants are read at once. The connector's
// rate limit still applies to every call.
const TokenWorkers = 8

// sensitiveScopes is the table of OAuth scopes that reach a user's mail, all of
// their Drive, the admin console, or all of Google Cloud. An app holding any of
// them is high risk. Built from Google's scope list:
// https://developers.google.com/identity/protocols/oauth2/scopes
//
//	area   scope, or prefix ending in a dot
//	mail   https://mail.google.com/                       full mail access
//	mail   https://www.googleapis.com/auth/gmail.         every Gmail scope, down to labels and metadata
//	drive  https://www.googleapis.com/auth/drive          full Drive access
//	drive  https://www.googleapis.com/auth/drive.         every Drive scope except the per-file ones below
//	drive  https://www.googleapis.com/auth/documents      every Doc the user can open (and .readonly)
//	drive  https://www.googleapis.com/auth/spreadsheets   every Sheet the user can open (and .readonly)
//	drive  https://www.googleapis.com/auth/presentations  every Slides deck the user can open (and .readonly)
//	drive  https://docs.google.com/feeds/                 legacy Docs list, full Drive access
//	drive  https://spreadsheets.google.com/feeds          legacy Sheets, every Sheet
//	admin  https://www.googleapis.com/auth/admin.         every Admin SDK scope
//	cloud  https://www.googleapis.com/auth/cloud-platform all of Google Cloud (and .read-only)
//
// Per-file Drive scopes reach only what the app made or the user opened with
// it, so they are not sensitive: drive.file, drive.appdata, drive.apps.readonly
// (lists Drive apps, no files) and drive.install.
var sensitiveScopes = []struct {
	scope, area string
}{
	{"https://mail.google.com/", "mail"},
	{"https://www.googleapis.com/auth/gmail.", "mail"},
	{"https://www.googleapis.com/auth/drive", "drive"},
	{"https://www.googleapis.com/auth/drive.", "drive"},
	{"https://www.googleapis.com/auth/documents", "drive"},
	{"https://www.googleapis.com/auth/documents.readonly", "drive"},
	{"https://www.googleapis.com/auth/spreadsheets", "drive"},
	{"https://www.googleapis.com/auth/spreadsheets.readonly", "drive"},
	{"https://www.googleapis.com/auth/presentations", "drive"},
	{"https://www.googleapis.com/auth/presentations.readonly", "drive"},
	{"https://docs.google.com/feeds/", "drive"},
	{"https://spreadsheets.google.com/feeds", "drive"},
	{"https://www.googleapis.com/auth/admin.", "admin"},
	{"https://www.googleapis.com/auth/cloud-platform", "cloud"},
	{"https://www.googleapis.com/auth/cloud-platform.read-only", "cloud"},
}

var perFileDrive = map[string]bool{
	"https://www.googleapis.com/auth/drive.file":          true,
	"https://www.googleapis.com/auth/drive.appdata":       true,
	"https://www.googleapis.com/auth/drive.apps.readonly": true,
	"https://www.googleapis.com/auth/drive.install":       true,
}

// SensitiveArea returns the area a scope reaches (mail, drive, admin or cloud),
// or "" when it is not sensitive.
func SensitiveArea(scope string) string {
	if perFileDrive[scope] {
		return ""
	}
	for _, s := range sensitiveScopes {
		if scope == s.scope || (strings.HasSuffix(s.scope, ".") && strings.HasPrefix(scope, s.scope)) {
			return s.area
		}
	}
	return ""
}

type grantedApp struct {
	name              string
	scopes            map[string]bool
	people            map[string]bool
	native, anonymous bool
}

type tokenUser struct{ id, email string }

// scopeDenied says whether an error means the delegation lacks the tokens scope:
// the token exchange refused it, or the API answered 401 or 403.
func scopeDenied(err error) bool {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return true
	}
	var ge *googleapi.Error
	return errors.As(err, &ge) && (ge.Code == http.StatusUnauthorized || ge.Code == http.StatusForbidden)
}

// collectTokens reads the OAuth grants of every user, one call per user. A
// missing scope gives an error on the scan record, so only the app drill sees
// it; a user whose grants could not be read makes the result partial.
func (c *Connector) collectTokens(ctx context.Context, s connector.Scope, out graph.Writer) error {
	usvc, err := c.service(ctx, s, admin.AdminDirectoryUserReadonlyScope)
	if err != nil {
		return err
	}
	var users []tokenUser
	if err := listUsers(ctx, usvc, s, func(u *admin.User) {
		users = append(users, tokenUser{id: u.Id, email: strings.ToLower(u.PrimaryEmail)})
	}); err != nil {
		return err
	}
	tsvc, err := c.service(ctx, s, TokensScope)
	if err != nil {
		return err
	}
	scan := graph.ScanID(TokenScanner, "")
	writeScan := func(attrs map[string]any) {
		attrs["scanner"], attrs["scope"] = TokenScanner, ""
		out.Node(graph.Node{ID: scan, Kind: graph.KindScan, Source: "google", SeenAt: s.Now, Attrs: attrs})
	}

	var mu sync.Mutex
	apps := map[string]*grantedApp{}
	read, denied, failed := 0, 0, 0
	var blocked error
	// The user ID, never the email, goes in the URL, so no address reaches the
	// call log.
	readOne := func(u tokenUser) error {
		res, err := tsvc.Tokens.List(u.id).Context(ctx).Do()
		mu.Lock()
		defer mu.Unlock()
		switch {
		case errors.Is(err, connector.ErrBlocked):
			blocked = err
			return err
		case err != nil && scopeDenied(err):
			denied++
			return err
		case err != nil:
			failed++
			return err
		}
		read++
		person := "person:" + s.Hasher.Email(u.email)
		for _, t := range res.Items {
			if t.ClientId == "" {
				continue
			}
			a := apps[t.ClientId]
			if a == nil {
				a = &grantedApp{scopes: map[string]bool{}, people: map[string]bool{}}
				apps[t.ClientId] = a
			}
			if a.name == "" {
				a.name = t.DisplayText
			}
			for _, sc := range t.Scopes {
				a.scopes[sc] = true
			}
			a.people[person] = true
			a.native = a.native || t.NativeApp
			a.anonymous = a.anonymous || t.Anonymous
		}
		return nil
	}

	// The first user goes alone: when the scope is missing every call fails the
	// same way, and stopping here saves a token exchange per user.
	if len(users) > 0 {
		if err := readOne(users[0]); err != nil && (blocked != nil || denied > 0) {
			if blocked != nil {
				return blocked
			}
			msg := fmt.Sprintf("could not read users' OAuth grants: %v. Add %s to the service account's domain-wide delegation in the Admin console", err, TokensScope)
			writeScan(map[string]any{"inspected": int64(0), "partial": msg, "error": msg})
			return nil
		}
	}
	work := make(chan tokenUser)
	var wg sync.WaitGroup
	for range TokenWorkers {
		wg.Go(func() {
			for u := range work {
				_ = readOne(u)
			}
		})
	}
	for _, u := range users[min(1, len(users)):] {
		work <- u
	}
	close(work)
	wg.Wait()
	if blocked != nil {
		return blocked
	}

	attrs := map[string]any{"inspected": int64(read)}
	if denied+failed > 0 {
		attrs["partial"] = fmt.Sprintf("the OAuth grants of %d of %d users could not be read", denied+failed, len(users))
	}
	writeScan(attrs)
	for id, a := range apps {
		writeApp(id, a, s, out)
	}
	return nil
}

func writeApp(clientID string, a *grantedApp, s connector.Scope, out graph.Writer) {
	scopes := sortedSet(a.scopes)
	sensitive := []any{}
	for _, sc := range scopes {
		if SensitiveArea(sc.(string)) != "" {
			sensitive = append(sensitive, sc)
		}
	}
	id := graph.ID("google:oauth-app/" + clientID)
	out.Node(graph.Node{ID: id, Kind: graph.KindOAuthApp, Source: "google", SeenAt: s.Now, Attrs: map[string]any{
		"client_id": clientID, "name": a.name, "scopes": scopes, "sensitive_scopes": sensitive,
		"high_risk": len(sensitive) > 0, "user_count": int64(len(a.people)), "native": a.native, "anonymous": a.anonymous,
	}})
	for p := range a.people {
		out.Edge(graph.Edge{From: id, To: graph.ID(p), Kind: graph.EdgeGrantedTo, Source: "google"})
	}
}

func sortedSet(m map[string]bool) []any {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}
