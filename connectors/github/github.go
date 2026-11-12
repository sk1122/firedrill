// Package github reads repo settings: branch protection and rulesets merged into
// effective rules, environments, plan limits and repo tarballs.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	gh "github.com/google/go-github/v93/github"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// ExportFile is where a repo admin's ruleset export lives.
const ExportFile = "evidence/rulesets.json"

// ExportMaxAge is how long CI may rely on an export.
const ExportMaxAge = 30 * 24 * time.Hour

// Connector reads GitHub.
type Connector struct{ connector.Base }

// New returns the connector.
func New() *Connector {
	return &Connector{ConnectorName: "github", Policy: connector.GitHubPolicy(), Limit: 5, Burst: 10}
}

func init() { connector.Register(New()) }

// Collection names.
const (
	CollectionSettings = "repo settings"
	CollectionPeople   = "people"
)

// Collections lists what it reads. Repo settings come first: the people
// collection resolves the bypass actors those reads found.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{
		Name:       CollectionSettings,
		Nodes:      []string{graph.KindGitHubRepo, graph.KindBranchRule, graph.KindEnvironment, graph.KindActionsPerms},
		Permission: "Metadata, Administration, Environments and Contents, read",
		Calls: []string{
			"GET https://api.github.com/orgs/{org}",
			"GET https://api.github.com/repos/{repo}",
			"GET https://api.github.com/repos/{repo}/branches/{branch}/protection",
			"GET https://api.github.com/repos/{repo}/rules/branches/{branch}",
			"GET https://api.github.com/repos/{repo}/rulesets/{id}",
			"GET https://api.github.com/repos/{repo}/environments",
			"GET https://api.github.com/repos/{repo}/actions/permissions/workflow",
			"GET https://api.github.com/orgs/{org}/audit-log?phrase=..., only after a diff: who changed a ruleset, branch protection, repo access or org role between the two runs (" + AuditPermission + ")",
		},
	}, {
		Name:       CollectionPeople,
		Nodes:      []string{graph.KindGitHubUser, graph.KindGitHubTeam, graph.KindGitHubApp, graph.KindDeployKey},
		Permission: "organization Members: read; repository Metadata and Administration: read",
		Calls: []string{
			"GET https://api.github.com/orgs/{org}/members?role=admin",
			"GET https://api.github.com/orgs/{org}/members?role=member",
			"GET https://api.github.com/orgs/{org}/outside_collaborators",
			"GET https://api.github.com/orgs/{org}/teams",
			"GET https://api.github.com/orgs/{org}/teams/{team}/members?role=maintainer, once per team",
			"GET https://api.github.com/orgs/{org}/teams/{team}/members?role=member, once per team",
			"GET https://api.github.com/repos/{repo}/collaborators?affiliation=all",
			"GET https://api.github.com/repos/{repo}/teams",
		},
	}}
}

// Available is true when GitHub was connected on purpose, a token is present and
// repos are listed. A token alone, such as the gh CLI's login, is never enough.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if !s.Project.Config.IsConnected("github") || s.Token == "" {
		return false, "connect github"
	}
	if s.Project.Config.GitHub.Org == "" || len(s.Project.Config.GitHub.Repos) == 0 {
		return false, "list github.org and github.repos in config"
	}
	return true, ""
}

func (c *Connector) client(s connector.Scope) (*gh.Client, error) {
	opts := []gh.ClientOptionsFunc{gh.WithHTTPClient(c.HTTP(s.Log))}
	if s.Token != "" {
		opts = append(opts, gh.WithAuthToken(s.Token))
	}
	return gh.NewClient(opts...)
}

func notFound(resp *gh.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusNotFound
}

func forbidden(resp *gh.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusForbidden
}

// plan returns the owner's plan in lowercase, or "unknown" when the token cannot
// see it. It reads an org first, then falls back to a user.
func plan(ctx context.Context, cl *gh.Client, owner string) string {
	org, resp, err := cl.Organizations.Get(ctx, owner)
	if err == nil && org.Plan != nil && org.Plan.Name != nil {
		return normalizePlan(*org.Plan.Name)
	}
	if notFound(resp) {
		u, _, err := cl.Users.Get(ctx, owner)
		if err == nil && u.Plan != nil && u.Plan.Name != nil {
			return normalizePlan(*u.Plan.Name)
		}
	}
	return "unknown"
}

func normalizePlan(p string) string {
	p = strings.ToLower(p)
	switch {
	case strings.Contains(p, "enterprise"):
		return "enterprise"
	case strings.Contains(p, "team"):
		return "team"
	case strings.Contains(p, "pro"):
		return "pro"
	case strings.Contains(p, "free"):
		return "free"
	}
	return p
}

// Collect reads settings for every listed repo, or the people who can reach them.
func (c *Connector) Collect(ctx context.Context, col connector.Collection, s connector.Scope, out graph.Writer) error {
	if col.Name == CollectionPeople {
		return c.collectPeople(ctx, s, out)
	}
	cl, err := c.client(s)
	if err != nil {
		return err
	}
	owner := s.Project.Config.GitHub.Org
	p := plan(ctx, cl, owner)
	exp, expDetail := loadExport(ctx, cl, s)
	for _, name := range s.Project.Config.GitHub.Repos {
		full := owner + "/" + name
		repo, _, err := cl.Repositories.Get(ctx, owner, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", full, err)
		}
		private := repo.GetPrivate()
		rule, actors, planBlocked, err := branchRule(ctx, cl, owner, name, repo.GetDefaultBranch(), exp, expDetail, s.Now)
		if err != nil {
			return fmt.Errorf("read rules of %s: %w", full, err)
		}
		// An unknown plan is assumed to have protection, so a drill never returns
		// N/A on a guess. GitHub saying the plan does not offer protection on
		// this repo is not a guess, so it counts whatever the plan lookup read.
		// Required reviewers stay off, the stricter reading of what to ask for.
		available := (!private || p != "free") && !planBlocked
		repoID := graph.ID("github:repo/" + full)
		out.Node(graph.Node{ID: repoID, Kind: graph.KindGitHubRepo, Source: "github", SeenAt: s.Now, Attrs: map[string]any{
			"name": full, "private": private, "plan": p, "protection_available": available,
		}})
		// The raw actors hold logins, so they stay private; the people
		// collection resolves them and adds the hashed list.
		out.Node(graph.Node{ID: graph.ID("github:branch-rule/" + full + "/default"), Kind: graph.KindBranchRule, Source: "github", SeenAt: s.Now,
			Attrs: rule, Private: map[string]any{privateActors: actors}})
		if err := environments(ctx, cl, owner, name, full, s, out); err != nil {
			return fmt.Errorf("read environments of %s: %w", full, err)
		}
		perms, _, err := cl.Repositories.GetDefaultWorkflowPermissions(ctx, owner, name)
		if err != nil {
			return fmt.Errorf("read Actions settings of %s: %w", full, err)
		}
		out.Node(graph.Node{ID: graph.ID("github:actions/" + full), Kind: graph.KindActionsPerms, Source: "github", SeenAt: s.Now, Attrs: map[string]any{
			"can_approve_pull_requests": perms.GetCanApprovePullRequestReviews(),
			"default_token_permission":  perms.GetDefaultWorkflowPermissions(),
		}})
	}
	return nil
}

type branchRuleEntry struct {
	Type       string `json:"type"`
	RulesetID  int64  `json:"ruleset_id"`
	Parameters struct {
		RequiredApprovals int  `json:"required_approving_review_count"`
		DismissStale      bool `json:"dismiss_stale_reviews_on_push"`
		CodeOwnerReview   bool `json:"require_code_owner_review"`
	} `json:"parameters"`
}

// planBlocks reports GitHub's reply that the plan offers no branch protection
// on this repo, such as a private repo on the free plan.
func planBlocks(err error) bool {
	var e *gh.ErrorResponse
	return errors.As(err, &e) && strings.Contains(e.Message, "Upgrade to GitHub Pro")
}

// branchRule merges branch protection and rulesets into the effective rules. It
// also returns who may bypass review as read, before any is resolved to people,
// and whether GitHub said the plan offers no protection on the repo. The rules
// carry bypass_actors_known: false when any bypass list could not be read, or
// names a role that cannot be resolved, so nothing about who is listed then.
func branchRule(ctx context.Context, cl *gh.Client, owner, repo, branch string, exp *Export, expDetail string, now time.Time) (map[string]any, []bypassActor, bool, error) {
	planBlocked := false
	approvals, dismiss, codeOwner := 0, false, false
	force, deletion := true, true
	bypass := "none"
	source := "api"
	actors := []bypassActor{}
	known := true

	prot, resp, err := cl.Repositories.GetBranchProtection(ctx, owner, repo, branch)
	switch {
	case err == nil:
		force = prot.GetAllowForcePushes() != nil && prot.GetAllowForcePushes().Enabled
		deletion = prot.GetAllowDeletions() != nil && prot.GetAllowDeletions().Enabled
		if r := prot.GetRequiredPullRequestReviews(); r != nil {
			approvals, dismiss, codeOwner = r.RequiredApprovingReviewCount, r.DismissStaleReviews, r.RequireCodeOwnerReviews
			if a := r.BypassPullRequestAllowances; a != nil && (len(a.Users)+len(a.Teams)+len(a.Apps)) > 0 {
				bypass = "allowed"
				actors = append(actors, classicAllowances(a)...)
			}
		}
		if e := prot.GetEnforceAdmins(); e == nil || !e.Enabled {
			bypass = "allowed"
			actors = append(actors, bypassActor{Kind: actorRole, Name: "admin", Via: viaAdminsNotEnforced})
		}
	case errors.Is(err, gh.ErrBranchNotProtected), notFound(resp):
		// No classic protection. Rulesets may still apply.
	case forbidden(resp) && planBlocks(err):
		// The plan offers no protection on this repo.
		planBlocked = true
	case forbidden(resp):
		// The token cannot read the protection, so nothing here is known.
		return nil, nil, false, fmt.Errorf("the token cannot read branch protection of %s/%s: give it Administration: read", owner, repo)
	default:
		return nil, nil, false, err
	}

	req, err := cl.NewRequest(ctx, http.MethodGet, fmt.Sprintf("repos/%s/%s/rules/branches/%s", owner, repo, branch), nil)
	if err != nil {
		return nil, nil, false, err
	}
	var rules []branchRuleEntry
	if resp, err := cl.Do(req, &rules); err != nil && !notFound(resp) {
		switch {
		case forbidden(resp) && planBlocks(err):
			// The plan offers no rulesets on this repo, so none apply.
		case forbidden(resp):
			return nil, nil, false, fmt.Errorf("the token cannot read the rulesets of %s/%s: give it Administration: read", owner, repo)
		default:
			return nil, nil, false, err
		}
	}
	ids := map[int64]bool{}
	var order []int64
	for _, r := range rules {
		if r.RulesetID != 0 && !ids[r.RulesetID] {
			ids[r.RulesetID] = true
			order = append(order, r.RulesetID)
		}
		switch r.Type {
		case "pull_request":
			if r.Parameters.RequiredApprovals > approvals {
				approvals = r.Parameters.RequiredApprovals
			}
			dismiss = dismiss || r.Parameters.DismissStale
			codeOwner = codeOwner || r.Parameters.CodeOwnerReview
		case "non_fast_forward":
			force = false
		case "deletion":
			deletion = false
		}
	}
	for _, id := range order {
		list, src, err := rulesetActors(ctx, cl, owner, repo, id, exp, now)
		if err != nil {
			return nil, nil, false, err
		}
		switch {
		case list == nil:
			known = false
			if bypass != "allowed" {
				bypass = "unknown"
			}
		case len(list) > 0:
			bypass = "allowed"
		}
		for _, a := range list {
			if a.Kind == actorRole && a.Name == "" {
				known = false // a custom role: who holds it is not read
			}
			actors = append(actors, a)
		}
		if src != "api" {
			source = src
			if expDetail != "" {
				source = src + ": " + expDetail
			}
		}
	}
	if !known {
		actors = []bypassActor{}
	}
	return map[string]any{
		"required_approvals": int64(approvals), "dismiss_stale": dismiss, "code_owner_review": codeOwner,
		"bypass": bypass, "bypass_source": strings.SplitN(source, ":", 2)[0], "bypass_detail": source,
		"force_push_allowed": force, "deletion_allowed": deletion, "bypass_actors_known": known,
	}, actors, planBlocked, nil
}

// rulesetDoc is the part of a ruleset read for its bypass list.
type rulesetDoc struct {
	Name         string             `json:"name"`
	BypassActors *[]json.RawMessage `json:"bypass_actors"`
}

// rulesetActors reads one ruleset's bypass list. GitHub returns it only to
// callers with write access, so it falls back to the admin export. A nil list
// means it could not be read; an empty one means nobody may bypass.
func rulesetActors(ctx context.Context, cl *gh.Client, owner, repo string, id int64, exp *Export, now time.Time) ([]bypassActor, string, error) {
	req, err := cl.NewRequest(ctx, http.MethodGet, fmt.Sprintf("repos/%s/%s/rulesets/%d?includes_parents=true", owner, repo, id), nil)
	if err != nil {
		return nil, "", err
	}
	var doc rulesetDoc
	resp, err := cl.Do(req, &doc)
	if err != nil && !notFound(resp) && !forbidden(resp) {
		return nil, "", err
	}
	if err == nil && doc.BypassActors != nil {
		return parseActors(*doc.BypassActors, rulesetVia(doc.Name, id)), "api", nil
	}
	if exp != nil && now.Sub(exp.GeneratedAt) < ExportMaxAge {
		if rs, ok := exp.Repos[owner+"/"+repo][fmt.Sprint(id)]; ok {
			return parseActors(rs.BypassActors, rulesetVia(rs.Name, id)), "admin_export", nil
		}
	}
	return nil, "api", nil
}

func rulesetVia(name string, id int64) string {
	if name == "" {
		name = fmt.Sprint(id)
	}
	return "ruleset:" + name
}

func environments(ctx context.Context, cl *gh.Client, owner, name, full string, s connector.Scope, out graph.Writer) error {
	opts := &gh.EnvironmentListOptions{PerPage: 100}
	for {
		list, resp, err := cl.Repositories.ListEnvironments(ctx, owner, name, opts)
		if notFound(resp) || (forbidden(resp) && planBlocks(err)) {
			return nil
		}
		if forbidden(resp) {
			return fmt.Errorf("the token cannot read the environments of %s: give it Environments: read", full)
		}
		if err != nil {
			return err
		}
		for _, e := range list.Environments {
			reviewers := []any{}
			prevent := false
			for _, rule := range e.ProtectionRules {
				if rule.GetType() != "required_reviewers" {
					continue
				}
				prevent = rule.GetPreventSelfReview()
				for _, r := range rule.Reviewers {
					reviewers = append(reviewers, reviewerName(r))
				}
			}
			protected := e.DeploymentBranchPolicy != nil && e.DeploymentBranchPolicy.GetProtectedBranches()
			out.Node(graph.Node{ID: graph.ID("github:env/" + full + "/" + e.GetName()), Kind: graph.KindEnvironment, Source: "github", SeenAt: s.Now, Attrs: map[string]any{
				"required_reviewers": reviewers, "prevent_self_review": prevent,
				"admin_bypass": e.CanAdminsBypass == nil || *e.CanAdminsBypass, "protected_branches_only": protected,
			}})
			out.Edge(graph.Edge{From: graph.ID("github:repo/" + full), To: graph.ID("github:env/" + full + "/" + e.GetName()), Kind: graph.EdgeDeploysTo, Source: "github"})
		}
		if resp.NextPage == 0 {
			return nil
		}
		opts.Page = resp.NextPage
	}
}

func reviewerName(r *gh.RequiredReviewer) string {
	switch v := r.Reviewer.(type) {
	case *gh.User:
		return v.GetLogin()
	case *gh.Team:
		return v.GetSlug()
	}
	return r.GetType()
}

// Tarball returns a function that downloads a repo's committed files.
func (c *Connector) Tarball(s connector.Scope) func(ctx context.Context, repo string) (io.ReadCloser, error) {
	cl := c.HTTP(s.Log)
	return func(ctx context.Context, repo string) (io.ReadCloser, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/repos/"+repo+"/tarball", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+s.Token)
		resp, err := cl.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("download %s: status %d", repo, resp.StatusCode)
		}
		return resp.Body, nil
	}
}

// RulesetExport is one ruleset in an export.
type RulesetExport struct {
	Name         string            `json:"name"`
	BypassActors []json.RawMessage `json:"bypass_actors"`
}

// Export is the file a repo admin commits so CI can see bypass lists.
type Export struct {
	GeneratedAt time.Time                           `json:"generated_at"`
	GeneratedBy string                              `json:"generated_by"`
	Repos       map[string]map[string]RulesetExport `json:"repos"`
}

// loadExport reads the export if present, and names the commit behind it when
// the run happens in CI.
func loadExport(ctx context.Context, cl *gh.Client, s connector.Scope) (*Export, string) {
	data, err := os.ReadFile(filepath.Join(s.Project.Dir, ExportFile))
	if err != nil {
		return nil, ""
	}
	var exp Export
	if err := json.Unmarshal(data, &exp); err != nil {
		return nil, ""
	}
	detail := "exported by " + exp.GeneratedBy
	if s.Getenv != nil {
		if owner, repo, ok := strings.Cut(s.Getenv("GITHUB_REPOSITORY"), "/"); ok {
			commits, _, err := cl.Repositories.ListCommits(ctx, owner, repo, &gh.CommitsListOptions{
				Path: ".firedrill/" + ExportFile, PerPage: 1,
			})
			if err == nil && len(commits) > 0 {
				detail = fmt.Sprintf("commit %s by %s", commits[0].GetSHA(), commits[0].GetCommit().GetCommitter().GetName())
			}
		}
	}
	return &exp, detail
}

// ExportRulesets reads every listed repo's rulesets as the current user, who must
// be a repo admin for the bypass lists to be returned, and writes the export.
func (c *Connector) ExportRulesets(ctx context.Context, s connector.Scope) (string, int, error) {
	cl, err := c.client(s)
	if err != nil {
		return "", 0, err
	}
	owner := s.Project.Config.GitHub.Org
	me, _, err := cl.Users.Get(ctx, "")
	if err != nil {
		return "", 0, fmt.Errorf("read the current user: %w", err)
	}
	exp := Export{GeneratedAt: s.Now.UTC(), GeneratedBy: me.GetLogin(), Repos: map[string]map[string]RulesetExport{}}
	count := 0
	for _, name := range s.Project.Config.GitHub.Repos {
		sets, resp, err := cl.Repositories.GetAllRulesets(ctx, owner, name, &gh.RepositoryListRulesetsOptions{IncludesParents: new(true)})
		if notFound(resp) {
			continue
		}
		if err != nil {
			return "", 0, fmt.Errorf("list rulesets of %s: %w", name, err)
		}
		repoSets := map[string]RulesetExport{}
		for _, rs := range sets {
			req, err := cl.NewRequest(ctx, http.MethodGet, fmt.Sprintf("repos/%s/%s/rulesets/%d?includes_parents=true", owner, name, rs.GetID()), nil)
			if err != nil {
				return "", 0, err
			}
			var doc struct {
				Name         string             `json:"name"`
				BypassActors *[]json.RawMessage `json:"bypass_actors"`
			}
			if _, err := cl.Do(req, &doc); err != nil {
				return "", 0, fmt.Errorf("read ruleset of %s: %w", name, err)
			}
			if doc.BypassActors == nil {
				return "", 0, fmt.Errorf("%s: GitHub did not return the bypass list. Run this as a repo admin", name)
			}
			repoSets[fmt.Sprint(rs.GetID())] = RulesetExport{Name: doc.Name, BypassActors: *doc.BypassActors}
			count++
		}
		exp.Repos[owner+"/"+name] = repoSets
	}
	b, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return "", 0, err
	}
	path := filepath.Join(s.Project.Dir, ExportFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", 0, err
	}
	return path, count, os.WriteFile(path, b, 0o644)
}

// RepoIsPublic reads a repo's visibility through the GitHub connection, for the
// check that keeps records out of public repos on a laptop.
func (c *Connector) RepoIsPublic(ctx context.Context, s connector.Scope, owner, repo string) (public, known bool) {
	cl, err := c.client(s)
	if err != nil {
		return false, false
	}
	r, _, err := cl.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return false, false
	}
	return !r.GetPrivate(), true
}
