// Package aws reads IAM users, roles and access keys in every connected account.
// Calls are checked by action name against a fixed list.
package aws

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/smithy-go/middleware"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// Connector reads AWS IAM.
type Connector struct {
	connector.Base
	// Load returns the SDK config of a profile. Tests replace it.
	Load func(ctx context.Context, profile string) (awssdk.Config, error)
	// ReportWait is how long to wait between credential report polls.
	ReportWait time.Duration
}

// New returns the connector.
func New() *Connector {
	return &Connector{
		Base:       connector.Base{ConnectorName: "aws"},
		ReportWait: 2 * time.Second,
		Load: func(ctx context.Context, profile string) (awssdk.Config, error) {
			return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithSharedConfigProfile(profile), awsconfig.WithRegion("us-east-1"))
		},
	}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	calls := make([]string, 0, len(connector.AWSActions))
	for a := range connector.AWSActions {
		calls = append(calls, a)
	}
	sort.Strings(calls)
	return []connector.Collection{{
		Name:       "iam",
		Nodes:      []string{graph.KindAWSPrincipal, graph.KindAWSKey},
		Permission: strings.Join(calls, ", "),
		Calls:      calls,
	}}
}

// Available is true when a profile is listed.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if len(s.Project.Config.AWS.Accounts) == 0 {
		return false, "connect aws"
	}
	return true, ""
}

// guardMiddleware refuses any action outside the list, whatever HTTP method the
// SDK uses.
func guardMiddleware(log *connector.CallLog) func(*middleware.Stack) error {
	return func(st *middleware.Stack) error {
		return st.Initialize.Add(middleware.InitializeMiddlewareFunc("FiredrillGuard",
			func(ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler) (middleware.InitializeOutput, middleware.Metadata, error) {
				op := awsmiddleware.GetOperationName(ctx)
				if err := connector.CheckAWS(log, "iam:"+op); err != nil {
					return middleware.InitializeOutput{}, middleware.Metadata{}, err
				}
				return next.HandleInitialize(ctx, in)
			}), middleware.Before)
	}
}

// ClientFor returns an IAM client behind the guard.
func ClientFor(cfg awssdk.Config, log *connector.CallLog) *iam.Client {
	return iam.NewFromConfig(cfg, func(o *iam.Options) {
		o.APIOptions = append(o.APIOptions, guardMiddleware(log))
	})
}

// Collect reads every connected account.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	for _, acct := range s.Project.Config.AWS.Accounts {
		cfg, err := c.Load(ctx, acct.Profile)
		if err != nil {
			return fmt.Errorf("aws profile %s: %w", acct.Profile, err)
		}
		if err := c.collectAccount(ctx, ClientFor(cfg, s.Log), s, out); err != nil {
			return fmt.Errorf("aws profile %s: %w", acct.Profile, err)
		}
	}
	return nil
}

func (c *Connector) collectAccount(ctx context.Context, cl *iam.Client, s connector.Scope, out graph.Writer) error {
	details, err := authDetails(ctx, cl)
	if err != nil {
		return err
	}
	managed := map[string]string{}
	for _, p := range details.policies {
		for _, v := range p.PolicyVersionList {
			if v.IsDefaultVersion {
				managed[awssdk.ToString(p.Arn)] = awssdk.ToString(v.Document)
			}
		}
	}
	groups := map[string]types.GroupDetail{}
	for _, g := range details.groups {
		groups[awssdk.ToString(g.GroupName)] = g
	}
	report, err := c.credentialReport(ctx, cl)
	if err != nil {
		return err
	}
	breakGlass := map[string]bool{}
	for _, a := range s.Project.Config.AWS.BreakGlass {
		breakGlass[a] = true
	}
	for _, u := range details.users {
		name, account := awssdk.ToString(u.UserName), accountOf(awssdk.ToString(u.Arn))
		var docs []string
		var arns []string
		for _, p := range u.UserPolicyList {
			docs = append(docs, awssdk.ToString(p.PolicyDocument))
		}
		for _, p := range u.AttachedManagedPolicies {
			arns = append(arns, awssdk.ToString(p.PolicyArn))
		}
		for _, gn := range u.GroupList {
			g := groups[gn]
			for _, p := range g.GroupPolicyList {
				docs = append(docs, awssdk.ToString(p.PolicyDocument))
			}
			for _, p := range g.AttachedManagedPolicies {
				arns = append(arns, awssdk.ToString(p.PolicyArn))
			}
		}
		flags := analyze(docs, arns, managed)
		lastUsed := report[name]
		keys := []any{}
		pager := iam.NewListAccessKeysPaginator(cl, &iam.ListAccessKeysInput{UserName: u.UserName})
		for pager.HasMorePages() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return err
			}
			for _, k := range page.AccessKeyMetadata {
				id := awssdk.ToString(k.AccessKeyId)
				keys = append(keys, id)
				last, err := cl.GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: k.AccessKeyId})
				if err != nil {
					return err
				}
				if last.AccessKeyLastUsed != nil && last.AccessKeyLastUsed.LastUsedDate != nil {
					lastUsed = later(lastUsed, *last.AccessKeyLastUsed.LastUsedDate)
				}
				keyNode := graph.ID("aws:key/" + id)
				out.Node(graph.Node{ID: keyNode, Kind: graph.KindAWSKey, Source: "aws", SeenAt: s.Now,
					Attrs: map[string]any{"key_id": id, "account": account, "user": name}})
				out.Edge(graph.Edge{From: graph.ID("aws:iam-user/" + account + "/" + name), To: keyNode, Kind: graph.EdgeHolds, Source: "aws"})
			}
		}
		out.Node(graph.Node{ID: graph.ID("aws:iam-user/" + account + "/" + name), Kind: graph.KindAWSPrincipal, Source: "aws", SeenAt: s.Now, Attrs: map[string]any{
			"account": account, "principal_kind": "user", "name": name, "last_used": stamp(lastUsed), "created": stamp(awssdk.ToTime(u.CreateDate)),
			"keys": keys, "is_admin": flags.admin, "destructive_actions": flags.destructive, "excluded": breakGlass[awssdk.ToString(u.Arn)],
		}})
	}
	for _, r := range details.roles {
		name, arn := awssdk.ToString(r.RoleName), awssdk.ToString(r.Arn)
		account := accountOf(arn)
		var docs, arns []string
		for _, p := range r.RolePolicyList {
			docs = append(docs, awssdk.ToString(p.PolicyDocument))
		}
		for _, p := range r.AttachedManagedPolicies {
			arns = append(arns, awssdk.ToString(p.PolicyArn))
		}
		flags := analyze(docs, arns, managed)
		var last time.Time
		if r.RoleLastUsed != nil {
			last = awssdk.ToTime(r.RoleLastUsed.LastUsedDate)
		}
		excluded := breakGlass[arn] || strings.HasPrefix(name, "AWSReservedSSO_") ||
			strings.HasPrefix(awssdk.ToString(r.Path), "/aws-reserved/") || strings.HasPrefix(awssdk.ToString(r.Path), "/aws-service-role/")
		out.Node(graph.Node{ID: graph.ID("aws:iam-role/" + account + "/" + name), Kind: graph.KindAWSPrincipal, Source: "aws", SeenAt: s.Now, Attrs: map[string]any{
			"account": account, "principal_kind": "role", "name": name, "last_used": stamp(last), "created": stamp(awssdk.ToTime(r.CreateDate)),
			"keys": []any{}, "is_admin": flags.admin, "destructive_actions": flags.destructive, "excluded": excluded,
		}})
	}
	return nil
}

type authResult struct {
	users    []types.UserDetail
	roles    []types.RoleDetail
	groups   []types.GroupDetail
	policies []types.ManagedPolicyDetail
}

func authDetails(ctx context.Context, cl *iam.Client) (*authResult, error) {
	res := &authResult{}
	pager := iam.NewGetAccountAuthorizationDetailsPaginator(cl, &iam.GetAccountAuthorizationDetailsInput{})
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		res.users = append(res.users, page.UserDetailList...)
		res.roles = append(res.roles, page.RoleDetailList...)
		res.groups = append(res.groups, page.GroupDetailList...)
		res.policies = append(res.policies, page.Policies...)
	}
	return res, nil
}

// credentialReport returns each user's last password use.
func (c *Connector) credentialReport(ctx context.Context, cl *iam.Client) (map[string]time.Time, error) {
	for attempt := 0; ; attempt++ {
		gen, err := cl.GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{})
		if err != nil {
			return nil, err
		}
		if gen.State == types.ReportStateTypeComplete {
			break
		}
		if attempt >= 10 {
			return nil, fmt.Errorf("the credential report did not finish")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(c.ReportWait):
		}
	}
	rep, err := cl.GetCredentialReport(ctx, &iam.GetCredentialReportInput{})
	if err != nil {
		return nil, err
	}
	return parseReport(string(rep.Content))
}

func parseReport(content string) (map[string]time.Time, error) {
	rows, err := csv.NewReader(strings.NewReader(content)).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("credential report: %w", err)
	}
	out := map[string]time.Time{}
	if len(rows) == 0 {
		return out, nil
	}
	userCol, passCol := -1, -1
	for i, h := range rows[0] {
		switch h {
		case "user":
			userCol = i
		case "password_last_used":
			passCol = i
		}
	}
	if userCol < 0 || passCol < 0 {
		return nil, fmt.Errorf("credential report: missing columns")
	}
	for _, r := range rows[1:] {
		if t, err := time.Parse(time.RFC3339, r[passCol]); err == nil {
			out[r[userCol]] = t
		}
	}
	return out, nil
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func accountOf(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}

type policyFlags struct {
	admin       bool
	destructive []any
}

var destructivePrefixes = []string{"delete", "terminate", "drop", "destroy", "purge"}

// analyze reads Allow statements from policy documents. It takes no account of
// Deny statements, permission boundaries or SCPs, so it can overstate what a
// principal can do. Policy simulation arrives in v0.2.
func analyze(docs, arns []string, managed map[string]string) policyFlags {
	var f policyFlags
	found := map[string]bool{}
	all := append([]string(nil), docs...)
	for _, arn := range arns {
		if strings.HasSuffix(arn, "/AdministratorAccess") {
			f.admin = true
		}
		if d, ok := managed[arn]; ok {
			all = append(all, d)
		}
	}
	for _, d := range all {
		if decoded, err := url.QueryUnescape(d); err == nil {
			d = decoded
		}
		var doc struct {
			Statement json.RawMessage `json:"Statement"`
		}
		if json.Unmarshal([]byte(d), &doc) != nil {
			continue
		}
		var stmts []struct {
			Effect   string          `json:"Effect"`
			Action   json.RawMessage `json:"Action"`
			Resource json.RawMessage `json:"Resource"`
		}
		if json.Unmarshal(doc.Statement, &stmts) != nil {
			var one struct {
				Effect   string          `json:"Effect"`
				Action   json.RawMessage `json:"Action"`
				Resource json.RawMessage `json:"Resource"`
			}
			if json.Unmarshal(doc.Statement, &one) != nil {
				continue
			}
			stmts = append(stmts[:0], one)
		}
		for _, st := range stmts {
			if !strings.EqualFold(st.Effect, "Allow") {
				continue
			}
			resources := stringOrList(st.Resource)
			for _, action := range stringOrList(st.Action) {
				lower := strings.ToLower(action)
				if (lower == "*" || lower == "*:*") && contains(resources, "*") {
					f.admin = true
				}
				if lower == "iam:*" {
					f.admin = true
				}
				if isDestructive(lower) {
					found[action] = true
				}
			}
		}
	}
	names := make([]string, 0, len(found))
	for a := range found {
		names = append(names, a)
	}
	sort.Strings(names)
	f.destructive = make([]any, len(names))
	for i, n := range names {
		f.destructive[i] = n
	}
	return f
}

// isDestructive matches a destructive action, or a wildcard covering one.
func isDestructive(action string) bool {
	if action == "*" || action == "*:*" {
		return true
	}
	_, op, ok := strings.Cut(action, ":")
	if !ok {
		return false
	}
	if op == "*" {
		return true
	}
	for _, p := range destructivePrefixes {
		if strings.HasPrefix(op, p) {
			return true
		}
		// A wildcard such as s3:Del* or *Delete* covers destructive actions.
		if strings.Contains(op, "*") {
			stem := strings.Trim(op, "*")
			if stem == "" || strings.HasPrefix(p, stem) || strings.Contains(stem, p) {
				return true
			}
		}
	}
	return false
}

func stringOrList(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
