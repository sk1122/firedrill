package graph

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Change types, in the order a reader should see them.
const (
	ChangeNewAdmin   = "new_admin"
	ChangeNewKey     = "new_key"
	ChangeSecretSeen = "secret_new_place"
	ChangeBypassOn   = "bypass_on"
	// ChangeBypassActor is a new can_bypass edge: someone, or an app, can now
	// skip review on a repo.
	ChangeBypassActor = "new_bypass_actor"
	ChangeDeployPath  = "new_deploy_path"
	ChangeMCPServer   = "new_mcp_server"
	ChangeOAuthGrant  = "new_oauth_grant"
	ChangePublic      = "new_public"
	ChangeWeakened    = "protection_weakened"
	ChangeAdded       = "added"
	ChangeChanged     = "changed"
	ChangeRemoved     = "removed"
)

var changeRank = map[string]int{
	ChangeNewAdmin: 0, ChangeNewKey: 1, ChangeSecretSeen: 2, ChangeBypassOn: 3, ChangeBypassActor: 4, ChangeDeployPath: 5,
	ChangeMCPServer: 6, ChangePublic: 7, ChangeOAuthGrant: 8, ChangeWeakened: 9, ChangeAdded: 10, ChangeChanged: 11, ChangeRemoved: 12,
}

var changeLabels = map[string]string{
	ChangeNewAdmin: "New admin", ChangeNewKey: "New key held", ChangeSecretSeen: "Secret seen in a new place",
	ChangeBypassOn: "Bypass turned on", ChangeBypassActor: "New bypass actor", ChangeDeployPath: "New deploy path", ChangeMCPServer: "New MCP server",
	ChangeOAuthGrant: "New OAuth grant",
	ChangePublic:     "New public thing", ChangeWeakened: "Protection weakened", ChangeAdded: "Added",
	ChangeChanged: "Changed", ChangeRemoved: "Removed",
}

// ChangeLabel names a change type in plain words.
func ChangeLabel(t string) string {
	if l, ok := changeLabels[t]; ok {
		return l
	}
	return t
}

// ChangeRank orders change types, most worth reading first.
func ChangeRank(t string) int {
	if r, ok := changeRank[t]; ok {
		return r
	}
	return len(changeRank)
}

// DiffResult is what changed between two snapshots.
type DiffResult struct {
	From    time.Time `json:"from"`
	To      time.Time `json:"to"`
	Changes []Change  `json:"changes"`
	// Skipped names what was not compared and why, so an outage never reads as
	// everything gone and then everything new.
	Skipped []string `json:"skipped"`
}

// Change is one difference. Summary is one plain line that never holds a
// secret value or an email.
type Change struct {
	Type      string `json:"type"`
	Summary   string `json:"summary"`
	Subject   ID     `json:"subject"`
	Kind      string `json:"kind"`
	Attr      string `json:"attr,omitempty"`
	Edge      *Edge  `json:"edge,omitempty"`
	Before    any    `json:"before,omitempty"`
	After     any    `json:"after,omitempty"`
	System    string `json:"system"`
	Weakening bool   `json:"weakening"`
	// Person and CaughtBy are filled by the run layer, never by Diff.
	Person   string     `json:"person,omitempty"`
	CaughtBy []DrillRef `json:"caught_by,omitempty"`
}

// DrillRef names a drill verdict that also caught a change.
type DrillRef struct {
	Drill  string `json:"drill"`
	Target string `json:"target,omitempty"`
}

// Counts returns how many changes weaken the setup and how many do not.
func (d DiffResult) Counts() (weakening, other int) {
	for _, c := range d.Changes {
		if c.Weakening {
			weakening++
		} else {
			other++
		}
	}
	return weakening, other
}

// stableAttrs is the one table of what the diff compares, per node kind. Only
// attributes that change when someone changes the setup are listed: times,
// day counts and counters change every run and are never compared. A kind with
// an empty list is compared by existence only. Kinds not listed are ignored:
// scan records, failures, file contents, Semgrep findings, people (they show
// through same_person edges), web responses, DNS records looked up for a drill,
// config targets and domains, CODEOWNERS, HR leavers and MCP server nodes
// (agent_config.mcp_servers already names each server). A manifest's
// new_install_scripts is left out: it is worked out against the previous run,
// and install_scripts already shows each change.
var stableAttrs = map[string][]string{
	KindIdentityUser: {"is_admin", "is_delegated_admin", "suspended", "mfa_enrolled", "mfa_enforced"},
	// keys is left out: each key is its own aws_key node with a holds edge.
	KindAWSPrincipal: {"is_admin", "destructive_actions", "excluded", "github_oidc", "github_oidc_unscoped"},
	KindAWSKey:       {},
	KindBranchRule:   {"required_approvals", "dismiss_stale", "code_owner_review", "bypass", "force_push_allowed", "deletion_allowed"},
	KindEnvironment:  {"required_reviewers", "prevent_self_review", "admin_bypass", "protected_branches_only"},
	KindActionsPerms: {"can_approve_pull_requests", "default_token_permission"},
	KindGitHubRepo:   {"private"},
	KindAgentConfig:  {"allowed_commands", "denied_commands", "deny_read_paths", "unguarded_destructive", "mcp_servers", "gitignored"},
	KindWorkflow: {"permissions", "triggers", "secrets", "unpinned_actions", "pull_request_target_checkout",
		"unfrozen_installs", "cloud_key_secrets", "uses_oidc"},
	KindManifest:   {"manager", "lockfile", "lockfile_committed", "install_scripts", "install_scripts_known"},
	KindGCPBinding: {"conditional"},
	KindGCPBucket:  {"public_grants", "public_access_prevention", "uniform_access"},
	KindGCPKey:     {"disabled"},
	KindGCPProject: {"member_domains"},
	KindCNAME:      {"target", "target_resolves"},
	KindHost:       {},
	KindSourceMap:  {},
	KindAPIDoc:     {},
	KindTFBucket:   {"public_acl", "public_policy", "public_access_block"},
	KindConfigHost: {"owner"},
	// The line is left out: an edit above a secret is not a change.
	KindSecretSeen: {"agent_readable"},
	// scopes is left out: sensitive_scopes shows each change that matters, and
	// user_count is a counter. Each person who granted it is a granted_to edge.
	KindOAuthApp: {"sensitive_scopes"},
	KindDatabase: {"production", "automated_backups", "retention_days", "deletion_protection", "separate_copy"},
	// limit_scope is left out: capped shows a cap that went away.
	KindAIKey:        {"status", "has_owner", "capped"},
	KindConfigApp:    {"owner", "reviewed"},
	KindConfigBackup: {"copy_location", "owner"},
	KindConfigAIKey:  {"owner", "monthly_limit_usd"},
	// GitHub people. Who can reach a repo is in their edges: member_of,
	// admin_of, writes_to and can_bypass.
	KindGitHubUser: {"org_role", "site_admin", "type"},
	KindGitHubTeam: {"privacy", "parent"},
	KindGitHubApp:  {},
	KindDeployKey:  {},
}

// Compared reports whether the diff compares a node kind.
func Compared(kind string) bool {
	_, ok := stableAttrs[kind]
	return ok
}

// Diff compares two snapshots. It reads only the attributes in stableAttrs,
// only what both runs read, and keys a secret occurrence by fingerprint, repo
// and file rather than line. The result is sorted: weakenings first, then by
// type, then by subject.
func Diff(old, new Snapshot) DiffResult {
	res := DiffResult{From: old.Time, To: new.Time, Changes: []Change{}, Skipped: []string{}}
	oc, nc := coverageOf(old), coverageOf(new)
	skips := map[string]string{}
	covered := func(sc scope) bool {
		a, b := oc.state(sc), nc.state(sc)
		if a == stateRead && b == stateRead {
			return true
		}
		var parts []string
		if a != stateRead {
			parts = append(parts, a.words(sc)+" in the earlier run")
		}
		if b != stateRead {
			parts = append(parts, b.words(sc)+" in the later run")
		}
		skips[sc.label()] = sc.label() + ": " + strings.Join(parts, " and ")
		return false
	}

	oldNodes, newNodes := keyedNodes(old), keyedNodes(new)
	added, removed := map[ID]bool{}, map[ID]bool{}
	for _, k := range unionKeys(oldNodes, newNodes) {
		a, inOld := oldNodes[k]
		b, inNew := newNodes[k]
		switch {
		case inOld && inNew:
			if !covered(nodeScope(b)) {
				continue
			}
			res.Changes = append(res.Changes, compareNode(a, b)...)
		case inNew:
			if !covered(nodeScope(b)) {
				continue
			}
			added[k] = true
			res.Changes = append(res.Changes, addedNode(b))
		default:
			if !covered(nodeScope(a)) {
				continue
			}
			removed[k] = true
			res.Changes = append(res.Changes, removedNode(a))
		}
	}

	oldEdges, newEdges := edgeSet(old), edgeSet(new)
	dropNode := map[ID]bool{}
	edgeChange := func(e Edge, isNew bool) {
		if !covered(edgeScope(e, old, new)) {
			return
		}
		nodes := removed
		if isNew {
			nodes = added
		}
		switch {
		case e.Kind == EdgeFoundIn && nodes[ID(string(e.From)+"@"+strings.TrimPrefix(string(e.To), "file:"))]:
			return // the occurrence tells it
		case e.Kind == EdgeDeploysTo && nodes[e.To]:
			dropNode[e.To] = true // the deploy path tells it better than a new environment
		case isNew && e.Source == "github" && (e.Kind == EdgeAdminOf || e.Kind == EdgeWritesTo || e.Kind == EdgeCanBypass):
			// A new account's power is worth its own row: the node only says
			// someone appeared.
		case nodes[e.From] || nodes[e.To]:
			return // the node tells it
		}
		res.Changes = append(res.Changes, edgeDiff(e, isNew, new, old))
	}
	for _, e := range newEdges {
		if _, ok := oldEdges[e]; !ok {
			edgeChange(e, true)
		}
	}
	for _, e := range oldEdges {
		if _, ok := newEdges[e]; !ok {
			edgeChange(e, false)
		}
	}
	outsideWithWrite(res.Changes, new)
	if len(dropNode) > 0 {
		kept := res.Changes[:0]
		for _, c := range res.Changes {
			if c.Edge == nil && c.Attr == "" && dropNode[c.Subject] {
				continue
			}
			kept = append(kept, c)
		}
		res.Changes = kept
	}

	for i := range res.Changes {
		res.Changes[i].Summary = noEmails(res.Changes[i].Summary)
	}
	SortChanges(res.Changes)
	for _, s := range skips {
		res.Skipped = append(res.Skipped, s)
	}
	sort.Strings(res.Skipped)
	return res
}

// SortChanges orders changes: weakenings first, then by type, then subject.
func SortChanges(cs []Change) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Weakening != b.Weakening {
			return a.Weakening
		}
		if ra, rb := ChangeRank(a.Type), ChangeRank(b.Type); ra != rb {
			return ra < rb
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		if a.Attr != b.Attr {
			return a.Attr < b.Attr
		}
		return a.Summary < b.Summary
	})
}

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

// noEmails keeps addresses out of a summary. People are hashed IDs, and a
// service account address is replaced too, to be safe.
func noEmails(s string) string { return emailRe.ReplaceAllString(s, "[address]") }

// ---- coverage

type state int

const (
	stateRead state = iota
	stateAbsent
	stateFailed
	statePartial
)

func (s state) words(sc scope) string {
	switch s {
	case stateFailed:
		if sc.source == "gcp" && sc.name != "" {
			return "could not be read"
		}
		return "failed"
	case statePartial:
		return "read only in part"
	}
	if sc.source == "files" && sc.name != "" {
		return "not scanned"
	}
	return "not read"
}

// scope is what one node or edge depends on having been read: a whole
// connector, or one repo, project or domain of it.
type scope struct {
	source, scanner, name string
}

func (s scope) label() string {
	if s.name == "" {
		return s.source
	}
	return s.source + " " + s.name
}

type coverage struct {
	explicit       bool
	read, failed   map[string]bool
	present        map[string]bool
	scans          map[ID]Node
	projects       map[string]Node
	inferredFailed map[string]bool
}

func coverageOf(s Snapshot) *coverage {
	c := &coverage{read: map[string]bool{}, failed: map[string]bool{}, present: map[string]bool{},
		scans: map[ID]Node{}, projects: map[string]Node{}, inferredFailed: map[string]bool{}}
	if s.Coverage != nil {
		c.explicit = true
		for _, n := range s.Coverage.Read {
			c.read[n] = true
		}
		for _, n := range s.Coverage.Failed {
			c.failed[n] = true
		}
	}
	for _, n := range s.Nodes {
		switch n.Kind {
		case KindScan:
			c.scans[n.ID] = n
		case KindConnectorFail:
			name, _ := n.Attrs["connector"].(string)
			if name == "" {
				name = n.Source
			}
			c.inferredFailed[name] = true
			continue
		case KindGCPProject:
			name, _ := n.Attrs["name"].(string)
			c.projects[name] = n
		}
		c.present[n.Source] = true
	}
	return c
}

// sourceState says whether a whole connector was read. The link step joins
// Google accounts to people, so it counts as read when Google was.
func (c *coverage) sourceState(source string) state {
	if source == "link" {
		source = "google"
	}
	if c.explicit {
		switch {
		case c.failed[source]:
			return stateFailed
		case c.read[source]:
			return stateRead
		}
		return stateAbsent
	}
	switch {
	case c.inferredFailed[source]:
		return stateFailed
	case c.present[source]:
		return stateRead
	}
	return stateAbsent
}

func (c *coverage) state(sc scope) state {
	if sc.name == "" && sc.scanner == "" {
		return c.sourceState(sc.source)
	}
	if sc.source == "gcp" && sc.scanner == "" {
		p, ok := c.projects[sc.name]
		switch {
		case !ok:
			if c.sourceState("gcp") == stateFailed {
				return stateFailed
			}
			return stateAbsent
		case p.Attrs["error"] != nil:
			return stateFailed
		}
		return stateRead
	}
	n, ok := c.scans[ScanID(sc.scanner, sc.name)]
	switch {
	case !ok:
		if c.sourceState(sc.source) == stateFailed {
			return stateFailed
		}
		return stateAbsent
	case n.Attrs["partial"] != nil && n.Attrs["partial"] != "":
		return statePartial
	}
	return stateRead
}

// domainScanner names the scanner that covers a domain-scoped kind.
var domainScanner = map[string]string{
	KindHost: "ctlog", KindCNAME: "dns", KindSourceMap: "web_source_maps", KindAPIDoc: "web_api_docs",
}

func nodeScope(n Node) scope {
	if sc, ok := domainScanner[n.Kind]; ok {
		d, _ := n.Attrs["domain"].(string)
		return scope{source: n.Source, scanner: sc, name: d}
	}
	// These are read by their own collection, which records its scan per
	// profile, project or provider, so a collection that failed while the
	// rest of its connector worked never reads as everything gone.
	switch n.Kind {
	case KindOAuthApp:
		return scope{source: n.Source, scanner: "oauth_tokens"}
	case KindAIKey:
		return scope{source: n.Source, scanner: "ai_keys", name: n.Source}
	case KindGitHubUser, KindGitHubTeam, KindGitHubApp, KindDeployKey:
		return scope{source: n.Source, scanner: "github_people", name: str(n, "org")}
	case KindDatabase:
		if n.Source == "gcp" {
			return scope{source: "gcp", scanner: "gcp_backups", name: str(n, "project")}
		}
		return scope{source: n.Source, scanner: n.Source + "_backups", name: str(n, "profile")}
	}
	switch n.Source {
	case "files":
		repo, _ := n.Attrs["repo"].(string)
		scanner := "secrets"
		if n.Kind == KindTFBucket {
			scanner = "terraform"
		}
		return scope{source: "files", scanner: scanner, name: repo}
	case "gcp":
		p, _ := n.Attrs["project"].(string)
		if n.Kind == KindGCPProject {
			p, _ = n.Attrs["name"].(string)
		}
		return scope{source: "gcp", name: p}
	}
	return scope{source: n.Source}
}

func edgeScope(e Edge, old, new Snapshot) scope {
	if e.Kind == EdgeGrantedTo {
		return scope{source: e.Source, scanner: "oauth_tokens"}
	}
	// GitHub people edges depend on the repo's or the org's people record.
	if e.Source == "github" && peopleEdge[e.Kind] {
		to := string(e.To)
		if repo, ok := strings.CutPrefix(to, "github:repo/"); ok {
			return scope{source: "github", scanner: "github_repo_people", name: repo}
		}
		if org, ok := strings.CutPrefix(to, "github:org/"); ok {
			return scope{source: "github", scanner: "github_people", name: org}
		}
		if rest, ok := strings.CutPrefix(to, "github:team/"); ok {
			org, _, _ := strings.Cut(rest, "/")
			return scope{source: "github", scanner: "github_people", name: org}
		}
	}
	switch e.Source {
	case "files":
		repo := repoOfFile(string(e.To), old, new)
		return scope{source: "files", scanner: "secrets", name: repo}
	case "gcp":
		if p, ok := strings.CutPrefix(string(e.From), "gcp:project/"); ok {
			return scope{source: "gcp", name: p}
		}
	case "dns":
		host := strings.TrimPrefix(string(e.From), "host:")
		for _, s := range []Snapshot{new, old} {
			for _, n := range s.Nodes {
				if n.ID == ID("dns-cname:"+host) || (n.Kind == KindHost && n.ID == e.From) {
					d, _ := n.Attrs["domain"].(string)
					return scope{source: "dns", scanner: "dns", name: d}
				}
			}
		}
	}
	return scope{source: e.Source}
}

// peopleEdge are the edges the GitHub people collection writes.
var peopleEdge = map[string]bool{EdgeMemberOf: true, EdgeAdminOf: true, EdgeWritesTo: true, EdgeCanBypass: true}

// repoOfFile finds the repo in file:<repo>/<path>. Repo names hold a slash, so
// it matches against the repos either run scanned, longest first.
func repoOfFile(id string, snaps ...Snapshot) string {
	rest := strings.TrimPrefix(id, "file:")
	best := ""
	for _, s := range snaps {
		for _, n := range s.Nodes {
			if n.Kind != KindScan || n.Source != "files" {
				continue
			}
			repo, _ := n.Attrs["scope"].(string)
			if strings.HasPrefix(rest, repo+"/") && len(repo) > len(best) {
				best = repo
			}
		}
	}
	return best
}

// ---- nodes

// diffKey is how a node is matched across runs. A secret occurrence is keyed
// by fingerprint, repo and file, so a line moving is not a change.
func diffKey(n Node) ID {
	if n.Kind == KindSecretSeen {
		hash, _ := n.Attrs["hash"].(string)
		repo, _ := n.Attrs["repo"].(string)
		file, _ := n.Attrs["file"].(string)
		if hash != "" {
			return ID("secret:" + hash + "@" + repo + "/" + file)
		}
	}
	return n.ID
}

// keyedNodes returns the compared nodes by key. When several occurrences share
// a key, the lowest ID stands for them.
func keyedNodes(s Snapshot) map[ID]Node {
	out := map[ID]Node{}
	for _, n := range s.Nodes {
		if !Compared(n.Kind) {
			continue
		}
		k := diffKey(n)
		if prev, ok := out[k]; ok && prev.ID < n.ID {
			continue
		}
		out[k] = n
	}
	return out
}

func unionKeys(a, b map[ID]Node) []ID {
	seen := map[ID]bool{}
	var out []ID
	for _, m := range []map[ID]Node{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func edgeSet(s Snapshot) map[Edge]Edge {
	out := map[Edge]Edge{}
	for _, e := range s.Edges {
		out[e] = e
	}
	return out
}

func compareNode(a, b Node) []Change {
	var out []Change
	for _, attr := range stableAttrs[b.Kind] {
		if b.Kind == KindGCPBucket && attr == "public_grants" && (a.Attrs["policy_readable"] == false || b.Attrs["policy_readable"] == false) {
			continue // an unreadable policy lists no grants, which is not the same as none
		}
		before, after := norm(a.Attrs[attr]), norm(b.Attrs[attr])
		if same(before, after) {
			continue
		}
		typ, weak, detail := classifyAttr(attr, before, after)
		out = append(out, Change{
			Type: typ, Summary: label(b) + ": " + detail, Subject: b.ID, Kind: b.Kind, Attr: attr,
			Before: before, After: after, System: b.Source, Weakening: weak,
		})
	}
	return out
}

func addedNode(n Node) Change {
	c := Change{Type: ChangeAdded, Subject: n.ID, Kind: n.Kind, System: n.Source, Summary: "new " + label(n)}
	weak := func(t, summary string) { c.Type, c.Weakening, c.Summary = t, true, summary }
	switch n.Kind {
	case KindIdentityUser, KindAWSPrincipal:
		if isTrue(n.Attrs["is_admin"]) || isTrue(n.Attrs["is_delegated_admin"]) {
			weak(ChangeNewAdmin, "new admin: "+label(n))
		}
	case KindAWSKey:
		user, _ := n.Attrs["user"].(string)
		weak(ChangeNewKey, "new "+label(n)+" held by IAM user "+user)
	case KindGCPKey:
		if !isTrue(n.Attrs["disabled"]) {
			weak(ChangeNewKey, "new "+label(n))
		}
	case KindSecretSeen:
		kind, _ := n.Attrs["kind"].(string)
		weak(ChangeSecretSeen, fmt.Sprintf("%s secret seen in a new place: %s", strings.TrimSpace(kind), label(n)))
	case KindWorkflow:
		if hasItem(n.Attrs["triggers"], "pull_request_target") {
			weak(ChangeWeakened, "new "+label(n)+" runs on pull_request_target")
		} else if l := listOf(norm(n.Attrs["cloud_key_secrets"])); len(l) > 0 {
			weak(ChangeWeakened, "new "+label(n)+" uses stored cloud keys: "+strings.Join(l, ", "))
		} else if l := listOf(norm(n.Attrs["unpinned_actions"])); len(l) > 0 {
			weak(ChangeWeakened, "new "+label(n)+" uses unpinned actions: "+strings.Join(l, ", "))
		} else if n.Attrs["permissions"] == "write" {
			weak(ChangeWeakened, "new "+label(n)+" has write permissions")
		}
	case KindManifest:
		if !isTrue(n.Attrs["lockfile_committed"]) {
			weak(ChangeWeakened, "new "+label(n)+" has no committed lockfile")
		}
	case KindAgentConfig:
		if names := serverNames(norm(n.Attrs["mcp_servers"])); len(names) > 0 {
			weak(ChangeMCPServer, "new "+label(n)+" adds MCP servers: "+strings.Join(names, ", "))
		} else if l := listOf(norm(n.Attrs["unguarded_destructive"])); len(l) > 0 {
			weak(ChangeWeakened, "new "+label(n)+" lets an agent run unguarded: "+strings.Join(l, ", "))
		}
	case KindGCPBinding:
		member, _ := n.Attrs["member_type"].(string)
		role, _ := n.Attrs["role"].(string)
		switch {
		case member == "allUsers" || member == "allAuthenticatedUsers":
			weak(ChangePublic, "new public grant: "+label(n))
		case role == "roles/owner" || role == "roles/editor":
			weak(ChangeNewAdmin, "new admin grant: "+label(n))
		}
	case KindGCPBucket:
		if l := listOf(norm(n.Attrs["public_grants"])); len(l) > 0 {
			weak(ChangePublic, "new "+label(n)+" is public: "+strings.Join(l, ", "))
		}
	case KindTFBucket:
		if isTrue(n.Attrs["public_acl"]) || isTrue(n.Attrs["public_policy"]) {
			weak(ChangePublic, "new "+label(n)+" is public")
		}
	case KindSourceMap, KindAPIDoc:
		weak(ChangePublic, "now served: "+label(n))
	case KindGitHubRepo:
		if n.Attrs["private"] == false {
			weak(ChangePublic, "new public "+label(n))
		}
	case KindOAuthApp:
		summary := "new OAuth grant: " + label(n)
		if l := listOf(norm(n.Attrs["sensitive_scopes"])); len(l) > 0 {
			summary += " holds " + strings.Join(l, ", ")
		}
		weak(ChangeOAuthGrant, summary)
	case KindAIKey:
		if n.Attrs["status"] == "active" {
			weak(ChangeNewKey, "new active "+label(n))
		}
	}
	return c
}

func removedNode(n Node) Change {
	c := Change{Type: ChangeRemoved, Subject: n.ID, Kind: n.Kind, System: n.Source, Summary: "gone: " + label(n)}
	// Usually good, but a database, or a copy or limit someone declared, going
	// away is worth a glance: its backups may have gone with it.
	switch n.Kind {
	case KindDatabase:
		c.Type, c.Weakening, c.Summary = ChangeWeakened, true, "gone: "+label(n)+"; check its backups are still there"
	case KindConfigBackup:
		c.Type, c.Weakening, c.Summary = ChangeWeakened, true, "gone: "+label(n)
	case KindConfigAIKey:
		c.Type, c.Weakening, c.Summary = ChangeWeakened, true, "gone: "+label(n)
	}
	return c
}

// ---- edges

func edgeDiff(e Edge, isNew bool, new, old Snapshot) Change {
	ee := e
	c := Change{Subject: e.From, Kind: "edge:" + e.Kind, Edge: &ee, System: e.Source}
	from, to := edgeEnd(e.From, new, old), edgeEnd(e.To, new, old)
	if !isNew {
		c.Type, c.Summary = ChangeRemoved, fmt.Sprintf("gone: %s %s %s", from, edgeWords(e.Kind), to)
		return c
	}
	c.Type, c.Weakening = ChangeAdded, false
	switch e.Kind {
	case EdgeHolds:
		c.Type, c.Weakening, c.Summary = ChangeNewKey, true, fmt.Sprintf("%s now holds %s", from, to)
	case EdgeFoundIn:
		c.Type, c.Weakening, c.Summary = ChangeSecretSeen, true, fmt.Sprintf("%s seen in a new place: %s", from, to)
	case EdgeDeploysTo:
		c.Type, c.Weakening, c.Summary = ChangeDeployPath, true, fmt.Sprintf("new deploy path: %s deploys to %s", from, to)
	case EdgeAdminOf:
		c.Type, c.Weakening, c.Summary = ChangeNewAdmin, true, fmt.Sprintf("%s is now an admin of %s", from, to)
	case EdgeCanBypass:
		c.Type, c.Weakening, c.Summary = ChangeBypassActor, true, fmt.Sprintf("%s can now bypass review on %s", from, to)
	case EdgeWritesTo:
		c.Type, c.Summary = ChangeAdded, fmt.Sprintf("%s can now push to %s", from, to)
		if n, ok := nodeIn(e.From, new); ok && str(n, "org_role") == "outside" {
			c.Type, c.Weakening, c.Summary = ChangeWeakened, true, fmt.Sprintf("outside collaborator %s can now push to %s", from, to)
		}
	case EdgeGrantedTo:
		c.Type, c.Weakening, c.Summary = ChangeOAuthGrant, true, fmt.Sprintf("new OAuth grant: %s granted %s access", to, from)
	default:
		c.Summary = fmt.Sprintf("new link: %s %s %s", from, edgeWords(e.Kind), to)
	}
	return c
}

func edgeWords(kind string) string {
	switch kind {
	case EdgeHolds:
		return "holds"
	case EdgeFoundIn:
		return "found in"
	case EdgeDeploysTo:
		return "deploys to"
	case EdgeSamePerson:
		return "is the same person as"
	case EdgeOwns:
		return "owns"
	case EdgePointsTo:
		return "points to"
	case EdgeMemberOf:
		return "is a member of"
	case EdgeAdminOf:
		return "is an admin of"
	case EdgeGrantedTo:
		return "was granted access by"
	case EdgeWritesTo:
		return "can push to"
	case EdgeCanBypass:
		return "can bypass review on"
	}
	return kind
}

func edgeEnd(id ID, snaps ...Snapshot) string {
	for _, s := range snaps {
		for _, n := range s.Nodes {
			if n.ID == id {
				return label(n)
			}
		}
	}
	return idLabel(id)
}

// idLabel names a node known only by its ID.
func idLabel(id ID) string {
	s := string(id)
	switch {
	case strings.HasPrefix(s, "secret:"):
		return "secret " + short(strings.TrimPrefix(s, "secret:"))
	case strings.HasPrefix(s, "file:"):
		return strings.TrimPrefix(s, "file:")
	case strings.HasPrefix(s, "person:"):
		return "person " + short(strings.TrimPrefix(s, "person:"))
	case strings.HasPrefix(s, "host:"):
		return strings.TrimPrefix(s, "host:")
	case strings.HasPrefix(s, "github:repo/"):
		return "repo " + strings.TrimPrefix(s, "github:repo/")
	case strings.HasPrefix(s, "github:env/"):
		return "environment " + strings.TrimPrefix(s, "github:env/")
	case strings.HasPrefix(s, "github:user/"):
		return "GitHub user " + short(strings.TrimPrefix(s, "github:user/"))
	case strings.HasPrefix(s, "github:org/"):
		return "org " + strings.TrimPrefix(s, "github:org/")
	case strings.HasPrefix(s, "github:team/"):
		return "team " + strings.TrimPrefix(s, "github:team/")
	case strings.HasPrefix(s, "github:app/"):
		return "GitHub app " + strings.TrimPrefix(s, "github:app/")
	case strings.HasPrefix(s, "github:deploy-key/"):
		return "deploy keys of " + strings.TrimPrefix(s, "github:deploy-key/")
	}
	return s
}

// ---- words

func short(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

func str(n Node, k string) string {
	s, _ := n.Attrs[k].(string)
	return s
}

// label names a node in plain words, with no email and no secret value.
func label(n Node) string {
	id := string(n.ID)
	switch n.Kind {
	case KindIdentityUser:
		return "Google user " + short(strings.TrimPrefix(id, "google:user/"))
	case KindAWSPrincipal:
		kind := str(n, "principal_kind")
		if kind == "user" {
			kind = "IAM user"
		} else {
			kind = "IAM " + kind
		}
		return fmt.Sprintf("%s %s in %s", kind, str(n, "name"), str(n, "account"))
	case KindAWSKey:
		return "AWS key " + str(n, "key_id")
	case KindBranchRule:
		return "default branch rule of " + strings.TrimSuffix(strings.TrimPrefix(id, "github:branch-rule/"), "/default")
	case KindEnvironment:
		return "environment " + strings.TrimPrefix(id, "github:env/")
	case KindActionsPerms:
		return "Actions settings of " + strings.TrimPrefix(id, "github:actions/")
	case KindGitHubRepo:
		return "repo " + str(n, "name")
	case KindAgentConfig:
		return "agent config " + str(n, "repo") + "/" + str(n, "file")
	case KindWorkflow:
		return "workflow " + str(n, "repo") + "/" + str(n, "file")
	case KindManifest:
		return str(n, "repo") + "/" + str(n, "file")
	case KindGCPBinding:
		who := str(n, "member_type")
		if who == "allUsers" || who == "allAuthenticatedUsers" {
			return fmt.Sprintf("%s for %s in %s", str(n, "role"), who, str(n, "project"))
		}
		return fmt.Sprintf("%s for a %s (%s) in %s", str(n, "role"), strings.ReplaceAll(who, "_", " "), short(id[strings.LastIndex(id, "/")+1:]), str(n, "project"))
	case KindGCPBucket:
		return "bucket " + str(n, "name")
	case KindGCPKey:
		return fmt.Sprintf("service account key %s in %s", short(str(n, "key_id")), str(n, "project"))
	case KindGCPProject:
		return "GCP project " + str(n, "name")
	case KindCNAME:
		return "CNAME " + str(n, "host")
	case KindHost:
		return "host " + str(n, "host")
	case KindSourceMap:
		return "source map " + str(n, "host") + str(n, "map_url")
	case KindAPIDoc:
		return "API docs " + str(n, "host") + str(n, "path")
	case KindTFBucket:
		return fmt.Sprintf("Terraform bucket %s in %s/%s", str(n, "name"), str(n, "repo"), str(n, "file"))
	case KindConfigHost:
		return "owner of " + str(n, "host")
	case KindSecretSeen:
		return fmt.Sprintf("secret %s in %s/%s", short(str(n, "hash")), str(n, "repo"), str(n, "file"))
	case KindOAuthApp:
		return fmt.Sprintf("OAuth app %s (%s)", str(n, "name"), str(n, "client_id"))
	case KindDatabase:
		where := str(n, "account")
		if p := str(n, "project"); p != "" {
			where = p
		}
		return fmt.Sprintf("%s database %s in %s %s", str(n, "system"), str(n, "name"), where, str(n, "region"))
	case KindAIKey:
		return fmt.Sprintf("%s key %s (%s)", str(n, "provider"), str(n, "key_id"), str(n, "name"))
	case KindConfigApp:
		return "apps.yaml entry for " + str(n, "client_id")
	case KindConfigBackup:
		return "declared copy of database " + str(n, "database")
	case KindConfigAIKey:
		return "ai-keys.yaml entry " + strings.TrimPrefix(id, "config-ai-key:")
	case KindGitHubUser:
		// Never the login: it names a person.
		return "GitHub user " + short(strings.TrimPrefix(id, "github:user/"))
	case KindGitHubTeam:
		return "team " + str(n, "org") + "/" + str(n, "slug")
	case KindGitHubApp:
		if name := str(n, "name"); name != "" {
			return "GitHub app " + name
		}
	case KindDeployKey:
		return "deploy keys of " + strings.TrimPrefix(id, "github:deploy-key/")
	}
	return idLabel(n.ID)
}

// classifyAttr names one attribute change: its type, whether it weakens the
// setup, and a few plain words saying what happened.
func classifyAttr(attr string, before, after any) (string, bool, string) {
	on, off := isTrue(after) && !isTrue(before), isTrue(before) && !isTrue(after)
	added, gone := listDiff(before, after)
	changed := fmt.Sprintf("%s changed from %s to %s", attr, show(before), show(after))
	switch attr {
	case "is_admin":
		if on {
			return ChangeNewAdmin, true, "is now an admin"
		}
		return ChangeChanged, false, "is no longer an admin"
	case "org_role":
		// A new org admin is told by its admin_of edge, and an outside
		// collaborator with write by outsideWithWrite.
		return ChangeChanged, false, fmt.Sprintf("org role changed from %s to %s", show(before), show(after))
	case "site_admin":
		if on {
			return ChangeNewAdmin, true, "is now a site admin"
		}
		return ChangeChanged, false, "is no longer a site admin"
	case "is_delegated_admin":
		if on {
			return ChangeNewAdmin, true, "is now a delegated admin"
		}
		return ChangeChanged, false, "is no longer a delegated admin"
	case "suspended":
		if off {
			return ChangeWeakened, true, "is no longer suspended"
		}
		return ChangeChanged, false, "was suspended"
	case "mfa_enrolled", "mfa_enforced":
		what := map[string]string{"mfa_enrolled": "enrolled in", "mfa_enforced": "required to use"}[attr]
		if off {
			return ChangeWeakened, true, "is no longer " + what + " 2-step verification"
		}
		return ChangeChanged, false, "is now " + what + " 2-step verification"
	case "excluded":
		if on {
			return ChangeWeakened, true, "is now excluded from drills as break-glass"
		}
		return ChangeChanged, false, "is no longer excluded from drills"
	case "required_approvals":
		b, _ := before.(float64)
		a, _ := after.(float64)
		if a < b {
			return ChangeWeakened, true, fmt.Sprintf("required approvals went down from %s to %s", show(before), show(after))
		}
		return ChangeChanged, false, fmt.Sprintf("required approvals went up from %s to %s", show(before), show(after))
	case "dismiss_stale", "code_owner_review", "prevent_self_review", "protected_branches_only", "uniform_access":
		words := map[string]string{
			"dismiss_stale": "stale approvals are dismissed", "code_owner_review": "code owner review is required",
			"prevent_self_review": "self-review is prevented", "protected_branches_only": "only protected branches may deploy",
			"uniform_access": "uniform bucket-level access is on",
		}[attr]
		if off {
			return ChangeWeakened, true, "no longer: " + words
		}
		return ChangeChanged, false, "now: " + words
	case "bypass":
		if after == "allowed" {
			return ChangeBypassOn, true, fmt.Sprintf("bypass is now allowed (was %s)", show(before))
		}
		return ChangeChanged, false, changed
	case "admin_bypass":
		if on {
			return ChangeBypassOn, true, "admins may now bypass its protection rules"
		}
		return ChangeChanged, false, "admins may no longer bypass its protection rules"
	case "force_push_allowed", "deletion_allowed", "can_approve_pull_requests", "pull_request_target_checkout":
		words := map[string]string{
			"force_push_allowed": "force pushes are allowed", "deletion_allowed": "the branch may be deleted",
			"can_approve_pull_requests":    "Actions may approve pull requests",
			"pull_request_target_checkout": "a pull_request_target job checks out the pull request's code",
		}[attr]
		if on {
			return ChangeWeakened, true, "now: " + words
		}
		return ChangeChanged, false, "no longer: " + words
	case "conditional":
		if off {
			return ChangeWeakened, true, "the grant no longer has a condition"
		}
		return ChangeChanged, false, "the grant now has a condition"
	case "public_acl", "public_policy":
		if on {
			return ChangePublic, true, "now has a public " + strings.TrimPrefix(attr, "public_")
		}
		return ChangeChanged, false, "no longer has a public " + strings.TrimPrefix(attr, "public_")
	case "public_access_block":
		if off {
			return ChangePublic, true, "its public access block was removed"
		}
		return ChangeChanged, false, "now has a public access block"
	case "private":
		if off {
			return ChangePublic, true, "is now public"
		}
		return ChangeChanged, false, "is now private"
	case "target_resolves":
		if on {
			return ChangePublic, true, "now resolves"
		}
		if off {
			return ChangeWeakened, true, "its target no longer resolves, so the name can be taken over"
		}
		return ChangeChanged, false, changed
	case "disabled":
		if off {
			return ChangeNewKey, true, "the key was enabled again"
		}
		return ChangeChanged, false, "the key was disabled"
	case "default_token_permission", "permissions":
		if after == "write" || (before == "read" && after == "undeclared") {
			return ChangeWeakened, true, fmt.Sprintf("token permissions went from %s to %s", show(before), show(after))
		}
		return ChangeChanged, false, fmt.Sprintf("token permissions went from %s to %s", show(before), show(after))
	case "public_access_prevention":
		if before == "enforced" {
			return ChangePublic, true, fmt.Sprintf("public access prevention is no longer enforced (now %s)", show(after))
		}
		return ChangeChanged, false, changed
	case "agent_readable":
		if on {
			return ChangeWeakened, true, "an agent can now read it"
		}
		return ChangeChanged, false, "agents can no longer read it"
	case "gitignored":
		if off {
			return ChangeWeakened, true, "is no longer gitignored, so it can be committed"
		}
		return ChangeChanged, false, "is now gitignored"
	case "lockfile_committed":
		if off {
			return ChangeWeakened, true, "its lockfile is no longer committed"
		}
		return ChangeChanged, false, "its lockfile is now committed"
	case "github_oidc_unscoped":
		if on {
			return ChangeWeakened, true, "any GitHub repo outside your org can now assume it"
		}
		return ChangeChanged, false, "its GitHub trust is now scoped to one org"
	case "github_oidc":
		if on {
			return ChangeChanged, false, "now trusts GitHub Actions OIDC tokens"
		}
		return ChangeChanged, false, "no longer trusts GitHub Actions OIDC tokens"
	case "uses_oidc":
		if on {
			return ChangeChanged, false, "now reaches the cloud through OIDC"
		}
		return ChangeChanged, false, "no longer reaches the cloud through OIDC"
	case "install_scripts_known":
		if off {
			return ChangeChanged, false, "its lockfile no longer records install scripts"
		}
		return ChangeChanged, false, "its lockfile now records install scripts"
	case "mcp_servers":
		return classifyServers(before, after)
	case "automated_backups":
		if off {
			return ChangeWeakened, true, "automated backups were turned off"
		}
		return ChangeChanged, false, "automated backups were turned on"
	case "deletion_protection":
		if off {
			return ChangeWeakened, true, "deletion protection was turned off"
		}
		return ChangeChanged, false, "deletion protection was turned on"
	case "retention_days":
		b, _ := before.(float64)
		a, _ := after.(float64)
		if a < b {
			return ChangeWeakened, true, fmt.Sprintf("backup retention went down from %s to %s days", show(before), show(after))
		}
		return ChangeChanged, false, fmt.Sprintf("backup retention went up from %s to %s days", show(before), show(after))
	case "separate_copy":
		if (before == "yes" || before == "declared") && after == "no" {
			return ChangeWeakened, true, fmt.Sprintf("its copy in another account or project is gone (was %s, now no)", show(before))
		}
		return ChangeChanged, false, fmt.Sprintf("separate copy changed from %s to %s", show(before), show(after))
	case "production":
		if on {
			return ChangeChanged, false, "is now production"
		}
		return ChangeChanged, false, "is no longer production"
	case "status":
		if after == "active" {
			return ChangeNewKey, true, fmt.Sprintf("the key is active again (was %s)", show(before))
		}
		return ChangeChanged, false, changed
	case "has_owner":
		if off {
			return ChangeWeakened, true, "it no longer has an owner"
		}
		return ChangeChanged, false, "it now has an owner"
	case "capped":
		if off {
			return ChangeWeakened, true, "its spend cap was removed"
		}
		return ChangeChanged, false, "it is now under a spend cap"
	case "monthly_limit_usd":
		b, _ := before.(float64)
		a, _ := after.(float64)
		if b > 0 && a <= 0 {
			return ChangeWeakened, true, "its declared spend limit was removed"
		}
		return ChangeChanged, false, changed
	}
	// Lists: which direction weakens depends on the list.
	if added != nil || gone != nil {
		parts := []string{}
		if len(added) > 0 {
			parts = append(parts, attr+" added: "+strings.Join(added, ", "))
		}
		if len(gone) > 0 {
			parts = append(parts, attr+" removed: "+strings.Join(gone, ", "))
		}
		detail := strings.Join(parts, "; ")
		switch attr {
		case "triggers":
			if contains(added, "pull_request_target") {
				return ChangeWeakened, true, "now runs on pull_request_target; " + detail
			}
		case "sensitive_scopes":
			if len(added) > 0 {
				return ChangeOAuthGrant, true, "now holds " + strings.Join(added, ", ")
			}
		case "public_grants":
			if len(added) > 0 {
				return ChangePublic, true, "now public to " + strings.Join(added, ", ")
			}
		case "unpinned_actions", "allowed_commands", "unguarded_destructive", "destructive_actions", "member_domains",
			"unfrozen_installs", "cloud_key_secrets", "install_scripts":
			if len(added) > 0 {
				return ChangeWeakened, true, detail
			}
		case "required_reviewers", "denied_commands", "deny_read_paths":
			if len(gone) > 0 {
				return ChangeWeakened, true, detail
			}
		}
		return ChangeChanged, false, detail
	}
	return ChangeChanged, false, changed
}

// classifyServers compares MCP servers by name, then their credentials, host,
// pin and package. A server given a new credential, moved to a host nobody
// owns or allowed, or left unpinned, weakens the setup.
func classifyServers(before, after any) (string, bool, string) {
	byName := func(v any) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, s := range asList(v) {
			m, _ := s.(map[string]any)
			name, _ := m["name"].(string)
			out[name] = m
		}
		return out
	}
	b, a := byName(before), byName(after)
	var added, gone, given, unknownHost, unpinned, unknownPkg, moved []string
	for name, srv := range a {
		old, ok := b[name]
		if !ok {
			added = append(added, name)
			continue
		}
		if more, _ := listDiff(toAny(listOf(old["credentials"])), toAny(listOf(srv["credentials"]))); len(more) > 0 {
			given = append(given, name)
		}
		// A snapshot from before a field existed does not count as a change.
		lost := func(attr string) bool {
			_, had := old[attr]
			return had && isTrue(old[attr]) && !isTrue(srv[attr])
		}
		changed := func(attr string) bool {
			_, had := old[attr]
			return had && canon(old[attr]) != canon(srv[attr])
		}
		switch {
		case srv["transport"] == "http" && (lost("host_known") || (old["transport"] != "http" && srv["host_known"] == false)):
			unknownHost = append(unknownHost, name)
		case lost("pinned"):
			unpinned = append(unpinned, name)
		case lost("package_known"):
			unknownPkg = append(unknownPkg, name)
		case changed("host") || changed("package") || changed("version") || changed("command"):
			moved = append(moved, name)
		}
	}
	for name := range b {
		if _, ok := a[name]; !ok {
			gone = append(gone, name)
		}
	}
	var parts []string
	add := func(words string, names []string) {
		if len(names) > 0 {
			sort.Strings(names)
			parts = append(parts, words+": "+strings.Join(names, ", "))
		}
	}
	add("MCP servers added", added)
	add("MCP servers given a new credential", given)
	add("MCP servers now pointing at a host nobody owns or allowed", unknownHost)
	add("MCP servers no longer pinned", unpinned)
	add("MCP servers now running a package not on the allowlist", unknownPkg)
	add("MCP servers changed", moved)
	add("MCP servers removed", gone)
	if len(parts) == 0 {
		parts = append(parts, "MCP server credentials changed")
	}
	detail := strings.Join(parts, "; ")
	switch {
	case len(added) > 0:
		return ChangeMCPServer, true, detail
	case len(given)+len(unknownHost)+len(unpinned)+len(unknownPkg) > 0:
		return ChangeWeakened, true, detail
	}
	return ChangeChanged, false, detail
}

// ---- values

// norm returns a value as JSON would give it back, so a value from this run
// compares equal to the same value read from a stored snapshot.
func norm(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if json.Unmarshal(b, &out) != nil {
		return v
	}
	return out
}

func canon(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// same compares two values; lists compare as sets, so order never counts.
func same(a, b any) bool {
	la, okA := a.([]any)
	lb, okB := b.([]any)
	if okA && okB {
		x, y := listOf(la), listOf(lb)
		sort.Strings(x)
		sort.Strings(y)
		return canon(x) == canon(y)
	}
	return canon(a) == canon(b)
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func toAny(in []string) []any {
	out := make([]any, len(in))
	for i, v := range in {
		out[i] = v
	}
	return out
}

// listOf turns a list into strings: a string stays itself, anything else
// becomes its JSON.
func listOf(v any) []string {
	var out []string
	for _, x := range asList(v) {
		if s, ok := x.(string); ok {
			out = append(out, s)
		} else {
			out = append(out, canon(x))
		}
	}
	return out
}

// listDiff returns what a list gained and lost, or nil, nil when neither value
// is a list.
func listDiff(before, after any) (added, gone []string) {
	_, okB := before.([]any)
	_, okA := after.([]any)
	if !okA && !okB {
		return nil, nil
	}
	b, a := map[string]bool{}, map[string]bool{}
	for _, s := range listOf(before) {
		b[s] = true
	}
	for _, s := range listOf(after) {
		a[s] = true
	}
	added, gone = []string{}, []string{}
	for s := range a {
		if !b[s] {
			added = append(added, s)
		}
	}
	for s := range b {
		if !a[s] {
			gone = append(gone, s)
		}
	}
	sort.Strings(added)
	sort.Strings(gone)
	return added, gone
}

func serverNames(v any) []string {
	var out []string
	for _, s := range asList(v) {
		m, _ := s.(map[string]any)
		if name, _ := m["name"].(string); name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func isTrue(v any) bool {
	b, _ := v.(bool)
	return b
}

func hasItem(v any, want string) bool { return contains(listOf(norm(v)), want) }

func contains(l []string, want string) bool {
	for _, s := range l {
		if s == want {
			return true
		}
	}
	return false
}

func show(v any) string {
	switch val := v.(type) {
	case nil:
		return "nothing"
	case string:
		if val == "" {
			return "empty"
		}
		return val
	case bool:
		if val {
			return "on"
		}
		return "off"
	case float64:
		return fmt.Sprint(val)
	case []any:
		if len(val) == 0 {
			return "none"
		}
		return strings.Join(listOf(val), ", ")
	}
	return canon(v)
}

// nodeIn finds a node in a snapshot by ID.
func nodeIn(id ID, s Snapshot) (Node, bool) {
	for _, n := range s.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return Node{}, false
}

// outsideWithWrite turns a GitHub user who became an outside collaborator, or
// appeared as one, into a weakening when they can push to or administer a repo.
func outsideWithWrite(cs []Change, new Snapshot) {
	repos := map[ID][]string{}
	for _, e := range new.Edges {
		if e.Kind == EdgeWritesTo || (e.Kind == EdgeAdminOf && strings.HasPrefix(string(e.To), "github:repo/")) {
			repos[e.From] = append(repos[e.From], strings.TrimPrefix(string(e.To), "github:repo/"))
		}
	}
	for i := range cs {
		c := &cs[i]
		if c.Kind != KindGitHubUser || len(repos[c.Subject]) == 0 {
			continue
		}
		became := c.Attr == "org_role" && c.After == "outside"
		if c.Type == ChangeAdded && c.Attr == "" && c.Edge == nil {
			n, _ := nodeIn(c.Subject, new)
			became = str(n, "org_role") == "outside"
		}
		if !became {
			continue
		}
		sort.Strings(repos[c.Subject])
		c.Type, c.Weakening = ChangeWeakened, true
		c.Summary = fmt.Sprintf("GitHub user %s is now an outside collaborator who can push to %s",
			short(strings.TrimPrefix(string(c.Subject), "github:user/")), strings.Join(repos[c.Subject], ", "))
	}
}
