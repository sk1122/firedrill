package google

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	admin "google.golang.org/api/admin/directory/v1"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// GroupsScope is the read-only scope groups.list and members.list accept.
// https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list
// https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/list
const GroupsScope = admin.AdminDirectoryGroupReadonlyScope

// GroupScanner names the scan record of the groups read.
const GroupScanner = "google_groups"

// GroupID names a Google group by its hashed address, as the link step does.
func GroupID(h graph.Hasher, email string) graph.ID {
	return graph.ID("google:group/" + h.Email(email))
}

// UserID names a Google account by its hashed address. A member outside the
// domain gets the same form of ID, with no identity_user node behind it.
func UserID(h graph.Hasher, email string) graph.ID { return graph.ID("google:user/" + h.Email(email)) }

// boundGroups lists the addresses of the groups GCP bindings name. Google
// runs after GCP, so the bindings are already in the graph.
func boundGroups(out graph.Writer) []string {
	reader, ok := out.(graph.Reader)
	if !ok {
		return nil
	}
	set := map[string]bool{}
	// A deleted group keeps its binding but has no members to read.
	for _, n := range reader.Nodes(graph.KindGCPBinding) {
		if t, _ := n.Attrs["member_type"].(string); t != "group" {
			continue
		}
		if e, _ := n.Private["email"].(string); e != "" {
			set[strings.ToLower(e)] = true
		}
	}
	list := make([]string, 0, len(set))
	for e := range set {
		list = append(list, e)
	}
	sort.Strings(list)
	return list
}

type readGroup struct {
	id, email       string
	aliases         []string
	known, allUsers bool
	external        bool
	count           int
	memberEmails    map[string]any // hashed address to address, for the link step
	why             string
}

// collectGroups reads the members of each group a GCP binding names, and of
// each group nested in one, and nothing else: no group's members are read
// unless it gives someone a role. groups.list maps addresses to group IDs, so
// no address reaches a URL or the call log. A missing scope is an error on
// this collection's scan record only; a group that cannot be read leaves its
// members unknown and the result partial.
func (c *Connector) collectGroups(ctx context.Context, s connector.Scope, out graph.Writer) error {
	scan := graph.ScanID(GroupScanner, "")
	writeScan := func(attrs map[string]any) {
		attrs["scanner"], attrs["scope"] = GroupScanner, ""
		out.Node(graph.Node{ID: scan, Kind: graph.KindScan, Source: "google", SeenAt: s.Now, Attrs: attrs})
	}
	bound := boundGroups(out)
	if len(bound) == 0 {
		writeScan(map[string]any{"inspected": int64(0), "note": "no GCP binding names a Google group, so no group was read"})
		return nil
	}
	svc, err := c.service(ctx, s, GroupsScope)
	if err != nil {
		return err
	}
	failed := func(err error) error {
		if errors.Is(err, connector.ErrBlocked) {
			return err
		}
		msg := fmt.Sprintf("could not read Google groups: %v", err)
		if scopeDenied(err) {
			msg += ". Add " + GroupsScope + " to the service account's domain-wide delegation in the Admin console"
		}
		writeScan(map[string]any{"inspected": int64(0), "partial": msg, "error": msg})
		return nil
	}
	byEmail := map[string]*admin.Group{}
	err = svc.Groups.List().Customer("my_customer").MaxResults(200).Pages(ctx, func(p *admin.Groups) error {
		for _, g := range p.Groups {
			for _, e := range append(append([]string{g.Email}, g.Aliases...), g.NonEditableAliases...) {
				byEmail[strings.ToLower(e)] = g
			}
		}
		return nil
	})
	if err != nil {
		return failed(err)
	}

	domains := map[string]bool{}
	for _, d := range append([]string{s.Project.Config.Google.Domain}, s.Project.Config.GCP.MemberDomains...) {
		if d != "" {
			domains[strings.ToLower(d)] = true
		}
	}
	type pending struct{ id, email string }
	var queue []pending
	visited := map[string]bool{}
	groups := []*readGroup{}
	for _, e := range bound {
		g, ok := byEmail[e]
		if !ok {
			groups = append(groups, &readGroup{email: e, why: "the group is not in this Workspace account, so its members cannot be read"})
			continue
		}
		if !visited[g.Id] {
			visited[g.Id] = true
			queue = append(queue, pending{g.Id, strings.ToLower(g.Email)})
		}
	}
	for len(queue) > 0 {
		p := queue[0]
		queue = queue[1:]
		rg := &readGroup{id: p.id, email: p.email, known: true, memberEmails: map[string]any{}}
		if g := byEmail[p.email]; g != nil {
			for _, a := range append(append([]string{}, g.Aliases...), g.NonEditableAliases...) {
				rg.aliases = append(rg.aliases, strings.ToLower(a))
			}
		}
		groups = append(groups, rg)
		parent := GroupID(s.Hasher, p.email)
		// The group ID, never the address, goes in the URL.
		err := svc.Members.List(p.id).MaxResults(200).Pages(ctx, func(page *admin.Members) error {
			for _, m := range page.Members {
				rg.count++
				email := strings.ToLower(m.Email)
				switch m.Type {
				case "CUSTOMER":
					rg.allUsers = true
				case "GROUP":
					out.Edge(graph.Edge{From: GroupID(s.Hasher, email), To: parent, Kind: graph.EdgeMemberOf, Source: "google"})
					if !visited[m.Id] {
						visited[m.Id] = true
						queue = append(queue, pending{m.Id, email})
					}
				default: // USER, and EXTERNAL should Google start using it
					if email == "" {
						continue
					}
					out.Edge(graph.Edge{From: UserID(s.Hasher, email), To: parent, Kind: graph.EdgeMemberOf, Source: "google"})
					rg.memberEmails[s.Hasher.Email(email)] = email
					_, domain, _ := strings.Cut(email, "@")
					if !domains[domain] {
						rg.external = true
					}
				}
			}
			return nil
		})
		switch {
		case err == nil:
		case errors.Is(err, connector.ErrBlocked):
			return err
		default:
			rg.known, rg.why = false, fmt.Sprintf("the members of a group could not be read: %v", err)
		}
	}

	read, unknown := 0, 0
	for _, rg := range groups {
		attrs := map[string]any{"members_known": rg.known, "member_count": int64(rg.count),
			"external_members": rg.external, "all_users": rg.allUsers}
		if rg.known {
			read++
		} else {
			unknown++
			attrs["member_count"] = int64(0)
		}
		out.Node(graph.Node{ID: GroupID(s.Hasher, rg.email), Kind: graph.KindGoogleGroup, Source: "google", SeenAt: s.Now, Attrs: attrs,
			Private: map[string]any{"email": rg.email, "aliases": rg.aliases, "member_emails": rg.memberEmails, "why": rg.why}})
	}
	attrs := map[string]any{"inspected": int64(read)}
	if unknown > 0 {
		attrs["partial"] = fmt.Sprintf("the members of %d of %d groups that hold a GCP role could not be read", unknown, len(groups))
	}
	writeScan(attrs)
	return nil
}
