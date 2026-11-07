// Package dns reads CNAMEs and proves domain ownership through a TXT record.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/sk1122/firedrill/connector"
	"github.com/sk1122/firedrill/internal/graph"
)

// Resolver is what the connector needs from DNS.
type Resolver interface {
	// CNAME returns the name a host points to, or "" when it has no CNAME.
	CNAME(ctx context.Context, host string) (string, error)
	// Resolves says whether a name has any address.
	Resolves(ctx context.Context, host string) (bool, error)
	TXT(ctx context.Context, host string) ([]string, error)
}

// Connector reads DNS.
type Connector struct {
	connector.Base
	Resolver Resolver
}

// New returns the connector with the system resolver.
func New() *Connector {
	return &Connector{ConnectorName: "dns", Resolver: System{}}
}

func init() { connector.Register(New()) }

// Collections lists what it reads.
func (c *Connector) Collections() []connector.Collection {
	return []connector.Collection{{Name: "cnames", Nodes: []string{graph.KindCNAME, graph.KindDNSRecord},
		Calls: []string{"DNS CNAME and address lookups for each host in public certificates on verified domains"}}}
}

// Available is true when a domain is verified, or a drill names a host.
func (c *Connector) Available(s connector.Scope) (bool, string) {
	if len(s.VerifiedDomains) == 0 && len(s.DNSHosts) == 0 {
		return false, "verify-domain"
	}
	return true, ""
}

// Collect looks up every host certificate logs named, and any named by a drill.
func (c *Connector) Collect(ctx context.Context, _ connector.Collection, s connector.Scope, out graph.Writer) error {
	reader, ok := out.(graph.Reader)
	if !ok {
		return errors.New("dns: the graph is not readable")
	}
	for _, domain := range s.VerifiedDomains {
		inspected, failures := 0, 0
		for _, h := range reader.Nodes(graph.KindHost) {
			if h.Attrs["domain"] != domain {
				continue
			}
			host, _ := h.Attrs["host"].(string)
			target, err := c.Resolver.CNAME(ctx, host)
			if err != nil {
				failures++
				continue
			}
			inspected++
			if target == "" {
				continue
			}
			resolves, err := c.Resolver.Resolves(ctx, target)
			if err != nil {
				failures++
				continue
			}
			id := graph.ID("dns-cname:" + host)
			out.Node(graph.Node{ID: id, Kind: graph.KindCNAME, Source: "dns", SeenAt: s.Now,
				Attrs: map[string]any{"domain": domain, "host": host, "target": target, "target_resolves": resolves}})
			out.Edge(graph.Edge{From: graph.ID("host:" + host), To: graph.ID("host:" + target), Kind: graph.EdgePointsTo, Source: "dns"})
		}
		partial := ""
		if failures > 0 {
			partial = fmt.Sprintf("%d DNS lookups failed", failures)
		}
		graph.WriteScan(out, "dns", "dns", domain, inspected, partial, s.Now)
	}
	for _, host := range s.DNSHosts {
		target, err := c.Resolver.CNAME(ctx, host)
		if err != nil {
			return fmt.Errorf("dns %s: %w", host, err)
		}
		resolves, err := c.Resolver.Resolves(ctx, host)
		if err != nil {
			return fmt.Errorf("dns %s: %w", host, err)
		}
		txt, err := c.Resolver.TXT(ctx, host)
		if err != nil {
			return fmt.Errorf("dns %s: %w", host, err)
		}
		list := make([]any, len(txt))
		for i, v := range txt {
			list[i] = v
		}
		out.Node(graph.Node{ID: graph.ID("dns:" + host), Kind: graph.KindDNSRecord, Source: "dns", SeenAt: s.Now,
			Attrs: map[string]any{"cname": target, "resolves": resolves, "txt": list}})
	}
	return nil
}

// VerifyRecord names where a domain's proof lives.
func VerifyRecord(domain string) string { return "_firedrill." + domain }

// VerifyValue is the value a domain publishes. It comes from the org's salt, so
// it needs no stored state and matches on every machine holding the salt.
func VerifyValue(h graph.Hasher, domain string) string {
	return "firedrill-verify=" + h.Sum("verify-domain:"+strings.ToLower(domain))
}

// VerifyDomains returns the domains whose TXT record is in place. It runs at the
// start of every run, so removing the record stops web checks.
func VerifyDomains(ctx context.Context, r Resolver, h graph.Hasher, domains []string) []string {
	var out []string
	for _, d := range domains {
		if IsVerified(ctx, r, h, d) {
			out = append(out, d)
		}
	}
	return out
}

// IsVerified checks one domain.
func IsVerified(ctx context.Context, r Resolver, h graph.Hasher, domain string) bool {
	txt, err := r.TXT(ctx, VerifyRecord(domain))
	if err != nil {
		return false
	}
	want := VerifyValue(h, domain)
	return slices.Contains(txt, want)
}

// System uses the machine's DNS configuration.
type System struct{}

// Resolves says whether a name has any address.
func (System) Resolves(ctx context.Context, host string) (bool, error) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return false, nil
		}
		return false, err
	}
	return len(addrs) > 0, nil
}

// TXT returns a name's TXT records.
func (System) TXT(ctx context.Context, host string) ([]string, error) {
	txt, err := net.DefaultResolver.LookupTXT(ctx, host)
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return nil, nil
		}
		return nil, err
	}
	return txt, nil
}

// CNAME asks the DNS server directly. The standard library's lookup fails on a
// CNAME whose target does not resolve, which is exactly the case to find.
func (System) CNAME(ctx context.Context, host string) (string, error) {
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return "", err
	}
	id := uint16(time.Now().UnixNano())
	msg := dnsmessage.Message{
		ID: id, RecursionDesired: true,
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return "", err
	}
	var d net.Dialer
	var lastErr error
	for _, server := range servers() {
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := d.DialContext(dctx, "udp", server)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		target, err := exchange(dctx, conn, packed, id)
		_ = conn.Close()
		cancel()
		if err == nil {
			return target, nil
		}
		lastErr = err
	}
	return "", lastErr
}

func exchange(ctx context.Context, conn net.Conn, packed []byte, id uint16) (string, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if _, err := conn.Write(packed); err != nil {
		return "", err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		return "", err
	}
	if resp.ID != id {
		return "", errors.New("DNS reply did not match the query")
	}
	if resp.RCode != dnsmessage.RCodeSuccess && resp.RCode != dnsmessage.RCodeNameError {
		return "", fmt.Errorf("DNS error %s", resp.RCode)
	}
	for _, a := range resp.Answers {
		if c, ok := a.Body.(*dnsmessage.CNAMEResource); ok {
			return strings.TrimSuffix(c.CNAME.String(), "."), nil
		}
	}
	return "", nil
}

// servers reads the system resolver list, falling back to a public one where
// there is no resolv.conf, as on Windows.
func servers() []string {
	var out []string
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for line := range strings.SplitSeq(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[0] == "nameserver" {
				out = append(out, net.JoinHostPort(f[1], "53"))
			}
		}
	}
	if len(out) == 0 {
		out = []string{"1.1.1.1:53"}
	}
	return out
}
