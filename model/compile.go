package model

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/SlateGitOrg/netreach/interval"
)

// ValidationError lists every problem found in a snapshot.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("invalid snapshot (%d problems):\n  - %s", len(e.Problems), strings.Join(e.Problems, "\n  - "))
}

type compiler struct {
	snap     *Snapshot
	net      *Network
	problems []string
}

func (c *compiler) fail(format string, args ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, args...))
}

// Compile validates s and resolves it into a Network. All problems are
// collected and returned together in a *ValidationError.
func Compile(s *Snapshot) (*Network, error) {
	c := &compiler{snap: s, net: &Network{Name: s.Name, Description: s.Description, byID: map[string]any{}}}
	c.vpcs()
	c.igws()
	c.peerings()
	c.acls()
	c.securityGroups()
	c.routeTablesShell()
	c.subnets()
	c.nats()
	c.routes()
	c.enis()
	c.sgRules()
	if len(c.problems) > 0 {
		return nil, &ValidationError{Problems: c.problems}
	}
	return c.net, nil
}

func (c *compiler) register(kind, id string, obj any) bool {
	if id == "" {
		c.fail("%s with empty id", kind)
		return false
	}
	if _, dup := c.net.byID[id]; dup {
		c.fail("duplicate id %q", id)
		return false
	}
	c.net.byID[id] = obj
	return true
}

func lookup[T any](c *compiler, owner, field, id string) T {
	var zero T
	obj, ok := c.net.byID[id]
	if !ok {
		c.fail("%s: %s references unknown id %q", owner, field, id)
		return zero
	}
	t, ok := obj.(T)
	if !ok {
		c.fail("%s: %s %q has the wrong type", owner, field, id)
		return zero
	}
	return t
}

func (c *compiler) vpcs() {
	var all []struct {
		cidr interval.CIDR
		vpc  string
	}
	for _, v := range c.snap.VPCs {
		node := &VPCNode{ID: v.ID}
		if !c.register("vpc", v.ID, node) {
			continue
		}
		if len(v.CIDRs) == 0 {
			c.fail("vpc %s: no CIDR blocks", v.ID)
		}
		for _, text := range v.CIDRs {
			cidr, err := interval.ParseCIDR(text)
			if err != nil {
				c.fail("vpc %s: %v", v.ID, err)
				continue
			}
			for _, other := range all {
				if !other.cidr.Set().Intersect(cidr.Set()).IsEmpty() {
					c.fail("vpc %s: CIDR %s overlaps %s of %s (VPC CIDRs must be unique in a snapshot)",
						v.ID, cidr, other.cidr, other.vpc)
				}
			}
			all = append(all, struct {
				cidr interval.CIDR
				vpc  string
			}{cidr, v.ID})
			node.CIDRs = append(node.CIDRs, cidr)
			node.Space = node.Space.Union(cidr.Set())
		}
		c.net.VPCs = append(c.net.VPCs, node)
	}
}

func (c *compiler) igws() {
	for _, g := range c.snap.InternetGateways {
		node := &IGWNode{ID: g.ID}
		if !c.register("internet gateway", g.ID, node) {
			continue
		}
		if g.VPC != "" {
			node.VPC = lookup[*VPCNode](c, "internet gateway "+g.ID, "vpc", g.VPC)
			if node.VPC != nil {
				if node.VPC.IGW != nil {
					c.fail("vpc %s has two internet gateways (%s, %s)", node.VPC.ID, node.VPC.IGW.ID, g.ID)
				}
				node.VPC.IGW = node
			}
		}
		c.net.IGWs = append(c.net.IGWs, node)
	}
}

func (c *compiler) peerings() {
	for _, p := range c.snap.Peerings {
		node := &PeeringNode{ID: p.ID}
		if !c.register("peering", p.ID, node) {
			continue
		}
		owner := "peering " + p.ID
		node.A = lookup[*VPCNode](c, owner, "requesterVpc", p.RequesterVPC)
		node.B = lookup[*VPCNode](c, owner, "accepterVpc", p.AccepterVPC)
		switch p.Status {
		case "", "active":
			node.Active = true
		case "pending-acceptance", "rejected", "deleted", "failed", "expired":
		default:
			c.fail("%s: unknown status %q", owner, p.Status)
		}
		if node.A != nil && node.A == node.B {
			c.fail("%s: a VPC cannot peer with itself", owner)
		}
		c.net.Peerings = append(c.net.Peerings, node)
	}
}

func (c *compiler) acls() {
	for _, a := range c.snap.NetworkACLs {
		node := &ACLNode{ID: a.ID}
		if !c.register("network acl", a.ID, node) {
			continue
		}
		node.VPC = lookup[*VPCNode](c, "network acl "+a.ID, "vpc", a.VPC)
		node.Inbound = c.aclEntries(a.ID, "inbound", a.Inbound)
		node.Outbound = c.aclEntries(a.ID, "outbound", a.Outbound)
		c.net.ACLs = append(c.net.ACLs, node)
	}
}

func (c *compiler) aclEntries(id, dir string, entries []ACLEntry) []ACLEntryNode {
	seen := map[int]bool{}
	out := make([]ACLEntryNode, 0, len(entries))
	for _, e := range entries {
		owner := fmt.Sprintf("network acl %s %s rule %d", id, dir, e.RuleNumber)
		if e.RuleNumber < 1 || e.RuleNumber > 32766 {
			c.fail("%s: rule number must be 1-32766", owner)
			continue
		}
		if seen[e.RuleNumber] {
			c.fail("%s: duplicate rule number", owner)
			continue
		}
		seen[e.RuleNumber] = true
		m, err := ParseMatch(e.Protocol, e.Ports)
		if err != nil {
			c.fail("%s: %v", owner, err)
			continue
		}
		cidr, err := interval.ParseCIDR(e.CIDR)
		if err != nil {
			c.fail("%s: %v", owner, err)
			continue
		}
		var allow bool
		switch strings.ToLower(e.Action) {
		case "allow":
			allow = true
		case "deny":
		default:
			c.fail("%s: action must be allow or deny, got %q", owner, e.Action)
			continue
		}
		out = append(out, ACLEntryNode{Number: e.RuleNumber, Allow: allow, Match: m, CIDR: cidr})
	}
	slices.SortFunc(out, func(a, b ACLEntryNode) int { return cmp.Compare(a.Number, b.Number) })
	return out
}

func (c *compiler) securityGroups() {
	for _, g := range c.snap.SecurityGroups {
		node := &SGNode{ID: g.ID}
		if !c.register("security group", g.ID, node) {
			continue
		}
		node.VPC = lookup[*VPCNode](c, "security group "+g.ID, "vpc", g.VPC)
		c.net.SGs = append(c.net.SGs, node)
	}
}

// sgRules runs after every group is registered so rules may reference any group.
func (c *compiler) sgRules() {
	for _, g := range c.snap.SecurityGroups {
		node, ok := c.net.byID[g.ID].(*SGNode)
		if !ok {
			continue
		}
		node.Inbound = c.sgRuleList(node, "inbound", g.Inbound)
		node.Outbound = c.sgRuleList(node, "outbound", g.Outbound)
	}
}

func (c *compiler) sgRuleList(sg *SGNode, dir string, rules []SGRule) []SGRuleNode {
	out := make([]SGRuleNode, 0, len(rules))
	for i, r := range rules {
		owner := fmt.Sprintf("security group %s %s rule #%d", sg.ID, dir, i+1)
		m, err := ParseMatch(r.Protocol, r.Ports)
		if err != nil {
			c.fail("%s: %v", owner, err)
			continue
		}
		node := SGRuleNode{Index: i + 1, Match: m, Description: r.Description}
		switch {
		case r.CIDR != "" && r.Group != "":
			c.fail("%s: set exactly one of cidr and group", owner)
			continue
		case r.CIDR != "":
			cidr, err := interval.ParseCIDR(r.CIDR)
			if err != nil {
				c.fail("%s: %v", owner, err)
				continue
			}
			node.HasCIDR, node.CIDR = true, cidr
		case r.Group != "":
			node.Group = lookup[*SGNode](c, owner, "group", r.Group)
			if node.Group == nil {
				continue
			}
		default:
			c.fail("%s: set exactly one of cidr and group", owner)
			continue
		}
		out = append(out, node)
	}
	return out
}

func (c *compiler) routeTablesShell() {
	for _, rt := range c.snap.RouteTables {
		node := &RouteTableNode{ID: rt.ID}
		if !c.register("route table", rt.ID, node) {
			continue
		}
		node.VPC = lookup[*VPCNode](c, "route table "+rt.ID, "vpc", rt.VPC)
		c.net.RouteTables = append(c.net.RouteTables, node)
	}
}

func (c *compiler) subnets() {
	for _, s := range c.snap.Subnets {
		node := &SubnetNode{ID: s.ID}
		if !c.register("subnet", s.ID, node) {
			continue
		}
		owner := "subnet " + s.ID
		node.VPC = lookup[*VPCNode](c, owner, "vpc", s.VPC)
		node.RouteTable = lookup[*RouteTableNode](c, owner, "routeTable", s.RouteTable)
		node.ACL = lookup[*ACLNode](c, owner, "networkAcl", s.NetworkACL)
		cidr, err := interval.ParseCIDR(s.CIDR)
		if err != nil {
			c.fail("%s: %v", owner, err)
		}
		node.CIDR = cidr
		if node.VPC == nil {
			continue
		}
		if err == nil && !cidr.Set().SubsetOf(node.VPC.Space) {
			c.fail("%s: CIDR %s is outside vpc %s", owner, cidr, node.VPC.ID)
		}
		if node.RouteTable != nil && node.RouteTable.VPC != node.VPC {
			c.fail("%s: route table %s belongs to another VPC", owner, node.RouteTable.ID)
		}
		if node.ACL != nil && node.ACL.VPC != node.VPC {
			c.fail("%s: network acl %s belongs to another VPC", owner, node.ACL.ID)
		}
		for _, other := range node.VPC.Subnets {
			if err == nil && !other.CIDR.Set().Intersect(cidr.Set()).IsEmpty() {
				c.fail("%s: CIDR %s overlaps subnet %s", owner, cidr, other.ID)
			}
		}
		node.VPC.Subnets = append(node.VPC.Subnets, node)
		c.net.Subnets = append(c.net.Subnets, node)
	}
}

func (c *compiler) nats() {
	for _, n := range c.snap.NATGateways {
		node := &NATNode{ID: n.ID}
		if !c.register("nat gateway", n.ID, node) {
			continue
		}
		owner := "nat gateway " + n.ID
		node.Subnet = lookup[*SubnetNode](c, owner, "subnet", n.Subnet)
		var err error
		if node.PrivateIP, err = interval.ParseIPv4(n.PrivateIP); err != nil {
			c.fail("%s: privateIp: %v", owner, err)
		} else if node.Subnet != nil && !node.Subnet.CIDR.Contains(node.PrivateIP) {
			c.fail("%s: private IP %s is outside subnet %s", owner, n.PrivateIP, node.Subnet.ID)
		}
		if node.PublicIP, err = interval.ParseIPv4(n.PublicIP); err != nil {
			c.fail("%s: publicIp: %v", owner, err)
		}
		c.net.NATs = append(c.net.NATs, node)
	}
}

// routes resolves explicit routes and adds the implicit local routes.
func (c *compiler) routes() {
	for _, rt := range c.snap.RouteTables {
		node, ok := c.net.byID[rt.ID].(*RouteTableNode)
		if !ok || node.VPC == nil {
			continue
		}
		owner := "route table " + rt.ID
		seen := map[interval.CIDR]bool{}
		for _, cidr := range node.VPC.CIDRs {
			node.Routes = append(node.Routes, RouteNode{Dest: cidr, Kind: RouteLocal, Target: "local"})
			seen[cidr] = true
		}
		for _, r := range rt.Routes {
			dest, err := interval.ParseCIDR(r.Destination)
			if err != nil {
				c.fail("%s: %v", owner, err)
				continue
			}
			if r.Target == "local" {
				if !slices.Contains(node.VPC.CIDRs, dest) {
					c.fail("%s: local route %s does not match a VPC CIDR", owner, dest)
				}
				continue // implicit route already present
			}
			if seen[dest] {
				c.fail("%s: duplicate route for %s", owner, dest)
				continue
			}
			seen[dest] = true
			if dest.Set().SubsetOf(node.VPC.Space) {
				c.fail("%s: route %s -> %s is more specific than the VPC's local route (not modelled)",
					owner, dest, r.Target)
				continue
			}
			route := RouteNode{Dest: dest, Target: r.Target}
			if !c.resolveTarget(owner, node.VPC, &route) {
				continue
			}
			node.Routes = append(node.Routes, route)
		}
		slices.SortFunc(node.Routes, func(a, b RouteNode) int {
			if a.Dest.Bits != b.Dest.Bits {
				return cmp.Compare(b.Dest.Bits, a.Dest.Bits)
			}
			return cmp.Compare(a.Dest.Addr, b.Dest.Addr)
		})
	}
}

func (c *compiler) resolveTarget(owner string, vpc *VPCNode, route *RouteNode) bool {
	if route.Target == "blackhole" {
		route.Kind = RouteBlackhole
		return true
	}
	switch t := c.net.byID[route.Target].(type) {
	case *IGWNode:
		if t.VPC != vpc {
			c.fail("%s: route to %s, which is not attached to vpc %s", owner, t.ID, vpc.ID)
			return false
		}
		route.Kind, route.IGW = RouteIGW, t
	case *NATNode:
		if t.Subnet != nil && t.Subnet.VPC != vpc {
			c.fail("%s: route to %s in another VPC", owner, t.ID)
			return false
		}
		route.Kind, route.NAT = RouteNAT, t
	case *PeeringNode:
		if t.A != vpc && t.B != vpc {
			c.fail("%s: route to %s, which does not involve vpc %s", owner, t.ID, vpc.ID)
			return false
		}
		route.Kind, route.Peering = RoutePeering, t
	default:
		c.fail("%s: unsupported route target %q (want an internet gateway, NAT gateway, peering connection or blackhole)",
			owner, route.Target)
		return false
	}
	return true
}

func (c *compiler) enis() {
	privateIPs := map[uint32]string{}
	for _, e := range c.snap.ENIs {
		node := &ENINode{ID: e.ID, Name: e.Name, Instance: e.Instance}
		if !c.register("eni", e.ID, node) {
			continue
		}
		owner := "eni " + e.ID
		node.Subnet = lookup[*SubnetNode](c, owner, "subnet", e.Subnet)
		ip, err := interval.ParseIPv4(e.PrivateIP)
		switch {
		case err != nil:
			c.fail("%s: privateIp: %v", owner, err)
		case node.Subnet != nil && !node.Subnet.CIDR.Contains(ip):
			c.fail("%s: private IP %s is outside subnet %s", owner, e.PrivateIP, node.Subnet.ID)
		case privateIPs[ip] != "":
			c.fail("%s: private IP %s already used by %s", owner, e.PrivateIP, privateIPs[ip])
		default:
			privateIPs[ip] = e.ID
		}
		node.PrivateIP = ip
		if e.PublicIP != "" {
			if node.PublicIP, err = interval.ParseIPv4(e.PublicIP); err != nil {
				c.fail("%s: publicIp: %v", owner, err)
			}
			node.HasPublicIP = true
		}
		if len(e.SecurityGroups) == 0 {
			c.fail("%s: at least one security group is required", owner)
		}
		for _, id := range e.SecurityGroups {
			sg := lookup[*SGNode](c, owner, "securityGroups", id)
			if sg == nil {
				continue
			}
			if node.Subnet != nil && sg.VPC != node.Subnet.VPC {
				c.fail("%s: security group %s belongs to another VPC", owner, id)
			}
			node.SGs = append(node.SGs, sg)
			sg.Members = append(sg.Members, node)
		}
		if node.Subnet == nil {
			continue
		}
		c.net.ENIs = append(c.net.ENIs, node)
	}
	slices.SortFunc(c.net.ENIs, func(a, b *ENINode) int { return cmp.Compare(a.ID, b.ID) })
}

// IsValidation reports whether err is (or wraps) a *ValidationError.
func IsValidation(err error) bool {
	var v *ValidationError
	return errors.As(err, &v)
}
