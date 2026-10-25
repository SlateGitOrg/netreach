package engine

import (
	"fmt"
	"strings"

	"github.com/archit2501/netreach/hspace"
	"github.com/archit2501/netreach/interval"
	"github.com/archit2501/netreach/model"
)

// Warning is a configuration smell found without running a query: rules that
// can never take effect, and gateways or addresses that cannot work.
type Warning struct {
	Component string `json:"component"`
	Message   string `json:"message"`
}

func (w Warning) String() string { return w.Component + ": " + w.Message }

// Lint inspects the network for dead rules and broken gateway setups.
//
// A NACL entry is shadowed when every flow it matches is already decided by
// lower-numbered entries; a security group rule is redundant when earlier
// CIDR rules of the same group and direction already admit everything it
// admits. Both are exact header-space subset tests, not heuristics.
func Lint(n *model.Network) []Warning {
	var out []Warning
	for _, acl := range n.ACLs {
		out = append(out, lintACL(acl, Inbound, acl.Inbound)...)
		out = append(out, lintACL(acl, Outbound, acl.Outbound)...)
	}
	for _, sg := range n.SGs {
		out = append(out, lintSG(sg, Inbound, sg.Inbound)...)
		out = append(out, lintSG(sg, Outbound, sg.Outbound)...)
	}
	for _, nat := range n.NATs {
		if r := defaultRoute(nat.Subnet.RouteTable); r == nil || r.Kind != model.RouteIGW {
			out = append(out, Warning{Component: nat.ID,
				Message: "its subnet " + nat.Subnet.ID + " has no default route to an internet gateway, so it cannot reach the internet"})
		}
	}
	for _, e := range n.ENIs {
		if e.HasPublicIP && e.VPC().IGW == nil {
			out = append(out, Warning{Component: e.ID,
				Message: "has public IP " + interval.FormatIPv4(e.PublicIP) + " but vpc " + e.VPC().ID + " has no internet gateway"})
		}
	}
	for _, g := range n.IGWs {
		if g.VPC == nil {
			out = append(out, Warning{Component: g.ID, Message: "is not attached to any VPC"})
		}
	}
	return out
}

func defaultRoute(rt *model.RouteTableNode) *model.RouteNode {
	for i := range rt.Routes {
		if rt.Routes[i].Dest.Bits == 0 {
			return &rt.Routes[i]
		}
	}
	return nil
}

func lintACL(acl *model.ACLNode, dir Direction, entries []model.ACLEntryNode) []Warning {
	var out []Warning
	decided := emptyFlowSpace
	var earlier []model.ACLEntryNode
	for _, e := range entries {
		region := matchRegion(e.Match, e.CIDR.Set(), DimServicePort)
		if region.SubsetOf(decided) {
			out = append(out, Warning{Component: acl.ID, Message: fmt.Sprintf(
				"%s rule %d (%s %s) is shadowed: earlier rule(s) %s decide every flow it matches",
				dir, e.Number, e.Action(), e.Match, overlapping(region, earlier))})
		}
		decided = decided.Union(region)
		earlier = append(earlier, e)
	}
	return out
}

func overlapping(region hspace.Space, earlier []model.ACLEntryNode) string {
	var nums []string
	for _, e := range earlier {
		if !matchRegion(e.Match, e.CIDR.Set(), DimServicePort).Intersect(region).IsEmpty() {
			nums = append(nums, fmt.Sprint(e.Number))
		}
	}
	return strings.Join(nums, ", ")
}

func lintSG(sg *model.SGNode, dir Direction, rules []model.SGRuleNode) []Warning {
	var out []Warning
	covered := emptyFlowSpace
	for _, r := range rules {
		if !r.HasCIDR {
			continue // group references depend on membership; not comparable
		}
		region := matchRegion(r.Match, r.CIDR.Set(), DimServicePort)
		if region.SubsetOf(covered) {
			out = append(out, Warning{Component: sg.ID, Message: fmt.Sprintf(
				"%s rule #%d (%s %s %s) is redundant: earlier rules already allow it", dir, r.Index, r.Match,
				dir.peerWord(), r.CIDR)})
		}
		covered = covered.Union(region)
	}
	return out
}
