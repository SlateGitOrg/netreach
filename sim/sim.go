// Package sim is a reference packet simulator: it evaluates ONE concrete flow
// by walking the same checks as the engine with plain per-rule comparisons,
// no interval arithmetic and no header spaces.
//
// It exists to be an independent oracle. Differential tests sample flows and
// assert that the engine's header-space answer (allowed, or blocked at a
// given step and component) agrees with the simulator for every sample. The
// two share only the compiled model; LPM, NACL ordering, security-group
// semantics and the NAT return-port quantifier are implemented separately.
package sim

import (
	"strings"

	"github.com/archit2501/netreach/model"
)

// natPortLo/natPortHi bound the NAT gateway's translated source ports.
const (
	natPortLo = 1024
	natPortHi = model.MaxPort
)

// Verdict is the outcome for one flow. When Allowed is false, Step and
// Component name the check that dropped it (same vocabulary as engine.Step).
type Verdict struct {
	Allowed   bool
	Step      string
	Component string
}

var allowed = Verdict{Allowed: true}

func blocked(step, component string) Verdict { return Verdict{Step: step, Component: component} }

// Packet is a canonical flow; ports are ignored for protocols without ports.
type Packet struct {
	Proto, InitiatorPort, ServicePort uint32
}

func (p Packet) canonical() Packet {
	if !model.HasPorts(p.Proto) {
		p.InitiatorPort, p.ServicePort = 0, 0
	}
	return p
}

// acl evaluates one NACL direction: first matching rule by number wins.
// addr is the address compared with rule CIDRs, port the packet's
// destination port in that direction.
func acl(a *model.ACLNode, inbound bool, addr, proto, port uint32) bool {
	entries := a.Outbound
	if inbound {
		entries = a.Inbound
	}
	best := -1
	for i, e := range entries { // explicit min search: do not rely on sort order
		if e.CIDR.Contains(addr) && e.Match.Matches(proto, port) && (best < 0 || e.Number < entries[best].Number) {
			best = i
		}
	}
	return best >= 0 && entries[best].Allow
}

// sg reports whether any rule of any group admits the flow.
func sg(groups []*model.SGNode, inbound bool, addr, proto, port uint32, peer *model.ENINode,
	groupOK func(*model.SGNode) bool) bool {
	for _, g := range groups {
		rules := g.Outbound
		if inbound {
			rules = g.Inbound
		}
		for _, r := range rules {
			if !r.Match.Matches(proto, port) {
				continue
			}
			if r.HasCIDR && r.CIDR.Contains(addr) {
				return true
			}
			if !r.HasCIDR && peer != nil && r.Group.HasMember(peer) && groupOK(r.Group) {
				return true
			}
		}
	}
	return false
}

func sgIDs(groups []*model.SGNode) string {
	ids := make([]string, len(groups))
	for i, g := range groups {
		ids[i] = g.ID
	}
	return strings.Join(ids, ",")
}

// lpm is an independent longest-prefix match: scan every route, keep the
// longest prefix containing ip.
func lpm(rt *model.RouteTableNode, ip uint32) *model.RouteNode {
	var best *model.RouteNode
	for i := range rt.Routes {
		r := &rt.Routes[i]
		if r.Dest.Contains(ip) && (best == nil || r.Dest.Bits > best.Dest.Bits) {
			best = r
		}
	}
	return best
}

func peered(n *model.Network, x, y *model.VPCNode) bool {
	for _, p := range n.Peerings {
		if p.Active && ((p.A == x && p.B == y) || (p.A == y && p.B == x)) {
			return true
		}
	}
	return false
}

// InternetIngress evaluates a flow from internet address src to target.
func InternetIngress(n *model.Network, src uint32, target *model.ENINode, pkt Packet) Verdict {
	p := pkt.canonical()
	vpc, sub := target.VPC(), target.Subnet
	if vpc.IGW == nil {
		return blocked("internet-gateway", vpc.ID)
	}
	if !target.HasPublicIP {
		return blocked("public-ip", target.ID)
	}
	if !acl(sub.ACL, true, src, p.Proto, p.ServicePort) {
		return blocked("nacl-inbound", sub.ACL.ID)
	}
	if !sg(target.SGs, true, src, p.Proto, p.ServicePort, nil, nil) {
		return blocked("sg-inbound", sgIDs(target.SGs))
	}
	if !acl(sub.ACL, false, src, p.Proto, p.InitiatorPort) {
		return blocked("nacl-outbound-return", sub.ACL.ID)
	}
	if r := lpm(sub.RouteTable, src); r == nil || r.Kind != model.RouteIGW || r.IGW != vpc.IGW {
		return blocked("route-return", sub.RouteTable.ID)
	}
	return allowed
}

// InternalIngress evaluates a flow from ENI src to ENI target.
func InternalIngress(n *model.Network, src, target *model.ENINode, pkt Packet) Verdict {
	p := pkt.canonical()
	sv, tv := src.VPC(), target.VPC()
	ss, ts := src.Subnet, target.Subnet
	sIP, tIP := src.PrivateIP, target.PrivateIP
	cross := ss != ts
	okFrom := func(own *model.VPCNode) func(*model.SGNode) bool {
		return func(g *model.SGNode) bool { return g.VPC == own || peered(n, own, g.VPC) }
	}
	if !sg(src.SGs, false, tIP, p.Proto, p.ServicePort, target, okFrom(sv)) {
		return blocked("sg-outbound", sgIDs(src.SGs))
	}
	if cross && !acl(ss.ACL, false, tIP, p.Proto, p.ServicePort) {
		return blocked("nacl-outbound", ss.ACL.ID)
	}
	r := lpm(ss.RouteTable, tIP)
	fwdOK := r != nil && ((r.Kind == model.RouteLocal && sv == tv) ||
		(r.Kind == model.RoutePeering && r.Peering.Active && sv != tv &&
			((r.Peering.A == sv && r.Peering.B == tv) || (r.Peering.A == tv && r.Peering.B == sv))))
	if !fwdOK {
		return blocked("route", ss.RouteTable.ID)
	}
	if cross && !acl(ts.ACL, true, sIP, p.Proto, p.ServicePort) {
		return blocked("nacl-inbound", ts.ACL.ID)
	}
	if !sg(target.SGs, true, sIP, p.Proto, p.ServicePort, src, okFrom(tv)) {
		return blocked("sg-inbound", sgIDs(target.SGs))
	}
	if cross && !acl(ts.ACL, false, sIP, p.Proto, p.InitiatorPort) {
		return blocked("nacl-outbound-return", ts.ACL.ID)
	}
	r = lpm(ts.RouteTable, sIP)
	retOK := r != nil && ((r.Kind == model.RouteLocal && sv == tv) ||
		(r.Kind == model.RoutePeering && r.Peering.Active && sv != tv &&
			((r.Peering.A == sv && r.Peering.B == tv) || (r.Peering.A == tv && r.Peering.B == sv))))
	if !retOK {
		return blocked("route-return", ts.RouteTable.ID)
	}
	if cross && !acl(ss.ACL, true, tIP, p.Proto, p.InitiatorPort) {
		return blocked("nacl-inbound-return", ss.ACL.ID)
	}
	return allowed
}

// Egress evaluates a flow from ENI src to internet address dst.
func Egress(n *model.Network, src *model.ENINode, dst uint32, pkt Packet) Verdict {
	p := pkt.canonical()
	ss := src.Subnet
	if !sg(src.SGs, false, dst, p.Proto, p.ServicePort, nil, nil) {
		return blocked("sg-outbound", sgIDs(src.SGs))
	}
	r := lpm(ss.RouteTable, dst)
	if r == nil {
		return blocked("route", ss.RouteTable.ID)
	}
	switch r.Kind {
	case model.RouteIGW:
		if !src.HasPublicIP {
			return blocked("public-ip", src.ID)
		}
		if !acl(ss.ACL, false, dst, p.Proto, p.ServicePort) {
			return blocked("nacl-outbound", ss.ACL.ID)
		}
		if !acl(ss.ACL, true, dst, p.Proto, p.InitiatorPort) {
			return blocked("nacl-inbound-return", ss.ACL.ID)
		}
		return allowed
	case model.RouteNAT:
		return natEgress(src, r.NAT, dst, p)
	}
	return blocked("route", ss.RouteTable.ID)
}

func natEgress(src *model.ENINode, nat *model.NATNode, dst uint32, p Packet) Verdict {
	ss, ns := src.Subnet, nat.Subnet
	cross := ss != ns
	if cross {
		if !acl(ss.ACL, false, dst, p.Proto, p.ServicePort) {
			return blocked("nacl-outbound", ss.ACL.ID)
		}
		if !acl(ns.ACL, true, src.PrivateIP, p.Proto, p.ServicePort) {
			return blocked("nat-nacl-inbound", ns.ACL.ID)
		}
	}
	if p.Proto != model.ProtoTCP && p.Proto != model.ProtoUDP && p.Proto != model.ProtoICMP {
		return blocked("nat-gateway", nat.ID)
	}
	if r := lpm(ns.RouteTable, dst); r == nil || r.Kind != model.RouteIGW {
		return blocked("nat-route", ns.RouteTable.ID)
	}
	if !acl(ns.ACL, false, dst, p.Proto, p.ServicePort) {
		return blocked("nat-nacl-outbound", ns.ACL.ID)
	}
	// Brute force over every port the NAT gateway may pick.
	if model.HasPorts(p.Proto) {
		for port := uint32(natPortLo); port <= natPortHi; port++ {
			if !acl(ns.ACL, true, dst, p.Proto, port) {
				return blocked("nat-nacl-inbound-return", ns.ACL.ID)
			}
		}
	} else if !acl(ns.ACL, true, dst, p.Proto, 0) {
		return blocked("nat-nacl-inbound-return", ns.ACL.ID)
	}
	if cross {
		if !acl(ns.ACL, false, src.PrivateIP, p.Proto, p.InitiatorPort) {
			return blocked("nat-nacl-outbound-return", ns.ACL.ID)
		}
		if !acl(ss.ACL, true, dst, p.Proto, p.InitiatorPort) {
			return blocked("nacl-inbound-return", ss.ACL.ID)
		}
	}
	return allowed
}
