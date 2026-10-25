package engine

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/archit2501/netreach/hspace"
	"github.com/archit2501/netreach/interval"
	"github.com/archit2501/netreach/model"
)

// Kind is the type of reachability question a Result answers.
type Kind string

// Query kinds.
const (
	// InternetIngress: which flows from an internet address set reach a target ENI.
	InternetIngress Kind = "internet-ingress"
	// InternalIngress: which flows from one ENI reach another ENI.
	InternalIngress Kind = "internal-ingress"
	// InternetEgress: which flows can an ENI open to internet destinations.
	InternetEgress Kind = "internet-egress"
)

// Result is the complete answer for one (source, target) pair: the reachable
// flows split by the path they take, and the unreachable flows split by the
// hop that dropped them. Allowed and Blocked are disjoint and together cover
// the queried flow space.
type Result struct {
	Kind Kind
	// Subject is the analysed ENI: the target for ingress, the source for egress.
	Subject *model.ENINode
	// Peer is the source ENI of an internal-ingress query.
	Peer *model.ENINode
	// Remote is the queried remote address set (internet sources or
	// destinations; the peer's address for internal ingress).
	Remote  interval.Set
	Allowed []Fragment
	Blocked []Fragment
}

// Reachable returns the union of all allowed flows.
func (r *Result) Reachable() hspace.Space {
	out := emptyFlowSpace
	for _, f := range r.Allowed {
		out = out.Union(f.Space)
	}
	return out
}

// Locate finds the fragment containing flow f. found is false when f lies
// outside the queried space (for example a source address not in the query).
func (r *Result) Locate(f Flow) (frag Fragment, allowed, found bool) {
	p := f.Point()
	for _, fr := range r.Allowed {
		if fr.Space.Contains(p...) {
			return fr, true, true
		}
	}
	for _, fr := range r.Blocked {
		if fr.Space.Contains(p...) {
			return fr, false, true
		}
	}
	return Fragment{}, false, false
}

// Analyzer answers reachability queries over one network.
type Analyzer struct {
	net       *model.Network
	log       *slog.Logger
	natReturn map[*model.ACLNode]hspace.Space
}

// New returns an Analyzer. A nil logger discards logs.
func New(net *model.Network, log *slog.Logger) *Analyzer {
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Analyzer{net: net, log: log, natReturn: map[*model.ACLNode]hspace.Space{}}
}

// Network returns the analysed network.
func (a *Analyzer) Network() *model.Network { return a.net }

func (a *Analyzer) finish(r Result, start time.Time) Result {
	a.log.Debug("analysed", "kind", r.Kind, "subject", r.Subject.ID,
		"allowedPaths", len(r.Allowed), "blockedPaths", len(r.Blocked), "elapsed", time.Since(start))
	return r
}

func subnetWhere(s *model.SubnetNode, role string) string {
	return s.ID + ", " + role
}

// InternetIngress computes the flows from sources (internet addresses) that
// reach target through its VPC's internet gateway and public IP.
//
// Path: internet gateway → public IP (1:1 NAT) → subnet NACL inbound →
// security groups inbound → [instance] → subnet NACL outbound (return,
// stateless) → subnet route table (return route must use the same IGW).
func (a *Analyzer) InternetIngress(sources interval.Set, target *model.ENINode) Result {
	start := time.Now()
	vpc, subnet := target.VPC(), target.Subnet
	init := Fragment{Space: Universe().Restrict(DimRemote, sources)}

	igwHop := Hop{Step: StepIGW, Component: vpc.ID, Detail: "vpc " + vpc.ID + " has no attached internet gateway"}
	if vpc.IGW != nil {
		igwHop.Component = vpc.IGW.ID
		igwHop.Detail = "enters vpc " + vpc.ID + " through " + vpc.IGW.ID
	}
	pubHop := Hop{Step: StepPublicIP, Component: target.ID, Detail: target.ID + " has no public IPv4 address"}
	if target.HasPublicIP {
		pubHop.Detail = fmt.Sprintf("public %s maps to private %s", interval.FormatIPv4(target.PublicIP),
			interval.FormatIPv4(target.PrivateIP))
	}
	where := subnetWhere(subnet, "target subnet")
	stages := []stage{
		gate(vpc.IGW != nil, igwHop),
		gate(target.HasPublicIP, pubHop),
		aclStage(aclCheck{step: StepNACLInbound, acl: subnet.ACL, dir: Inbound, addr: RemoteAddr(),
			portDim: DimServicePort, where: where}),
		sgStage(sgCheck{step: StepSGInbound, sgs: target.SGs, dir: Inbound, addr: RemoteAddr()}),
		aclStage(aclCheck{step: StepNACLOutReturn, acl: subnet.ACL, dir: Outbound, addr: RemoteAddr(),
			portDim: DimInitiatorPt, where: where}),
		routeStage(StepRouteReturn, subnet.RouteTable, RemoteAddr(), "the source address",
			func(r *model.RouteNode) (bool, string) {
				if r.Kind == model.RouteIGW && r.IGW == vpc.IGW {
					return true, "return traffic leaves through the internet gateway"
				}
				return false, "return traffic would not leave through " + igwName(vpc) + " (asymmetric path, dropped)"
			}),
	}
	pass, block := run([]Fragment{init}, stages...)
	return a.finish(Result{Kind: InternetIngress, Subject: target, Remote: sources, Allowed: pass, Blocked: block}, start)
}

func igwName(v *model.VPCNode) string {
	if v.IGW == nil {
		return "an internet gateway"
	}
	return v.IGW.ID
}

// peered reports whether an active peering joins x and y.
func (a *Analyzer) peered(x, y *model.VPCNode) bool {
	for _, p := range a.net.Peerings {
		if p.Connects(x, y) {
			return true
		}
	}
	return false
}

// groupRefOK says whether a security group rule in a group of VPC `own` may
// reference group g: same VPC, or a VPC joined by an active peering.
func (a *Analyzer) groupRefOK(own *model.VPCNode) func(*model.SGNode) bool {
	return func(g *model.SGNode) bool { return g.VPC == own || a.peered(own, g.VPC) }
}

// InternalIngress computes the flows src can open to target inside the
// snapshot (same VPC or across an active peering connection).
//
// Path: src security groups outbound → src subnet NACL outbound → src route
// table → target subnet NACL inbound → target security groups inbound →
// target subnet NACL outbound (return) → target route table (return) → src
// subnet NACL inbound (return). NACL checks are skipped when both ENIs share
// a subnet, because NACLs only filter traffic crossing the subnet boundary.
func (a *Analyzer) InternalIngress(src, target *model.ENINode) (Result, error) {
	if src == target {
		return Result{}, fmt.Errorf("source and target are the same interface %s", src.ID)
	}
	return a.internalIngress(src, target), nil
}

func (a *Analyzer) internalIngress(src, target *model.ENINode) Result {
	start := time.Now()
	sv, tv := src.VPC(), target.VPC()
	ss, ts := src.Subnet, target.Subnet
	sIP, tIP := src.PrivateIP, target.PrivateIP
	sameSubnet := ss == ts
	srcWhere, dstWhere := subnetWhere(ss, "source subnet"), subnetWhere(ts, "target subnet")
	init := Fragment{Space: Universe().Restrict(DimRemote, interval.Single(sIP))}

	stages := []stage{
		sgStage(sgCheck{step: StepSGOutbound, sgs: src.SGs, dir: Outbound, addr: FixedAddr(tIP),
			peer: target, groupOK: a.groupRefOK(sv)}),
	}
	if !sameSubnet {
		stages = append(stages, aclStage(aclCheck{step: StepNACLOutbound, acl: ss.ACL, dir: Outbound,
			addr: FixedAddr(tIP), portDim: DimServicePort, where: srcWhere}))
	}
	stages = append(stages, routeStage(StepRoute, ss.RouteTable, FixedAddr(tIP), interval.FormatIPv4(tIP),
		func(r *model.RouteNode) (bool, string) {
			switch {
			case r.Kind == model.RouteLocal && sv == tv:
				return true, ""
			case r.Kind == model.RoutePeering && r.Peering.Connects(sv, tv):
				return true, "peering connects " + sv.ID + " and " + tv.ID
			case r.Kind == model.RoutePeering:
				return false, "peering " + r.Peering.ID + " is inactive or does not reach " + tv.ID
			}
			return false, "does not lead to " + tv.ID
		}))
	if !sameSubnet {
		stages = append(stages, aclStage(aclCheck{step: StepNACLInbound, acl: ts.ACL, dir: Inbound,
			addr: RemoteAddr(), portDim: DimServicePort, where: dstWhere}))
	}
	stages = append(stages, sgStage(sgCheck{step: StepSGInbound, sgs: target.SGs, dir: Inbound,
		addr: RemoteAddr(), peer: src, groupOK: a.groupRefOK(tv)}))
	if !sameSubnet {
		stages = append(stages, aclStage(aclCheck{step: StepNACLOutReturn, acl: ts.ACL, dir: Outbound,
			addr: RemoteAddr(), portDim: DimInitiatorPt, where: dstWhere}))
	}
	stages = append(stages, routeStage(StepRouteReturn, ts.RouteTable, RemoteAddr(), interval.FormatIPv4(sIP),
		func(r *model.RouteNode) (bool, string) {
			switch {
			case r.Kind == model.RouteLocal && sv == tv:
				return true, ""
			case r.Kind == model.RoutePeering && r.Peering.Connects(tv, sv):
				return true, "return over peering"
			}
			return false, "return traffic does not lead back to " + sv.ID
		}))
	if !sameSubnet {
		stages = append(stages, aclStage(aclCheck{step: StepNACLInReturn, acl: ss.ACL, dir: Inbound,
			addr: FixedAddr(tIP), portDim: DimInitiatorPt, where: srcWhere}))
	}
	pass, block := run([]Fragment{init}, stages...)
	return a.finish(Result{Kind: InternalIngress, Subject: target, Peer: src, Remote: interval.Single(sIP),
		Allowed: pass, Blocked: block}, start)
}

// DefaultEgressDestinations is every address outside the snapshot's VPCs.
func (a *Analyzer) DefaultEgressDestinations() interval.Set {
	return a.net.AllVPCSpace().Complement(interval.MaxIPv4)
}

// Egress computes the flows src can open to internet destinations dests,
// either directly through an internet gateway (requires a public IP) or via a
// NAT gateway in another subnet.
func (a *Analyzer) Egress(src *model.ENINode, dests interval.Set) Result {
	start := time.Now()
	ss := src.Subnet
	srcWhere := subnetWhere(ss, "source subnet")
	init := Fragment{Space: Universe().Restrict(DimRemote, dests)}

	split := branch(func(space hspace.Space) []branchPart {
		var out []branchPart
		for _, p := range routeSplit(ss.RouteTable, RemoteAddr(), space) {
			hop := Hop{Step: StepRoute, Component: ss.RouteTable.ID,
				Detail: routeText(ss.RouteTable, p.route, "the destination")}
			part := branchPart{space: p.space, hop: hop}
			switch {
			case p.route == nil:
				part.hop.Detail += "; packet dropped"
			case p.route.Kind == model.RouteIGW:
				part.hop.Allowed = true
				part.then = a.igwEgress(src, srcWhere)
			case p.route.Kind == model.RouteNAT:
				part.hop.Allowed = true
				part.then = a.natEgress(src, p.route.NAT, srcWhere)
			case p.route.Kind == model.RouteBlackhole:
				part.hop.Detail += "; packet dropped"
			default:
				part.hop.Detail += "; destination is internal to the snapshot, not internet egress"
			}
			out = append(out, part)
		}
		return out
	})
	stages := []stage{
		sgStage(sgCheck{step: StepSGOutbound, sgs: src.SGs, dir: Outbound, addr: RemoteAddr()}),
		split,
	}
	pass, block := run([]Fragment{init}, stages...)
	return a.finish(Result{Kind: InternetEgress, Subject: src, Remote: dests, Allowed: pass, Blocked: block}, start)
}

func (a *Analyzer) igwEgress(src *model.ENINode, srcWhere string) []stage {
	ss := src.Subnet
	pubHop := Hop{Step: StepPublicIP, Component: src.ID,
		Detail: src.ID + " has no public IPv4 address; an internet gateway drops its traffic"}
	if src.HasPublicIP {
		pubHop.Detail = fmt.Sprintf("private %s is translated to public %s", interval.FormatIPv4(src.PrivateIP),
			interval.FormatIPv4(src.PublicIP))
	}
	return []stage{
		gate(src.HasPublicIP, pubHop),
		aclStage(aclCheck{step: StepNACLOutbound, acl: ss.ACL, dir: Outbound, addr: RemoteAddr(),
			portDim: DimServicePort, where: srcWhere}),
		gate(true, Hop{Step: StepIGW, Component: ss.VPC.IGW.ID, Detail: "leaves vpc " + ss.VPC.ID + " through " + ss.VPC.IGW.ID}),
		aclStage(aclCheck{step: StepNACLInReturn, acl: ss.ACL, dir: Inbound, addr: RemoteAddr(),
			portDim: DimInitiatorPt, where: srcWhere}),
	}
}

func (a *Analyzer) natEgress(src *model.ENINode, nat *model.NATNode, srcWhere string) []stage {
	ss, ns := src.Subnet, nat.Subnet
	natWhere := subnetWhere(ns, "NAT subnet")
	crosses := ss != ns
	var stages []stage
	if crosses {
		stages = append(stages,
			aclStage(aclCheck{step: StepNACLOutbound, acl: ss.ACL, dir: Outbound, addr: RemoteAddr(),
				portDim: DimServicePort, where: srcWhere}),
			aclStage(aclCheck{step: StepNATNACLInbound, acl: ns.ACL, dir: Inbound, addr: FixedAddr(src.PrivateIP),
				portDim: DimServicePort, where: natWhere}))
	}
	stages = append(stages,
		constrain(Universe().Restrict(DimProto, natProtocols),
			Hop{Step: StepNAT, Component: nat.ID, Detail: fmt.Sprintf("source translated to %s:%s",
				interval.FormatIPv4(nat.PublicIP), NATPortRange)},
			Hop{Step: StepNAT, Component: nat.ID, Detail: "NAT gateways translate only TCP, UDP and ICMP"}),
		routeStage(StepNATRoute, ns.RouteTable, RemoteAddr(), "the destination",
			func(r *model.RouteNode) (bool, string) {
				if r.Kind == model.RouteIGW {
					return true, ""
				}
				return false, "NAT gateway traffic must leave through an internet gateway"
			}),
		aclStage(aclCheck{step: StepNATNACLOutbound, acl: ns.ACL, dir: Outbound, addr: RemoteAddr(),
			portDim: DimServicePort, where: natWhere}),
		constrain(a.natReturnRegion(ns.ACL),
			Hop{Step: StepNATReturnPorts, Component: ns.ACL.ID,
				Detail: fmt.Sprintf("inbound admits replies to every NAT port %s [%s]", NATPortRange, natWhere)},
			Hop{Step: StepNATReturnPorts, Component: ns.ACL.ID,
				Detail: fmt.Sprintf("inbound denies replies to some NAT ports in %s [%s]", NATPortRange, natWhere)}),
	)
	if crosses {
		stages = append(stages,
			aclStage(aclCheck{step: StepNATNACLOutReturn, acl: ns.ACL, dir: Outbound, addr: FixedAddr(src.PrivateIP),
				portDim: DimInitiatorPt, where: natWhere}),
			aclStage(aclCheck{step: StepNACLInReturn, acl: ss.ACL, dir: Inbound, addr: RemoteAddr(),
				portDim: DimInitiatorPt, where: srcWhere}))
	}
	return stages
}

// natProtocols are the protocols a NAT gateway translates.
var natProtocols = model.PortProtocols.Union(interval.Single(model.ProtoICMP))

// natReturnRegion returns the flows whose replies the NAT subnet's inbound
// NACL admits for every port the NAT gateway might have chosen:
//
//	{x : ∀p ∈ NATPortRange. allowed(x with initiator port p)}
//	  = U \ Cylinder_port( (U \ Allowed) ∩ slab )
//
// where slab pins the port dimension to NATPortRange (port 0 for protocols
// without ports). The result does not constrain the initiator port.
func (a *Analyzer) natReturnRegion(acl *model.ACLNode) hspace.Space {
	if r, ok := a.natReturn[acl]; ok {
		return r
	}
	u := Universe()
	allowed := aclAllowed(aclCheck{step: StepNATReturnPorts, acl: acl, dir: Inbound, addr: RemoteAddr(),
		portDim: DimInitiatorPt})
	slab := u.Box(hspace.Box{allIPs, model.PortProtocols, NATPortRange, allPorts}).
		Union(u.Box(hspace.Box{allIPs, nonPortProtos, zeroPort, zeroPort}))
	bad := u.Subtract(allowed).Intersect(slab)
	region := u.Subtract(bad.Cylinder(DimInitiatorPt).Intersect(u))
	a.natReturn[acl] = region
	return region
}

// NATReturnDenied returns the NAT-gateway ports in NATPortRange to which the
// given NACL denies replies from remote over proto (TCP/UDP only; empty for
// other protocols). It refines the explanation of a nat-nacl-inbound-return
// block into concrete ports.
func NATReturnDenied(acl *model.ACLNode, remote, proto uint32) interval.Set {
	if !model.HasPorts(proto) {
		return interval.Set{}
	}
	allowed := aclAllowed(aclCheck{step: StepNATReturnPorts, acl: acl, dir: Inbound, addr: RemoteAddr(),
		portDim: DimInitiatorPt}).
		Restrict(DimRemote, interval.Single(remote)).
		Restrict(DimProto, interval.Single(proto)).
		Project(DimInitiatorPt)
	return NATPortRange.Subtract(allowed)
}

// InternetExposure runs InternetIngress for every ENI.
func (a *Analyzer) InternetExposure(sources interval.Set) []Result {
	out := make([]Result, 0, len(a.net.ENIs))
	for _, e := range a.net.ENIs {
		out = append(out, a.InternetIngress(sources, e))
	}
	return out
}

// ExposureFrom runs InternalIngress from src to every other ENI.
func (a *Analyzer) ExposureFrom(src *model.ENINode) []Result {
	out := make([]Result, 0, len(a.net.ENIs))
	for _, e := range a.net.ENIs {
		if e == src {
			continue
		}
		out = append(out, a.internalIngress(src, e))
	}
	return out
}

// EgressAll runs Egress for every ENI.
func (a *Analyzer) EgressAll(dests interval.Set) []Result {
	out := make([]Result, 0, len(a.net.ENIs))
	for _, e := range a.net.ENIs {
		out = append(out, a.Egress(e, dests))
	}
	return out
}
