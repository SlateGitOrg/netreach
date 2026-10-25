// Package engine computes reachability over a compiled model.Network by
// pushing whole header spaces (sets of flows) through the ordered checks a
// packet meets on its path, splitting them at every rule boundary.
//
// A flow is a point in the 4-dimensional space
//
//	remote IPv4 × IP protocol × initiator port × service port
//
// For ingress analysis the remote address is the flow's source; for egress it
// is the destination. The initiator port is the port on the side that opens
// the connection; the service port is the port it connects to. Protocols
// other than TCP and UDP carry no ports and are pinned to port 0 in both
// port dimensions, so every flow has exactly one canonical point.
package engine

import (
	"github.com/SlateGitOrg/netreach/hspace"
	"github.com/SlateGitOrg/netreach/interval"
	"github.com/SlateGitOrg/netreach/model"
)

// Dimensions of the flow space.
const (
	DimRemote      = 0
	DimProto       = 1
	DimInitiatorPt = 2
	DimServicePort = 3
)

// NATPortRange is the source-port range a NAT gateway translates to. AWS picks
// any port in it, so return traffic must be admitted for all of them.
var NATPortRange = interval.Span(1024, model.MaxPort)

var (
	maxes          = []uint32{interval.MaxIPv4, model.MaxProto, model.MaxPort, model.MaxPort}
	nonPortProtos  = model.PortProtocols.Complement(model.MaxProto)
	allPorts       = interval.Full(model.MaxPort)
	zeroPort       = interval.Single(0)
	allIPs         = interval.Full(interval.MaxIPv4)
	emptyFlowSpace = hspace.Universe(maxes...).Empty()
)

// Universe returns every canonical flow: TCP and UDP with any ports, every
// other protocol with both ports pinned to 0.
func Universe() hspace.Space {
	u := emptyFlowSpace
	u = u.Union(u.Box(hspace.Box{allIPs, model.PortProtocols, allPorts, allPorts}))
	return u.Union(u.Box(hspace.Box{allIPs, nonPortProtos, zeroPort, zeroPort}))
}

// Flow is one concrete canonical flow.
type Flow struct {
	Remote        uint32
	Proto         uint32
	InitiatorPort uint32
	ServicePort   uint32
}

// Canonical pins the ports of non-TCP/UDP flows to 0.
func (f Flow) Canonical() Flow {
	if !model.HasPorts(f.Proto) {
		f.InitiatorPort, f.ServicePort = 0, 0
	}
	return f
}

// Point returns f as hspace coordinates.
func (f Flow) Point() []uint32 {
	c := f.Canonical()
	return []uint32{c.Remote, c.Proto, c.InitiatorPort, c.ServicePort}
}

// matchRegion returns the flows whose protocol matches m, whose remote
// address is in remote and whose port in dimension portDim matches m's ports.
func matchRegion(m model.Match, remote interval.Set, portDim int) hspace.Space {
	out := emptyFlowSpace
	if remote.IsEmpty() {
		return out
	}
	if p := m.Protocols.Intersect(model.PortProtocols); !p.IsEmpty() {
		b := hspace.Box{remote, p, allPorts, allPorts}
		b[portDim] = m.Ports
		out = out.Union(out.Box(b))
	}
	if p := m.Protocols.Intersect(nonPortProtos); !p.IsEmpty() {
		out = out.Union(out.Box(hspace.Box{remote, p, zeroPort, zeroPort}))
	}
	return out
}

// Addr says which address a rule's CIDR is compared with: either the remote
// dimension of the flow space, or a fixed address known for the whole query
// (for example the target's private IP when checking the source's egress).
type Addr struct {
	fixed bool
	ip    uint32
}

// RemoteAddr compares rule CIDRs with the remote dimension.
func RemoteAddr() Addr { return Addr{} }

// FixedAddr compares rule CIDRs with the constant ip.
func FixedAddr(ip uint32) Addr { return Addr{fixed: true, ip: ip} }

// remoteSet returns the remote-dimension set selected by a rule CIDR.
func (a Addr) remoteSet(c interval.CIDR) interval.Set {
	if a.fixed {
		if c.Contains(a.ip) {
			return allIPs
		}
		return interval.Set{}
	}
	return c.Set()
}
