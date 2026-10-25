// Package report turns engine results into exposure reports (JSON and
// Markdown) and provides the projections used to summarise a header space:
// open ports per protocol, source sets per port, and human-readable address
// set descriptions.
package report

import (
	"fmt"
	"strings"

	"github.com/archit2501/netreach/engine"
	"github.com/archit2501/netreach/hspace"
	"github.com/archit2501/netreach/interval"
	"github.com/archit2501/netreach/model"
)

// PortSummary projects a flow space onto (protocol, service port).
type PortSummary struct {
	TCP   interval.Set // service ports reachable over TCP
	UDP   interval.Set // service ports reachable over UDP
	Other interval.Set // non-TCP/UDP protocol numbers reachable
}

var nonPortProtos = model.PortProtocols.Complement(model.MaxProto)

// Summarize computes the PortSummary of space.
func Summarize(space hspace.Space) PortSummary {
	return PortSummary{
		TCP:   space.Restrict(engine.DimProto, interval.Single(model.ProtoTCP)).Project(engine.DimServicePort),
		UDP:   space.Restrict(engine.DimProto, interval.Single(model.ProtoUDP)).Project(engine.DimServicePort),
		Other: space.Restrict(engine.DimProto, nonPortProtos).Project(engine.DimProto),
	}
}

// IsEmpty reports whether nothing is reachable.
func (p PortSummary) IsEmpty() bool { return p.TCP.IsEmpty() && p.UDP.IsEmpty() && p.Other.IsEmpty() }

// String renders p like "tcp 22,80; udp 53; icmp".
func (p PortSummary) String() string {
	var parts []string
	if !p.TCP.IsEmpty() {
		parts = append(parts, "tcp "+portText(p.TCP))
	}
	if !p.UDP.IsEmpty() {
		parts = append(parts, "udp "+portText(p.UDP))
	}
	if !p.Other.IsEmpty() {
		parts = append(parts, "proto "+model.ProtocolName(p.Other))
	}
	if len(parts) == 0 {
		return "nothing"
	}
	return strings.Join(parts, "; ")
}

func portText(s interval.Set) string {
	if s.Equal(interval.Full(model.MaxPort)) {
		return "all ports"
	}
	return s.String()
}

// setText renders a port/protocol set for reports: "" when empty.
func setText(s interval.Set) string {
	if s.IsEmpty() {
		return ""
	}
	return s.String()
}

// RemotesFor returns the remote addresses that reach (proto, port) in space
// with at least one initiator port.
func RemotesFor(space hspace.Space, proto, port uint32) interval.Set {
	return space.Restrict(engine.DimProto, interval.Single(proto)).
		Restrict(engine.DimServicePort, interval.Single(port)).Project(engine.DimRemote)
}

// InitiatorPortsFor returns the initiator ports that work for (proto, port)
// from at least one remote address.
func InitiatorPortsFor(space hspace.Space, proto, port uint32) interval.Set {
	return space.Restrict(engine.DimProto, interval.Single(proto)).
		Restrict(engine.DimServicePort, interval.Single(port)).Project(engine.DimInitiatorPt)
}

// DescribeAddresses renders an address set compactly. A set covering more
// than half the address space is shown as "0.0.0.0/0 except …" when that is
// shorter than listing its prefixes.
func DescribeAddresses(s interval.Set) string {
	const maxListed = 6
	if s.IsEmpty() {
		return "none"
	}
	cidrs := s.CIDRStrings()
	all := interval.Full(interval.MaxIPv4)
	if s.Equal(all) {
		return "0.0.0.0/0"
	}
	if hole := s.Complement(interval.MaxIPv4); s.Size() > hole.Size() {
		if holes := hole.CIDRStrings(); len(holes) < len(cidrs) {
			return "0.0.0.0/0 except " + truncateList(holes, maxListed)
		}
	}
	return truncateList(cidrs, maxListed)
}

func truncateList(items []string, limit int) string {
	if len(items) <= limit {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:limit], ", ") + fmt.Sprintf(" (+%d more)", len(items)-limit)
}
