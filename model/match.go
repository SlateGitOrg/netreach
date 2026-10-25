package model

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/archit2501/netreach/interval"
)

// IP protocol numbers with port semantics.
const (
	ProtoICMP = 1
	ProtoTCP  = 6
	ProtoUDP  = 17
	MaxProto  = 255
	MaxPort   = 65535
)

// HasPorts reports whether protocol p carries TCP/UDP-style port numbers.
// For every other protocol netreach ignores port fields (ICMP type/code is not
// modelled; see DECISIONS.md).
func HasPorts(p uint32) bool { return p == ProtoTCP || p == ProtoUDP }

// PortProtocols is the set {tcp, udp}.
var PortProtocols = func() interval.Set {
	s, _ := interval.FromRanges(interval.Range{Lo: ProtoTCP, Hi: ProtoTCP}, interval.Range{Lo: ProtoUDP, Hi: ProtoUDP})
	return s
}()

// Match is the protocol/port selector shared by security group rules and
// NACL entries. Ports constrains only TCP and UDP traffic.
type Match struct {
	Protocols interval.Set
	Ports     interval.Set
}

// Matches reports whether a packet with protocol proto and (destination, for
// the rule's direction) port matches m.
func (m Match) Matches(proto, port uint32) bool {
	if !m.Protocols.Contains(proto) {
		return false
	}
	return !HasPorts(proto) || m.Ports.Contains(port)
}

// String renders m like "tcp 443" or "all".
func (m Match) String() string {
	if m.Protocols.Equal(interval.Full(MaxProto)) {
		return "all traffic"
	}
	name := ProtocolName(m.Protocols)
	if m.Protocols.SubsetOf(PortProtocols) {
		if m.Ports.Equal(interval.Full(MaxPort)) {
			return name + " all ports"
		}
		return name + " " + m.Ports.String()
	}
	return name
}

// ProtocolName renders a protocol set with well-known names.
func ProtocolName(s interval.Set) string {
	if s.Equal(interval.Full(MaxProto)) {
		return "all"
	}
	return s.Format(func(v uint32) string {
		switch v {
		case ProtoTCP:
			return "tcp"
		case ProtoUDP:
			return "udp"
		case ProtoICMP:
			return "icmp"
		}
		return strconv.Itoa(int(v))
	})
}

// ParseProtocol accepts "tcp", "udp", "icmp", "all"/"-1", or a number 0-255.
func ParseProtocol(text string) (interval.Set, error) {
	switch strings.ToLower(strings.TrimSpace(text)) {
	case "tcp":
		return interval.Single(ProtoTCP), nil
	case "udp":
		return interval.Single(ProtoUDP), nil
	case "icmp":
		return interval.Single(ProtoICMP), nil
	case "all", "-1":
		return interval.Full(MaxProto), nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || n < 0 || n > MaxProto {
		return interval.Set{}, fmt.Errorf("invalid protocol %q", text)
	}
	return interval.Single(uint32(n)), nil
}

// ParsePorts accepts "" (all ports), "443", "1024-65535" or a comma list.
func ParsePorts(text string) (interval.Set, error) {
	if strings.TrimSpace(text) == "" {
		return interval.Full(MaxPort), nil
	}
	s, err := interval.Parse(text)
	if err != nil {
		return interval.Set{}, fmt.Errorf("invalid ports %q: %w", text, err)
	}
	if s.IsEmpty() || !s.SubsetOf(interval.Full(MaxPort)) {
		return interval.Set{}, fmt.Errorf("invalid ports %q: must be within 0-65535", text)
	}
	return s, nil
}

// ParseMatch combines ParseProtocol and ParsePorts.
func ParseMatch(protocol, ports string) (Match, error) {
	protos, err := ParseProtocol(protocol)
	if err != nil {
		return Match{}, err
	}
	p, err := ParsePorts(ports)
	if err != nil {
		return Match{}, err
	}
	return Match{Protocols: protos, Ports: p}, nil
}
