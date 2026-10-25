package report

import (
	"cmp"
	"slices"

	"github.com/SlateGitOrg/netreach/engine"
	"github.com/SlateGitOrg/netreach/hspace"
	"github.com/SlateGitOrg/netreach/interval"
	"github.com/SlateGitOrg/netreach/model"
)

// Version is the report schema/tool version.
const Version = "0.1.0"

// Report is the serialisable result of one analysis run.
type Report struct {
	Tool     string   `json:"tool"`
	Version  string   `json:"version"`
	Snapshot string   `json:"snapshot"`
	Query    Query    `json:"query"`
	Summary  Summary  `json:"summary"`
	Targets  []Target `json:"targets"`
}

// Query describes what was asked.
type Query struct {
	Kind engine.Kind `json:"kind"`
	// From is the source: an address set for internet ingress, an ENI ID for
	// internal ingress and egress.
	From string `json:"from"`
	// Remote describes the remote address set; RemoteRole says whether those
	// addresses are flow sources (ingress) or destinations (egress).
	Remote     string `json:"remote"`
	RemoteRole string `json:"remoteRole"`
}

// Summary aggregates the targets.
type Summary struct {
	Targets   int              `json:"targets"`
	Reachable int              `json:"reachable"`
	Findings  map[Severity]int `json:"findings"`
}

// Target is the result for one analysed ENI.
type Target struct {
	ENI       string      `json:"eni"`
	Name      string      `json:"name,omitempty"`
	Instance  string      `json:"instance,omitempty"`
	Subnet    string      `json:"subnet"`
	VPC       string      `json:"vpc"`
	PrivateIP string      `json:"privateIp"`
	PublicIP  string      `json:"publicIp,omitempty"`
	Peer      string      `json:"peer,omitempty"`
	Reachable bool        `json:"reachable"`
	Open      OpenPorts   `json:"open"`
	Severity  Severity    `json:"severity,omitempty"`
	Exposures []Exposure  `json:"exposures"`
	Blocked   []Blocked   `json:"blocked"`
	Stats     TargetStats `json:"stats"`
}

// OpenPorts lists reachable service ports per protocol ("" when none).
type OpenPorts struct {
	TCP   string `json:"tcp"`
	UDP   string `json:"udp"`
	Other string `json:"other"`
}

// TargetStats exposes the size of the computation for this target.
type TargetStats struct {
	AllowedPaths int `json:"allowedPaths"`
	BlockedPaths int `json:"blockedPaths"`
	Boxes        int `json:"boxes"`
}

// Exposure is one reachable class of flows and the path it takes.
type Exposure struct {
	Protocol       string       `json:"protocol"`
	Ports          string       `json:"ports,omitempty"`
	Remote         []string     `json:"remote"`
	RemoteSummary  string       `json:"remoteSummary"`
	InitiatorPorts string       `json:"initiatorPorts,omitempty"`
	Severity       Severity     `json:"severity"`
	Reason         string       `json:"reason"`
	Path           []engine.Hop `json:"path"`
}

// Blocked is one class of dropped flows and the hop that dropped it.
type Blocked struct {
	Step      engine.Step `json:"step"`
	Component string      `json:"component"`
	Detail    string      `json:"detail"`
	Flows     string      `json:"flows"`
}

// Build assembles a report from engine results. from describes the query
// source for the header.
func Build(net *model.Network, kind engine.Kind, from string, remote interval.Set, results []engine.Result) Report {
	r := Report{
		Tool: "netreach", Version: Version, Snapshot: net.Name,
		Query:   Query{Kind: kind, From: from, Remote: DescribeAddresses(remote), RemoteRole: "source"},
		Summary: Summary{Targets: len(results), Findings: map[Severity]int{}},
		Targets: make([]Target, 0, len(results)),
	}
	if kind == engine.InternetEgress {
		r.Query.RemoteRole = "destination"
	}
	for i := range results {
		t := buildTarget(&results[i])
		if t.Reachable {
			r.Summary.Reachable++
		}
		for _, e := range t.Exposures {
			r.Summary.Findings[e.Severity]++
		}
		r.Targets = append(r.Targets, t)
	}
	return r
}

func buildTarget(res *engine.Result) Target {
	e := res.Subject
	reach := res.Reachable()
	open := Summarize(reach)
	t := Target{
		ENI: e.ID, Name: e.Name, Instance: e.Instance, Subnet: e.Subnet.ID, VPC: e.VPC().ID,
		PrivateIP: interval.FormatIPv4(e.PrivateIP),
		Reachable: !reach.IsEmpty(),
		Open:      OpenPorts{TCP: setText(open.TCP), UDP: setText(open.UDP), Other: setText(open.Other)},
		Exposures: []Exposure{},
		Blocked:   []Blocked{},
		Stats:     TargetStats{AllowedPaths: len(res.Allowed), BlockedPaths: len(res.Blocked)},
	}
	if e.HasPublicIP {
		t.PublicIP = interval.FormatIPv4(e.PublicIP)
	}
	if res.Peer != nil {
		t.Peer = res.Peer.ID
	}
	for _, f := range res.Allowed {
		t.Stats.Boxes += f.Space.NumBoxes()
		for _, b := range f.Space.Boxes() {
			t.Exposures = append(t.Exposures, exposuresOf(res.Kind, b, f.Hops)...)
		}
	}
	slices.SortStableFunc(t.Exposures, compareExposure)
	for _, x := range t.Exposures {
		if t.Severity == "" || Worse(x.Severity, t.Severity) {
			t.Severity = x.Severity
		}
	}
	// Different paths can be dropped by the same hop (e.g. tcp 80 and tcp 443
	// admitted by different SG rules, then both dropped by the return route);
	// report one row per deciding hop.
	byHop := map[engine.Hop]int{}
	var spaces []hspace.Space
	for _, f := range res.Blocked {
		t.Stats.Boxes += f.Space.NumBoxes()
		h := f.Blocker()
		if i, ok := byHop[h]; ok {
			spaces[i] = spaces[i].Union(f.Space)
			continue
		}
		byHop[h] = len(t.Blocked)
		spaces = append(spaces, f.Space)
		t.Blocked = append(t.Blocked, Blocked{Step: h.Step, Component: h.Component, Detail: h.Detail})
	}
	for i := range t.Blocked {
		t.Blocked[i].Flows = Summarize(spaces[i]).String()
	}
	return t
}

// exposuresOf splits one box of an allowed fragment into per-protocol exposures.
func exposuresOf(kind engine.Kind, b hspace.Box, path []engine.Hop) []Exposure {
	remote := b[engine.DimRemote]
	var out []Exposure
	add := func(proto uint32, x Exposure, ports interval.Set) {
		x.Remote = remote.CIDRStrings()
		x.RemoteSummary = DescribeAddresses(remote)
		x.Path = path
		x.Severity, x.Reason = Info, "not graded ("+string(kind)+")"
		if kind == engine.InternetIngress {
			x.Severity, x.Reason = Assess(proto, ports, remote)
		}
		out = append(out, x)
	}
	protos := b[engine.DimProto]
	for _, p := range []uint32{model.ProtoTCP, model.ProtoUDP} {
		if protos.Contains(p) {
			add(p, Exposure{
				Protocol:       model.ProtocolName(interval.Single(p)),
				Ports:          b[engine.DimServicePort].String(),
				InitiatorPorts: b[engine.DimInitiatorPt].String(),
			}, b[engine.DimServicePort])
		}
	}
	if other := protos.Intersect(nonPortProtos); !other.IsEmpty() {
		// Grade by the riskiest member: any protocol other than ICMP.
		rep := uint32(model.ProtoICMP)
		if rest := other.Subtract(interval.Single(model.ProtoICMP)); !rest.IsEmpty() {
			rep, _ = rest.Min()
		}
		add(rep, Exposure{Protocol: model.ProtocolName(other)}, interval.Set{})
	}
	return out
}

func compareExposure(a, b Exposure) int {
	if c := cmp.Compare(severityRank[a.Severity], severityRank[b.Severity]); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Protocol, b.Protocol); c != 0 {
		return c
	}
	return cmp.Compare(firstPort(a.Ports), firstPort(b.Ports))
}

func firstPort(ports string) uint32 {
	s, err := interval.Parse(ports)
	if err != nil {
		return 0
	}
	v, _ := s.Min()
	return v
}
