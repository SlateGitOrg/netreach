package model

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/SlateGitOrg/netreach/interval"
)

// base returns a small valid snapshot that each invalid case mutates.
func base() *Snapshot {
	return &Snapshot{
		Name:             "t",
		VPCs:             []VPC{{ID: "vpc-1", CIDRs: []string{"10.0.0.0/16"}}, {ID: "vpc-2", CIDRs: []string{"10.1.0.0/16"}}},
		InternetGateways: []InternetGateway{{ID: "igw-1", VPC: "vpc-1"}},
		Peerings:         []Peering{{ID: "pcx-1", RequesterVPC: "vpc-1", AccepterVPC: "vpc-2"}},
		NATGateways:      []NATGateway{{ID: "nat-1", Subnet: "subnet-1", PrivateIP: "10.0.1.5", PublicIP: "52.0.0.1"}},
		Subnets: []Subnet{
			{ID: "subnet-1", VPC: "vpc-1", CIDR: "10.0.1.0/24", RouteTable: "rtb-1", NetworkACL: "acl-1"},
			{ID: "subnet-2", VPC: "vpc-2", CIDR: "10.1.1.0/24", RouteTable: "rtb-2", NetworkACL: "acl-2"},
		},
		RouteTables: []RouteTable{
			{ID: "rtb-1", VPC: "vpc-1", Routes: []Route{
				{Destination: "0.0.0.0/0", Target: "igw-1"},
				{Destination: "10.1.0.0/16", Target: "pcx-1"},
				{Destination: "192.0.2.0/24", Target: "nat-1"},
				{Destination: "198.51.100.0/24", Target: "blackhole"},
				{Destination: "10.0.0.0/16", Target: "local"},
			}},
			{ID: "rtb-2", VPC: "vpc-2", Routes: []Route{{Destination: "10.0.0.0/16", Target: "pcx-1"}}},
		},
		NetworkACLs: []NetworkACL{
			{ID: "acl-1", VPC: "vpc-1",
				Inbound:  []ACLEntry{{RuleNumber: 200, Protocol: "all", Action: "allow", CIDR: "0.0.0.0/0"}, {RuleNumber: 100, Protocol: "tcp", Ports: "22", Action: "deny", CIDR: "0.0.0.0/0"}},
				Outbound: []ACLEntry{{RuleNumber: 100, Protocol: "-1", Action: "ALLOW", CIDR: "0.0.0.0/0"}}},
			{ID: "acl-2", VPC: "vpc-2"},
		},
		SecurityGroups: []SecurityGroup{
			{ID: "sg-1", VPC: "vpc-1", Inbound: []SGRule{{Protocol: "tcp", Ports: "443", CIDR: "0.0.0.0/0"}, {Protocol: "tcp", Ports: "22", Group: "sg-2"}}},
			{ID: "sg-2", VPC: "vpc-2", Outbound: []SGRule{{Protocol: "all", CIDR: "0.0.0.0/0"}}},
		},
		ENIs: []ENI{
			{ID: "eni-b", Name: "b", Instance: "i-1", Subnet: "subnet-1", PrivateIP: "10.0.1.10", PublicIP: "54.0.0.1", SecurityGroups: []string{"sg-1"}},
			{ID: "eni-a", Subnet: "subnet-2", PrivateIP: "10.1.1.10", SecurityGroups: []string{"sg-2"}},
		},
	}
}

func TestCompileValidSnapshot(t *testing.T) {
	n, err := Compile(base())
	if err != nil {
		t.Fatal(err)
	}
	if len(n.ENIs) != 2 || n.ENIs[0].ID != "eni-a" {
		t.Fatalf("ENIs not sorted by ID: %v", n.ENIs)
	}
	rt := n.Subnet("subnet-1").RouteTable
	// local /16 and peering /16 both precede the /24s? No: /24s are more specific.
	wantOrder := []string{"192.0.2.0/24", "198.51.100.0/24", "10.0.0.0/16", "10.1.0.0/16", "0.0.0.0/0"}
	for i, r := range rt.Routes {
		if r.Dest.String() != wantOrder[i] {
			t.Fatalf("route %d = %s, want %s", i, r.Dest, wantOrder[i])
		}
	}
	kinds := map[string]RouteKind{"local": RouteLocal, "igw-1": RouteIGW, "nat-1": RouteNAT, "pcx-1": RoutePeering, "blackhole": RouteBlackhole}
	for _, r := range rt.Routes {
		if kinds[r.Target] != r.Kind {
			t.Fatalf("route %s kind %s", r.Target, r.Kind)
		}
	}
	if got := rt.Lookup(0xC0000201); got == nil || got.Kind != RouteNAT { // 192.0.2.1
		t.Fatalf("lookup 192.0.2.1 = %v", got)
	}
	if got := rt.Lookup(0x0A000001); got.Kind != RouteLocal {
		t.Fatal("lookup local")
	}
	acl := n.Subnet("subnet-1").ACL
	if acl.Inbound[0].Number != 100 || acl.Inbound[0].Action() != "deny" || acl.Outbound[0].Action() != "allow" {
		t.Fatal("ACL entries not sorted/parsed")
	}
	b := n.ENI("eni-b")
	if b.Label() != "b (eni-b)" || n.ENI("eni-a").Label() != "eni-a" || !b.HasPublicIP {
		t.Fatal("labels")
	}
	if len(n.ENIsOfInstance("i-1")) != 1 || n.ENI("nope") != nil || n.Subnet("nope") != nil {
		t.Fatal("lookups")
	}
	if n.VPCOf(0x0A010101).ID != "vpc-2" || n.VPCOf(0x08080808) != nil {
		t.Fatal("VPCOf")
	}
	if !n.AllVPCSpace().Equal(interval.MustParseCIDR("10.0.0.0/15").Set()) {
		t.Fatal("AllVPCSpace")
	}
	sg1 := n.SGs[0]
	if !sg1.HasMember(b) || sg1.Inbound[1].Peer() != "sg-2" || sg1.Inbound[0].Peer() != "0.0.0.0/0" {
		t.Fatal("sg membership / peer")
	}
	p := n.Peerings[0]
	if !p.Connects(n.VPCs[1], n.VPCs[0]) || p.Connects(n.VPCs[0], n.VPCs[0]) {
		t.Fatal("Connects")
	}
	if n.VPCs[0].IGW == nil || n.NATs[0].Subnet.ID != "subnet-1" {
		t.Fatal("igw/nat wiring")
	}
}

func TestCompileRejectsInvalidSnapshots(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Snapshot)
		want   string
	}{
		{"duplicate id", func(s *Snapshot) { s.ENIs[1].ID = "eni-b" }, `duplicate id "eni-b"`},
		{"empty id", func(s *Snapshot) { s.VPCs = append(s.VPCs, VPC{CIDRs: []string{"10.9.0.0/16"}}) }, "empty id"},
		{"bad vpc cidr", func(s *Snapshot) { s.VPCs[0].CIDRs = []string{"10.0.0.1/16"} }, "host bits set"},
		{"no vpc cidr", func(s *Snapshot) { s.VPCs[1].CIDRs = nil }, "no CIDR blocks"},
		{"overlapping vpcs", func(s *Snapshot) { s.VPCs[1].CIDRs = []string{"10.0.128.0/17"} }, "overlaps"},
		{"two igws", func(s *Snapshot) {
			s.InternetGateways = append(s.InternetGateways, InternetGateway{ID: "igw-2", VPC: "vpc-1"})
		}, "two internet gateways"},
		{"unknown ref", func(s *Snapshot) { s.Subnets[0].RouteTable = "rtb-x" }, `unknown id "rtb-x"`},
		{"wrong type ref", func(s *Snapshot) { s.Subnets[0].NetworkACL = "sg-1" }, "wrong type"},
		{"subnet outside vpc", func(s *Snapshot) { s.Subnets[0].CIDR = "10.5.0.0/24" }, "outside vpc"},
		{"subnet overlap", func(s *Snapshot) {
			s.Subnets = append(s.Subnets, Subnet{ID: "subnet-3", VPC: "vpc-1", CIDR: "10.0.1.128/25", RouteTable: "rtb-1", NetworkACL: "acl-1"})
		}, "overlaps subnet"},
		{"route table other vpc", func(s *Snapshot) { s.Subnets[0].RouteTable = "rtb-2" }, "route table rtb-2 belongs to another VPC"},
		{"acl other vpc", func(s *Snapshot) { s.Subnets[0].NetworkACL = "acl-2" }, "network acl acl-2 belongs to another VPC"},
		{"self peering", func(s *Snapshot) { s.Peerings[0].AccepterVPC = "vpc-1" }, "cannot peer with itself"},
		{"bad peering status", func(s *Snapshot) { s.Peerings[0].Status = "weird" }, "unknown status"},
		{"acl rule number", func(s *Snapshot) { s.NetworkACLs[0].Inbound[0].RuleNumber = 0 }, "rule number must be"},
		{"acl duplicate number", func(s *Snapshot) { s.NetworkACLs[0].Inbound[0].RuleNumber = 100 }, "duplicate rule number"},
		{"acl bad action", func(s *Snapshot) { s.NetworkACLs[0].Inbound[0].Action = "maybe" }, "action must be"},
		{"acl bad protocol", func(s *Snapshot) { s.NetworkACLs[0].Inbound[0].Protocol = "sctpx" }, "invalid protocol"},
		{"acl bad cidr", func(s *Snapshot) { s.NetworkACLs[0].Inbound[0].CIDR = "x" }, "invalid CIDR"},
		{"acl bad ports", func(s *Snapshot) { s.NetworkACLs[0].Inbound[1].Ports = "70000" }, "invalid ports"},
		{"sg both peers", func(s *Snapshot) { s.SecurityGroups[0].Inbound[0].Group = "sg-2" }, "exactly one"},
		{"sg no peer", func(s *Snapshot) { s.SecurityGroups[0].Inbound[0].CIDR = "" }, "exactly one"},
		{"sg bad cidr", func(s *Snapshot) { s.SecurityGroups[0].Inbound[0].CIDR = "1.2.3.4/40" }, "invalid CIDR"},
		{"sg unknown group", func(s *Snapshot) { s.SecurityGroups[0].Inbound[1].Group = "sg-x" }, `unknown id "sg-x"`},
		{"sg bad ports", func(s *Snapshot) { s.SecurityGroups[0].Inbound[0].Ports = "9-1" }, "invalid ports"},
		{"route bad dest", func(s *Snapshot) { s.RouteTables[0].Routes[0].Destination = "nope" }, "invalid CIDR"},
		{"local mismatch", func(s *Snapshot) { s.RouteTables[0].Routes[4].Destination = "10.0.0.0/8" }, "local route"},
		{"duplicate route", func(s *Snapshot) { s.RouteTables[0].Routes[3].Destination = "192.0.2.0/24" }, "duplicate route"},
		{"route inside vpc", func(s *Snapshot) { s.RouteTables[0].Routes[3].Destination = "10.0.5.0/24" }, "more specific than the VPC"},
		{"route to foreign igw", func(s *Snapshot) { s.RouteTables[1].Routes[0].Target = "igw-1" }, "not attached"},
		{"route to foreign nat", func(s *Snapshot) {
			s.RouteTables[1].Routes = append(s.RouteTables[1].Routes, Route{Destination: "0.0.0.0/0", Target: "nat-1"})
		}, "in another VPC"},
		{"route to unrelated peering", func(s *Snapshot) {
			s.VPCs = append(s.VPCs, VPC{ID: "vpc-3", CIDRs: []string{"10.2.0.0/16"}})
			s.RouteTables = append(s.RouteTables, RouteTable{ID: "rtb-3", VPC: "vpc-3", Routes: []Route{{Destination: "10.0.0.0/16", Target: "pcx-1"}}})
		}, "does not involve"},
		{"route unsupported target", func(s *Snapshot) { s.RouteTables[0].Routes[0].Target = "eni-b" }, "unsupported route target"},
		{"nat ip outside subnet", func(s *Snapshot) { s.NATGateways[0].PrivateIP = "10.0.2.5" }, "outside subnet"},
		{"nat bad ips", func(s *Snapshot) { s.NATGateways[0].PrivateIP, s.NATGateways[0].PublicIP = "x", "y" }, "publicIp"},
		{"eni ip outside", func(s *Snapshot) { s.ENIs[0].PrivateIP = "10.0.9.9" }, "outside subnet"},
		{"eni bad ip", func(s *Snapshot) { s.ENIs[0].PrivateIP = "10.0.1" }, "privateIp"},
		{"eni bad public", func(s *Snapshot) { s.ENIs[0].PublicIP = "1.2.3.400" }, "publicIp"},
		{"eni duplicate ip", func(s *Snapshot) {
			s.ENIs = append(s.ENIs, ENI{ID: "eni-c", Subnet: "subnet-1", PrivateIP: "10.0.1.10", SecurityGroups: []string{"sg-1"}})
		}, "already used"},
		{"eni no sg", func(s *Snapshot) { s.ENIs[0].SecurityGroups = nil }, "at least one security group"},
		{"eni foreign sg", func(s *Snapshot) { s.ENIs[0].SecurityGroups = []string{"sg-2"} }, "belongs to another VPC"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mutate(s)
			_, err := Compile(s)
			if err == nil {
				t.Fatalf("expected an error containing %q", tc.want)
			}
			if !IsValidation(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := Decode(strings.NewReader(`{"name":"x","vpcs":[],"bogus":1}`))
	if err == nil || !strings.Contains(err.Error(), "bogus") {
		t.Fatalf("got %v", err)
	}
	raw, _ := json.Marshal(base())
	s, err := Decode(strings.NewReader(string(raw)))
	if err != nil || s.Name != "t" {
		t.Fatalf("round trip: %v", err)
	}
	if _, err := LoadFile("does-not-exist.json"); err == nil {
		t.Fatal("missing file")
	}
	if _, err := Load("does-not-exist.json"); err == nil {
		t.Fatal("missing file")
	}
}

func TestMatchSemantics(t *testing.T) {
	m, err := ParseMatch("tcp", "80,443")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Matches(ProtoTCP, 443) || m.Matches(ProtoTCP, 22) || m.Matches(ProtoUDP, 443) {
		t.Fatal("tcp match")
	}
	icmp, _ := ParseMatch("icmp", "")
	if !icmp.Matches(ProtoICMP, 12345) {
		t.Fatal("ports must be ignored for ICMP")
	}
	all, _ := ParseMatch("-1", "")
	if all.String() != "all traffic" || m.String() != "tcp 80,443" || icmp.String() != "icmp" {
		t.Fatalf("strings: %q %q %q", all, m, icmp)
	}
	udpAll, _ := ParseMatch("udp", "")
	if udpAll.String() != "udp all ports" {
		t.Fatal(udpAll.String())
	}
	gre, _ := ParseMatch("47", "")
	if gre.String() != "47" || !HasPorts(ProtoTCP) || HasPorts(47) {
		t.Fatal("numeric protocol")
	}
	for _, bad := range []string{"256", "-2", "x"} {
		if _, err := ParseProtocol(bad); err == nil {
			t.Errorf("protocol %q accepted", bad)
		}
	}
	if RouteBlackhole.String() != "blackhole" {
		t.Fatal("route kind string")
	}
}
