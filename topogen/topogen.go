// Package topogen generates random but valid VPC snapshots. It drives the
// differential tests (engine versus simulator on thousands of sampled flows)
// and the scaling benchmarks.
//
// Generated rules draw CIDRs and ports from a small vocabulary of
// overlapping values, so rules interact (shadowing, partial overlaps, nested
// prefixes) far more often than uniformly random values would.
package topogen

import (
	"fmt"
	"math/rand/v2"
	"slices"

	"github.com/archit2501/netreach/model"
)

// Params controls the size and shape of a generated snapshot.
type Params struct {
	Seed               uint64
	VPCs               int // number of VPCs (max 200)
	SubnetsPerVPC      int // max 250
	ENIsPerSubnet      int // max 200
	SGsPerVPC          int
	SGRules            int // inbound rules per security group
	ACLRules           int // rules per NACL direction
	ExtraRoutes        int // external more-specific routes per route table
	PeeringProbability float64
}

// Small is the shape used by differential tests.
func Small(seed uint64) Params {
	return Params{Seed: seed, VPCs: 2, SubnetsPerVPC: 2, ENIsPerSubnet: 2, SGsPerVPC: 3,
		SGRules: 4, ACLRules: 5, ExtraRoutes: 2, PeeringProbability: 0.7}
}

// Validate checks p's bounds.
func (p Params) Validate() error {
	switch {
	case p.VPCs < 1 || p.VPCs > 200:
		return fmt.Errorf("vpcs must be 1-200")
	case p.SubnetsPerVPC < 1 || p.SubnetsPerVPC > 250:
		return fmt.Errorf("subnets per VPC must be 1-250")
	case p.ENIsPerSubnet < 1 || p.ENIsPerSubnet > 200:
		return fmt.Errorf("ENIs per subnet must be 1-200")
	case p.SGsPerVPC < 1 || p.SGRules < 0 || p.ACLRules < 0 || p.ExtraRoutes < 0:
		return fmt.Errorf("rule counts must be non-negative and at least one SG per VPC")
	}
	return nil
}

var externalCIDRs = []string{
	"0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "8.0.0.0/8", "8.8.0.0/16", "8.8.8.0/24",
	"100.64.0.0/10", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "203.0.113.128/25",
	"52.0.0.0/8", "10.0.0.0/8",
}

var portChoices = []string{"", "22", "80", "443", "53", "0-1023", "1024-65535", "3306-3310",
	"8000-8999", "1024-2047", "80,443", "123"}

var protocolChoices = []string{"tcp", "tcp", "tcp", "udp", "udp", "icmp", "all", "47"}

type gen struct {
	p    Params
	rng  *rand.Rand
	snap *model.Snapshot
}

// Generate returns a random snapshot. The same Params always yield the same
// snapshot. The result always passes model.Compile.
func Generate(p Params) (*model.Snapshot, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	g := &gen{p: p, rng: rand.New(rand.NewPCG(p.Seed, p.Seed^0x9e3779b97f4a7c15)),
		snap: &model.Snapshot{Name: fmt.Sprintf("generated-%d", p.Seed)}}
	g.vpcs()
	g.peerings()
	for v := range p.VPCs {
		g.vpcInterior(v)
	}
	return g.snap, nil
}

func vpcID(v int) string             { return fmt.Sprintf("vpc-%d", v) }
func vpcCIDR(v int) string           { return fmt.Sprintf("10.%d.0.0/16", v+1) }
func subnetID(v, s int) string       { return fmt.Sprintf("subnet-%d-%d", v, s) }
func sgID(v, i int) string           { return fmt.Sprintf("sg-%d-%d", v, i) }
func aclID(v, i int) string          { return fmt.Sprintf("acl-%d-%d", v, i) }
func rtbID(v, i int) string          { return fmt.Sprintf("rtb-%d-%d", v, i) }
func pick[T any](g *gen, xs []T) T   { return xs[g.rng.IntN(len(xs))] }
func (g *gen) chance(p float64) bool { return g.rng.Float64() < p }

func (g *gen) vpcs() {
	for v := range g.p.VPCs {
		g.snap.VPCs = append(g.snap.VPCs, model.VPC{ID: vpcID(v), CIDRs: []string{vpcCIDR(v)}})
		if g.chance(0.85) {
			g.snap.InternetGateways = append(g.snap.InternetGateways,
				model.InternetGateway{ID: fmt.Sprintf("igw-%d", v), VPC: vpcID(v)})
		}
	}
}

func (g *gen) hasIGW(v int) bool {
	return slices.ContainsFunc(g.snap.InternetGateways, func(i model.InternetGateway) bool { return i.VPC == vpcID(v) })
}

func (g *gen) peerings() {
	for a := range g.p.VPCs {
		for b := a + 1; b < g.p.VPCs; b++ {
			if !g.chance(g.p.PeeringProbability) {
				continue
			}
			status := "active"
			if g.chance(0.2) {
				status = "pending-acceptance"
			}
			g.snap.Peerings = append(g.snap.Peerings, model.Peering{ID: fmt.Sprintf("pcx-%d-%d", a, b),
				RequesterVPC: vpcID(a), AccepterVPC: vpcID(b), Status: status})
		}
	}
}

func (g *gen) cidr() string {
	if g.chance(0.25) {
		// A CIDR inside some VPC, so internal sources and peers match too.
		other := g.rng.IntN(g.p.VPCs)
		if g.chance(0.5) {
			return vpcCIDR(other)
		}
		return fmt.Sprintf("10.%d.%d.0/24", other+1, g.rng.IntN(g.p.SubnetsPerVPC))
	}
	return pick(g, externalCIDRs)
}

func (g *gen) vpcInterior(v int) {
	// Network ACLs: two per VPC.
	for i := range 2 {
		g.snap.NetworkACLs = append(g.snap.NetworkACLs, model.NetworkACL{ID: aclID(v, i), VPC: vpcID(v),
			Inbound: g.aclEntries(), Outbound: g.aclEntries()})
	}
	// NAT gateway in subnet 0 (when there is more than one subnet).
	hasNAT := g.p.SubnetsPerVPC > 1 && g.chance(0.6)
	natID := fmt.Sprintf("nat-%d", v)
	if hasNAT {
		g.snap.NATGateways = append(g.snap.NATGateways, model.NATGateway{ID: natID, Subnet: subnetID(v, 0),
			PrivateIP: fmt.Sprintf("10.%d.0.5", v+1), PublicIP: fmt.Sprintf("52.%d.0.5", v+1)})
	}
	// Route tables: rtb-0 (public-ish) and rtb-1 (private-ish).
	for i := range 2 {
		g.snap.RouteTables = append(g.snap.RouteTables, g.routeTable(v, i, hasNAT, natID))
	}
	// Security groups.
	for i := range g.p.SGsPerVPC {
		sg := model.SecurityGroup{ID: sgID(v, i), VPC: vpcID(v), Inbound: []model.SGRule{}, Outbound: []model.SGRule{}}
		for range g.p.SGRules {
			sg.Inbound = append(sg.Inbound, g.sgRule(v))
		}
		if g.chance(0.7) {
			sg.Outbound = append(sg.Outbound, model.SGRule{Protocol: "all", CIDR: "0.0.0.0/0"})
		} else {
			for range 1 + g.rng.IntN(3) {
				sg.Outbound = append(sg.Outbound, g.sgRule(v))
			}
		}
		g.snap.SecurityGroups = append(g.snap.SecurityGroups, sg)
	}
	// Subnets and ENIs.
	for s := range g.p.SubnetsPerVPC {
		rtb := rtbID(v, 1)
		if s == 0 || g.chance(0.4) {
			rtb = rtbID(v, 0)
		}
		g.snap.Subnets = append(g.snap.Subnets, model.Subnet{ID: subnetID(v, s), VPC: vpcID(v),
			CIDR: fmt.Sprintf("10.%d.%d.0/24", v+1, s), RouteTable: rtb, NetworkACL: aclID(v, g.rng.IntN(2))})
		for e := range g.p.ENIsPerSubnet {
			eni := model.ENI{ID: fmt.Sprintf("eni-%d-%d-%d", v, s, e), Subnet: subnetID(v, s),
				PrivateIP: fmt.Sprintf("10.%d.%d.%d", v+1, s, 10+e)}
			if g.chance(0.5) {
				eni.PublicIP = fmt.Sprintf("54.%d.%d.%d", v+1, s, 10+e)
			}
			eni.SecurityGroups = []string{sgID(v, g.rng.IntN(g.p.SGsPerVPC))}
			if g.p.SGsPerVPC > 1 && g.chance(0.3) {
				second := sgID(v, g.rng.IntN(g.p.SGsPerVPC))
				if second != eni.SecurityGroups[0] {
					eni.SecurityGroups = append(eni.SecurityGroups, second)
				}
			}
			g.snap.ENIs = append(g.snap.ENIs, eni)
		}
	}
}

func (g *gen) aclEntries() []model.ACLEntry {
	out := make([]model.ACLEntry, 0, g.p.ACLRules+1)
	numbers := g.rng.Perm(g.p.ACLRules + 50)
	for i := range g.p.ACLRules {
		action := "allow"
		if g.chance(0.3) {
			action = "deny"
		}
		out = append(out, model.ACLEntry{RuleNumber: 10 * (numbers[i] + 1), Protocol: pick(g, protocolChoices),
			Ports: pick(g, portChoices), Action: action, CIDR: g.cidr()})
	}
	if g.chance(0.6) { // a common catch-all allow at the end
		out = append(out, model.ACLEntry{RuleNumber: 32000, Protocol: "all", Action: "allow", CIDR: "0.0.0.0/0"})
	}
	return out
}

func (g *gen) sgRule(v int) model.SGRule {
	r := model.SGRule{Protocol: pick(g, protocolChoices), Ports: pick(g, portChoices)}
	if g.chance(0.25) {
		// Reference a group in this VPC or in any VPC (peered or not).
		other := v
		if g.chance(0.3) {
			other = g.rng.IntN(g.p.VPCs)
		}
		r.Group = sgID(other, g.rng.IntN(g.p.SGsPerVPC))
	} else {
		r.CIDR = g.cidr()
	}
	return r
}

func (g *gen) routeTable(v, i int, hasNAT bool, natID string) model.RouteTable {
	rt := model.RouteTable{ID: rtbID(v, i), VPC: vpcID(v), Routes: []model.Route{}}
	used := map[string]bool{}
	add := func(dest, target string) {
		if used[dest] {
			return
		}
		used[dest] = true
		rt.Routes = append(rt.Routes, model.Route{Destination: dest, Target: target})
	}
	igw := fmt.Sprintf("igw-%d", v)
	switch {
	case i == 0 && g.hasIGW(v):
		add("0.0.0.0/0", igw)
	case i == 1 && hasNAT && g.chance(0.8):
		add("0.0.0.0/0", natID)
	case g.hasIGW(v) && g.chance(0.5):
		add("0.0.0.0/0", igw)
	}
	for _, p := range g.snap.Peerings {
		var peer string
		switch vpcID(v) {
		case p.RequesterVPC:
			peer = p.AccepterVPC
		case p.AccepterVPC:
			peer = p.RequesterVPC
		default:
			continue
		}
		if g.chance(0.85) {
			var n int
			_, _ = fmt.Sscanf(peer, "vpc-%d", &n)
			add(vpcCIDR(n), p.ID)
		}
	}
	for range g.p.ExtraRoutes {
		dest := pick(g, externalCIDRs[1:])
		targets := []string{"blackhole"}
		if g.hasIGW(v) {
			targets = append(targets, igw, igw)
		}
		if hasNAT && i == 1 {
			targets = append(targets, natID)
		}
		add(dest, pick(g, targets))
	}
	return rt
}
