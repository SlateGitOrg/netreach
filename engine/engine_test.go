package engine_test

import (
	"strings"
	"testing"

	"github.com/archit2501/netreach/engine"
	"github.com/archit2501/netreach/interval"
	"github.com/archit2501/netreach/model"
	"github.com/archit2501/netreach/report"
)

func load(t *testing.T, name string) *model.Network {
	t.Helper()
	n, err := model.Load("../testdata/topologies/" + name + "/snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	return n
}

var all = interval.Full(interval.MaxIPv4)

func TestUniverseIsCanonical(t *testing.T) {
	u := engine.Universe()
	if !u.Contains(1, 6, 40000, 443) || u.Contains(1, 1, 5, 0) || !u.Contains(1, 1, 0, 0) {
		t.Fatal("non-port protocols must have both ports pinned to 0")
	}
	f := engine.Flow{Remote: 9, Proto: 1, InitiatorPort: 7, ServicePort: 8}.Canonical()
	if f.InitiatorPort != 0 || f.ServicePort != 0 {
		t.Fatal("Canonical")
	}
}

func TestLocateOutsideQueriedSpace(t *testing.T) {
	n := load(t, "public-web")
	an := engine.New(n, nil)
	office := interval.MustParseCIDR("203.0.113.0/24").Set()
	res := an.InternetIngress(office, n.ENI("eni-web"))
	if _, _, found := res.Locate(engine.Flow{Remote: 0x08080808, Proto: 6, InitiatorPort: 1, ServicePort: 22}); found {
		t.Fatal("8.8.8.8 is outside the queried source set")
	}
	frag, allowed, found := res.Locate(engine.Flow{Remote: 0xCB007105, Proto: 6, InitiatorPort: 1, ServicePort: 22})
	if !found || !allowed || len(frag.Hops) != 6 {
		t.Fatalf("office SSH should be allowed with a 6-hop path: %+v", frag.Hops)
	}
	if an.Network() != n {
		t.Fatal("Network accessor")
	}
}

func TestInternalIngressRejectsSelf(t *testing.T) {
	n := load(t, "peering")
	an := engine.New(n, nil)
	if _, err := an.InternalIngress(n.ENI("eni-a"), n.ENI("eni-a")); err == nil {
		t.Fatal("self query must fail")
	}
	if got := len(an.ExposureFrom(n.ENI("eni-a"))); got != 2 {
		t.Fatalf("ExposureFrom returned %d results", got)
	}
}

// TestNATReturnQuantifier pins the universally-quantified NAT check: replies
// must be admitted for every port the NAT may choose, not just one.
func TestNATReturnQuantifier(t *testing.T) {
	n := load(t, "nat-egress")
	an := engine.New(n, nil)
	res := an.Egress(n.ENI("eni-worker"), an.DefaultEgressDestinations())
	sum := report.Summarize(res.Reachable())
	if !sum.TCP.IsEmpty() || sum.UDP.String() != "53" {
		t.Fatalf("summary %v", sum)
	}
	var natBlock *engine.Fragment
	for i := range res.Blocked {
		if res.Blocked[i].Blocker().Step == engine.StepNATReturnPorts {
			natBlock = &res.Blocked[i]
		}
	}
	if natBlock == nil || !natBlock.Space.Contains(0x08080808, 6, 50000, 443) {
		t.Fatal("tcp 443 must be blocked by the NAT return-port quantifier")
	}
	if natBlock.Blocker().Allowed {
		t.Fatal("blocking hop must not be marked allowed")
	}
}

func TestEgressClassifiesInternalDestinations(t *testing.T) {
	n := load(t, "peering")
	an := engine.New(n, nil)
	res := an.Egress(n.ENI("eni-a"), all)
	if !res.Reachable().IsEmpty() {
		t.Fatal("no internet path exists in the peering fixture")
	}
	var internal bool
	for _, f := range res.Blocked {
		if strings.Contains(f.Blocker().Detail, "internal to the snapshot") {
			internal = true
		}
	}
	if !internal {
		t.Fatal("peering/local destinations must be reported as internal, not internet egress")
	}
}

func TestLint(t *testing.T) {
	cases := map[string][]string{
		"nacl-ordering": {"acl-dmz: inbound rule 130 (allow udp 1194) is shadowed: earlier rule(s) 120"},
		"route-shadow":  {"eni-island: has public IP 54.30.0.30", "igw-spare: is not attached"},
		"public-web":    nil,
	}
	for name, want := range cases {
		ws := engine.Lint(load(t, name))
		if len(ws) != len(want) {
			t.Fatalf("%s: got %v", name, ws)
		}
		for i, w := range want {
			if !strings.Contains(ws[i].String(), w) {
				t.Errorf("%s: warning %q lacks %q", name, ws[i], w)
			}
		}
	}
	// Synthetic: redundant SG rule, broken NAT.
	snap := &model.Snapshot{
		Name: "lint", VPCs: []model.VPC{{ID: "vpc-1", CIDRs: []string{"10.0.0.0/16"}}},
		NATGateways: []model.NATGateway{{ID: "nat-1", Subnet: "subnet-1", PrivateIP: "10.0.0.5", PublicIP: "52.0.0.1"}},
		Subnets:     []model.Subnet{{ID: "subnet-1", VPC: "vpc-1", CIDR: "10.0.0.0/24", RouteTable: "rtb-1", NetworkACL: "acl-1"}},
		RouteTables: []model.RouteTable{{ID: "rtb-1", VPC: "vpc-1"}},
		NetworkACLs: []model.NetworkACL{{ID: "acl-1", VPC: "vpc-1"}},
		SecurityGroups: []model.SecurityGroup{{ID: "sg-1", VPC: "vpc-1", Inbound: []model.SGRule{
			{Protocol: "tcp", Ports: "0-1023", CIDR: "0.0.0.0/0"},
			{Protocol: "tcp", Ports: "22", CIDR: "10.0.0.0/8"},
			{Protocol: "tcp", Ports: "22", Group: "sg-1"},
		}}},
		ENIs: []model.ENI{{ID: "eni-1", Subnet: "subnet-1", PrivateIP: "10.0.0.10", SecurityGroups: []string{"sg-1"}}},
	}
	n, err := model.Compile(snap)
	if err != nil {
		t.Fatal(err)
	}
	ws := engine.Lint(n)
	if len(ws) != 2 || !strings.Contains(ws[0].Message, "inbound rule #2") || ws[1].Component != "nat-1" {
		t.Fatalf("got %v", ws)
	}
}

func TestStringers(t *testing.T) {
	if engine.Inbound.String() != "inbound" || engine.Outbound.String() != "outbound" {
		t.Fatal("Direction")
	}
}

func TestNATReturnDenied(t *testing.T) {
	n := load(t, "nat-egress")
	acl := n.ACL("acl-pub")
	if acl == nil || n.ACL("nope") != nil {
		t.Fatal("ACL lookup")
	}
	if got := engine.NATReturnDenied(acl, 0x08080808, 6).String(); got != "1024-2047" {
		t.Fatalf("tcp denied ports = %s", got)
	}
	if !engine.NATReturnDenied(acl, 0x08080808, 17).IsEmpty() || !engine.NATReturnDenied(acl, 0x08080808, 1).IsEmpty() {
		t.Fatal("udp replies are allowed and ICMP has no ports")
	}
}
