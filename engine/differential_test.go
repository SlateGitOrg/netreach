package engine_test

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/SlateGitOrg/netreach/engine"
	"github.com/SlateGitOrg/netreach/hspace"
	"github.com/SlateGitOrg/netreach/interval"
	"github.com/SlateGitOrg/netreach/model"
	"github.com/SlateGitOrg/netreach/sim"
	"github.com/SlateGitOrg/netreach/topogen"
)

// sampler draws flows biased toward rule boundaries: every CIDR edge and port
// edge in the snapshot (±1) is a candidate, plus uniform noise.
type sampler struct {
	rng   *rand.Rand
	ips   []uint32
	ports []uint32
}

func newSampler(seed uint64, n *model.Network) *sampler {
	s := &sampler{rng: rand.New(rand.NewPCG(seed, 99))}
	addIP := func(c interval.CIDR) {
		r := c.Range()
		s.ips = append(s.ips, r.Lo, r.Hi, r.Lo-1, r.Hi+1, r.Lo+(r.Hi-r.Lo)/2)
	}
	addPorts := func(m model.Match) {
		for _, r := range m.Ports.Ranges() {
			s.ports = append(s.ports, r.Lo, r.Hi, r.Lo-1, r.Hi+1)
		}
	}
	for _, a := range n.ACLs {
		for _, e := range append(append([]model.ACLEntryNode{}, a.Inbound...), a.Outbound...) {
			addIP(e.CIDR)
			addPorts(e.Match)
		}
	}
	for _, g := range n.SGs {
		for _, r := range append(append([]model.SGRuleNode{}, g.Inbound...), g.Outbound...) {
			if r.HasCIDR {
				addIP(r.CIDR)
			}
			addPorts(r.Match)
		}
	}
	for _, rt := range n.RouteTables {
		for _, r := range rt.Routes {
			addIP(r.Dest)
		}
	}
	s.ports = append(s.ports, 0, 1023, 1024, 2047, 2048, 65535)
	return s
}

func (s *sampler) ip() uint32 {
	if s.rng.IntN(10) < 7 {
		return s.ips[s.rng.IntN(len(s.ips))]
	}
	return s.rng.Uint32()
}

func (s *sampler) port() uint32 {
	if s.rng.IntN(10) < 7 {
		return s.ports[s.rng.IntN(len(s.ports))] & 0xffff
	}
	return uint32(s.rng.IntN(model.MaxPort + 1))
}

func (s *sampler) proto() uint32 {
	return []uint32{6, 6, 6, 17, 17, 1, 47, 0}[s.rng.IntN(8)]
}

func (s *sampler) packet() sim.Packet {
	return sim.Packet{Proto: s.proto(), InitiatorPort: s.port(), ServicePort: s.port()}
}

func engineVerdict(t *testing.T, res *engine.Result, f engine.Flow) sim.Verdict {
	t.Helper()
	frag, allowed, found := res.Locate(f)
	if !found {
		t.Fatalf("flow %+v not covered by result for %s", f, res.Subject.ID)
	}
	if allowed {
		return sim.Verdict{Allowed: true}
	}
	h := frag.Blocker()
	return sim.Verdict{Step: string(h.Step), Component: h.Component}
}

// checkPartition asserts that allowed and blocked fragments are pairwise
// disjoint and exactly cover the queried space.
func checkPartition(t *testing.T, res *engine.Result, queried hspace.Space) {
	t.Helper()
	frags := append(append([]engine.Fragment{}, res.Allowed...), res.Blocked...)
	union := queried.Empty()
	for i, f := range frags {
		for _, g := range frags[i+1:] {
			if !f.Space.Intersect(g.Space).IsEmpty() {
				t.Fatalf("%s: fragments overlap", res.Subject.ID)
			}
		}
		union = union.Union(f.Space)
	}
	if !union.Equal(queried) {
		t.Fatalf("%s: fragments do not cover the queried space", res.Subject.ID)
	}
}

const (
	differentialSeeds   = 40
	samplesPerQuery     = 150
	egressSamplesPerENI = 40 // the simulator brute-forces 64k NAT ports per egress flow
)

func TestDifferentialEngineVersusSimulator(t *testing.T) {
	all := interval.Full(interval.MaxIPv4)
	total, allowedCount := 0, 0
	steps := map[string]int{}
	for seed := uint64(1); seed <= differentialSeeds; seed++ {
		snap, err := topogen.Generate(topogen.Small(seed))
		if err != nil {
			t.Fatal(err)
		}
		net, err := model.Compile(snap)
		if err != nil {
			t.Fatalf("seed %d: generated snapshot invalid: %v", seed, err)
		}
		an := engine.New(net, nil)
		smp := newSampler(seed, net)
		label := fmt.Sprintf("seed %d", seed)

		for _, target := range net.ENIs {
			res := an.InternetIngress(all, target)
			checkPartition(t, &res, engine.Universe())
			for range samplesPerQuery {
				src, pkt := smp.ip(), smp.packet()
				want := sim.InternetIngress(src, target, pkt)
				got := engineVerdict(t, &res, engine.Flow{Remote: src, Proto: pkt.Proto,
					InitiatorPort: pkt.InitiatorPort, ServicePort: pkt.ServicePort})
				if got != want {
					t.Fatalf("%s internet %s -> %s %+v: engine %+v, simulator %+v", label,
						interval.FormatIPv4(src), target.ID, pkt, got, want)
				}
				total++
				steps[got.Step]++
				if got.Allowed {
					allowedCount++
				}
			}

			for _, src := range net.ENIs {
				if src == target {
					continue
				}
				res, err := an.InternalIngress(src, target)
				if err != nil {
					t.Fatal(err)
				}
				queried := engine.Universe().Restrict(engine.DimRemote, interval.Single(src.PrivateIP))
				checkPartition(t, &res, queried)
				for range samplesPerQuery / 5 {
					pkt := smp.packet()
					want := sim.InternalIngress(net, src, target, pkt)
					got := engineVerdict(t, &res, engine.Flow{Remote: src.PrivateIP, Proto: pkt.Proto,
						InitiatorPort: pkt.InitiatorPort, ServicePort: pkt.ServicePort})
					if got != want {
						t.Fatalf("%s internal %s -> %s %+v: engine %+v, simulator %+v", label,
							src.ID, target.ID, pkt, got, want)
					}
					total++
					steps[got.Step]++
					if got.Allowed {
						allowedCount++
					}
				}
			}

			eg := an.Egress(target, all)
			checkPartition(t, &eg, engine.Universe())
			for range egressSamplesPerENI {
				dst, pkt := smp.ip(), smp.packet()
				want := sim.Egress(target, dst, pkt)
				got := engineVerdict(t, &eg, engine.Flow{Remote: dst, Proto: pkt.Proto,
					InitiatorPort: pkt.InitiatorPort, ServicePort: pkt.ServicePort})
				if got != want {
					t.Fatalf("%s egress %s -> %s %+v: engine %+v, simulator %+v", label,
						target.ID, interval.FormatIPv4(dst), pkt, got, want)
				}
				total++
				steps[got.Step]++
				if got.Allowed {
					allowedCount++
				}
			}
		}
	}
	t.Logf("%d sampled flows agreed (%d allowed, %d blocked); deciding steps: %v",
		total, allowedCount, total-allowedCount, steps)
	for _, st := range []engine.Step{engine.StepSGOutbound, engine.StepRoute, engine.StepNACLOutbound,
		engine.StepIGW, engine.StepPublicIP, engine.StepNACLInbound, engine.StepSGInbound, engine.StepNACLOutReturn,
		engine.StepRouteReturn, engine.StepNACLInReturn, engine.StepNATNACLInbound, engine.StepNAT,
		engine.StepNATRoute, engine.StepNATNACLOutbound, engine.StepNATReturnPorts, engine.StepNATNACLOutReturn} {
		if steps[string(st)] == 0 {
			t.Errorf("no sampled flow was decided at step %s; the generator no longer exercises it", st)
		}
	}
	if allowedCount == 0 || allowedCount == total {
		t.Fatalf("degenerate sample: %d of %d allowed", allowedCount, total)
	}
}
