// Package groundtruth checks the engine (and the reference simulator) against
// hand-derived expectations stored next to each fixture topology in
// expected.json. It is used by the test suite and by `netreach verify`.
package groundtruth

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/archit2501/netreach/engine"
	"github.com/archit2501/netreach/interval"
	"github.com/archit2501/netreach/model"
	"github.com/archit2501/netreach/report"
	"github.com/archit2501/netreach/sim"
)

// Expected is the schema of expected.json.
type Expected struct {
	Comment              string                 `json:"comment"`
	Exposure             map[string]Open        `json:"exposure"`
	Sources              []SourceExpectation    `json:"sources,omitempty"`
	InitiatorPorts       []PortExpectation      `json:"initiatorPorts,omitempty"`
	Egress               map[string]Open        `json:"egress,omitempty"`
	EgressInitiatorPorts []PortExpectation      `json:"egressInitiatorPorts,omitempty"`
	Internal             []InternalExpectation  `json:"internal,omitempty"`
	Probes               []Probe                `json:"probes"`
}

// Open is an expected port summary; empty strings mean "nothing".
type Open struct {
	TCP   string `json:"tcp"`
	UDP   string `json:"udp"`
	Other string `json:"other"`
}

// SourceExpectation: the internet addresses reaching (eni, proto, port) are
// exactly include minus exclude.
type SourceExpectation struct {
	ENI     string   `json:"eni"`
	Proto   string   `json:"proto"`
	Port    uint32   `json:"port"`
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

// PortExpectation: the initiator ports that work for (eni, proto, port).
type PortExpectation struct {
	ENI   string `json:"eni"`
	Proto string `json:"proto"`
	Port  uint32 `json:"port"`
	Ports string `json:"ports"`
}

// InternalExpectation: the services From can reach on To.
type InternalExpectation struct {
	From  string `json:"from"`
	To    string `json:"to"`
	TCP   string `json:"tcp"`
	UDP   string `json:"udp"`
	Other string `json:"other"`
}

// Probe is one concrete flow with its expected verdict.
type Probe struct {
	Kind          string `json:"kind"` // internet | internal | egress
	From          string `json:"from"` // IP for internet, ENI otherwise
	To            string `json:"to"`   // ENI, or IP for egress
	Proto         string `json:"proto"`
	InitiatorPort uint32 `json:"initiatorPort"`
	ServicePort   uint32 `json:"servicePort"`
	Expect        string `json:"expect"` // allow | block
	Step          string `json:"step,omitempty"`
	Component     string `json:"component,omitempty"`
}

// Outcome is the result of checking one fixture.
type Outcome struct {
	Name     string
	Checks   int
	Probes   int
	Failures []string
}

// Fixture is a snapshot plus its expectations.
type Fixture struct {
	Name     string
	Dir      string
	Network  *model.Network
	Expected Expected
}

// LoadDir loads every fixture directory (containing snapshot.json and
// expected.json) under root, sorted by name.
func LoadDir(root string) ([]Fixture, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []Fixture
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		f, err := Load(filepath.Join(root, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Load loads one fixture directory.
func Load(dir string) (Fixture, error) {
	net, err := model.Load(filepath.Join(dir, "snapshot.json"))
	if err != nil {
		return Fixture{}, err
	}
	raw, err := os.ReadFile(filepath.Join(dir, "expected.json"))
	if err != nil {
		return Fixture{}, err
	}
	var exp Expected
	if err := json.Unmarshal(raw, &exp); err != nil {
		return Fixture{}, fmt.Errorf("%s/expected.json: %w", dir, err)
	}
	return Fixture{Name: filepath.Base(dir), Dir: dir, Network: net, Expected: exp}, nil
}

type checker struct {
	fx  Fixture
	an  *engine.Analyzer
	out Outcome
}

func (c *checker) expect(ok bool, format string, args ...any) {
	c.out.Checks++
	if !ok {
		c.out.Failures = append(c.out.Failures, fmt.Sprintf(format, args...))
	}
}

func (c *checker) eni(id string) *model.ENINode {
	e := c.fx.Network.ENI(id)
	if e == nil {
		c.expect(false, "unknown eni %q in expected.json", id)
	}
	return e
}

// Check runs every expectation of fx against the engine and the simulator.
func Check(fx Fixture) Outcome {
	c := &checker{fx: fx, an: engine.New(fx.Network, nil), out: Outcome{Name: fx.Name}}
	c.exposure()
	c.egress()
	c.internal()
	for _, p := range fx.Expected.Probes {
		c.probe(p)
	}
	return c.out
}

func (c *checker) compareOpen(what string, got report.PortSummary, want Open) {
	g := Open{TCP: text(got.TCP), UDP: text(got.UDP), Other: text(got.Other)}
	c.expect(g == want, "%s: got tcp=%q udp=%q other=%q, want tcp=%q udp=%q other=%q",
		what, g.TCP, g.UDP, g.Other, want.TCP, want.UDP, want.Other)
}

func text(s interval.Set) string {
	if s.IsEmpty() {
		return ""
	}
	return s.String()
}

func (c *checker) exposure() {
	all := interval.Full(interval.MaxIPv4)
	c.expect(len(c.fx.Expected.Exposure) == len(c.fx.Network.ENIs),
		"exposure expectations must cover all %d ENIs, got %d", len(c.fx.Network.ENIs), len(c.fx.Expected.Exposure))
	reach := map[string]engine.Result{}
	for id, want := range c.fx.Expected.Exposure {
		e := c.eni(id)
		if e == nil {
			continue
		}
		res := c.an.InternetIngress(all, e)
		reach[id] = res
		c.compareOpen("exposure "+id, report.Summarize(res.Reachable()), want)
	}
	for _, s := range c.fx.Expected.Sources {
		res, ok := reach[s.ENI]
		proto, err := model.ParseProtocol(s.Proto)
		if !ok || err != nil {
			c.expect(false, "sources: bad expectation %+v", s)
			continue
		}
		p, _ := proto.Min()
		want, err := cidrSet(s.Include, s.Exclude)
		if err != nil {
			c.expect(false, "sources %s: %v", s.ENI, err)
			continue
		}
		got := report.RemotesFor(res.Reachable(), p, s.Port)
		c.expect(got.Equal(want), "sources %s %s/%d: got %s, want %s", s.ENI, s.Proto, s.Port,
			report.DescribeAddresses(got), report.DescribeAddresses(want))
	}
	for _, s := range c.fx.Expected.InitiatorPorts {
		if res, ok := reach[s.ENI]; ok {
			c.initiatorPorts("initiator ports", res, s)
		}
	}
}

func (c *checker) initiatorPorts(what string, res engine.Result, s PortExpectation) {
	proto, err := model.ParseProtocol(s.Proto)
	if err != nil {
		c.expect(false, "%s: %v", what, err)
		return
	}
	p, _ := proto.Min()
	got := report.InitiatorPortsFor(res.Reachable(), p, s.Port)
	c.expect(got.String() == s.Ports, "%s %s %s/%d: got %s, want %s", what, s.ENI, s.Proto, s.Port, got, s.Ports)
}

func cidrSet(include, exclude []string) (interval.Set, error) {
	var in, ex interval.Set
	for _, t := range include {
		c, err := interval.ParseCIDR(t)
		if err != nil {
			return in, err
		}
		in = in.Union(c.Set())
	}
	for _, t := range exclude {
		c, err := interval.ParseCIDR(t)
		if err != nil {
			return in, err
		}
		ex = ex.Union(c.Set())
	}
	return in.Subtract(ex), nil
}

func (c *checker) egress() {
	dests := c.an.DefaultEgressDestinations()
	results := map[string]engine.Result{}
	for id, want := range c.fx.Expected.Egress {
		e := c.eni(id)
		if e == nil {
			continue
		}
		res := c.an.Egress(e, dests)
		results[id] = res
		c.compareOpen("egress "+id, report.Summarize(res.Reachable()), want)
	}
	for _, s := range c.fx.Expected.EgressInitiatorPorts {
		res, ok := results[s.ENI]
		if !ok {
			e := c.eni(s.ENI)
			if e == nil {
				continue
			}
			res = c.an.Egress(e, dests)
		}
		c.initiatorPorts("egress initiator ports", res, s)
	}
}

func (c *checker) internal() {
	for _, x := range c.fx.Expected.Internal {
		src, dst := c.eni(x.From), c.eni(x.To)
		if src == nil || dst == nil {
			continue
		}
		res, err := c.an.InternalIngress(src, dst)
		if err != nil {
			c.expect(false, "internal %s->%s: %v", x.From, x.To, err)
			continue
		}
		c.compareOpen(fmt.Sprintf("internal %s->%s", x.From, x.To), report.Summarize(res.Reachable()),
			Open{TCP: x.TCP, UDP: x.UDP, Other: x.Other})
	}
}

// probe checks one flow three ways: expected verdict, engine verdict (the
// fragment containing the flow), simulator verdict.
func (c *checker) probe(p Probe) {
	c.out.Probes++
	name := fmt.Sprintf("probe %s %s->%s %s %d->%d", p.Kind, p.From, p.To, p.Proto, p.InitiatorPort, p.ServicePort)
	protoSet, err := model.ParseProtocol(p.Proto)
	if err != nil {
		c.expect(false, "%s: %v", name, err)
		return
	}
	proto, _ := protoSet.Min()
	pkt := sim.Packet{Proto: proto, InitiatorPort: p.InitiatorPort, ServicePort: p.ServicePort}
	var res engine.Result
	var simV sim.Verdict
	var remote uint32
	switch p.Kind {
	case "internet":
		ip, err1 := interval.ParseIPv4(p.From)
		dst := c.eni(p.To)
		if err1 != nil || dst == nil {
			c.expect(false, "%s: bad probe", name)
			return
		}
		remote = ip
		res = c.an.InternetIngress(interval.Full(interval.MaxIPv4), dst)
		simV = sim.InternetIngress(c.fx.Network, ip, dst, pkt)
	case "internal":
		src, dst := c.eni(p.From), c.eni(p.To)
		if src == nil || dst == nil {
			return
		}
		remote = src.PrivateIP
		res, err = c.an.InternalIngress(src, dst)
		if err != nil {
			c.expect(false, "%s: %v", name, err)
			return
		}
		simV = sim.InternalIngress(c.fx.Network, src, dst, pkt)
	case "egress":
		src := c.eni(p.From)
		ip, err1 := interval.ParseIPv4(p.To)
		if src == nil || err1 != nil {
			c.expect(false, "%s: bad probe", name)
			return
		}
		remote = ip
		res = c.an.Egress(src, interval.Full(interval.MaxIPv4))
		simV = sim.Egress(c.fx.Network, src, ip, pkt)
	default:
		c.expect(false, "%s: unknown kind", name)
		return
	}
	flow := engine.Flow{Remote: remote, Proto: proto, InitiatorPort: p.InitiatorPort, ServicePort: p.ServicePort}
	frag, allowed, found := res.Locate(flow)
	if !found {
		c.expect(false, "%s: engine has no fragment for the flow", name)
		return
	}
	engineV := sim.Verdict{Allowed: allowed}
	if !allowed {
		h := frag.Blocker()
		engineV.Step, engineV.Component = string(h.Step), h.Component
	}
	want := sim.Verdict{Allowed: p.Expect == "allow", Step: p.Step, Component: p.Component}
	c.expect(engineV == want, "%s: engine says %+v, ground truth %+v", name, engineV, want)
	c.expect(simV == want, "%s: simulator says %+v, ground truth %+v", name, simV, want)
}
