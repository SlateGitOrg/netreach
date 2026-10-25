package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/archit2501/netreach/engine"
	"github.com/archit2501/netreach/interval"
	"github.com/archit2501/netreach/model"
	"github.com/archit2501/netreach/report"
	"github.com/archit2501/netreach/sim"
)

func (e *env) load(path string) (*model.Network, error) {
	if path == "" {
		return nil, usageErr("-s SNAPSHOT is required")
	}
	n, err := model.Load(path)
	if err != nil {
		if model.IsValidation(err) {
			return nil, &exitError{code: ExitUsage, err: err}
		}
		return nil, err
	}
	e.log.Debug("loaded snapshot", "name", n.Name, "enis", len(n.ENIs), "subnets", len(n.Subnets))
	return n, nil
}

// parseAddresses parses "internet" or a comma-separated CIDR list.
func parseAddresses(text string) (interval.Set, error) {
	if text == "" || text == "internet" {
		return interval.Full(interval.MaxIPv4), nil
	}
	var s interval.Set
	for _, part := range strings.Split(text, ",") {
		c, err := interval.ParseCIDR(part)
		if err != nil {
			return s, err
		}
		s = s.Union(c.Set())
	}
	return s, nil
}

// resolveENI finds an ENI by ENI ID or by instance ID (which must have
// exactly one interface).
func resolveENI(n *model.Network, id string) (*model.ENINode, error) {
	if e := n.ENI(id); e != nil {
		return e, nil
	}
	switch enis := n.ENIsOfInstance(id); len(enis) {
	case 0:
		return nil, usageErr("no ENI or instance %q in snapshot %s", id, n.Name)
	case 1:
		return enis[0], nil
	default:
		return nil, usageErr("instance %q has %d interfaces; name one ENI", id, len(enis))
	}
}

func isENIRef(n *model.Network, id string) bool {
	return n.ENI(id) != nil || len(n.ENIsOfInstance(id)) > 0
}

func (e *env) analyze(args []string) error {
	fs, verbose := e.newFlags("analyze")
	snap := fs.String("s", "", "snapshot JSON file")
	from := fs.String("from", "internet", `source: "internet", CIDR list, or ENI/instance ID`)
	egress := fs.Bool("egress", false, "analyse internet egress of the -from ENI (or of every ENI with -from all)")
	to := fs.String("to", "", "egress destinations as a CIDR list (default: everything outside the snapshot's VPCs)")
	target := fs.String("target", "", "only analyse this target ENI/instance")
	format := fs.String("format", "md", "output format: md or json")
	out := fs.String("o", "", "write the report to this file instead of stdout")
	failOn := fs.String("fail-on", "", "exit 3 if any finding is at least this severity (high, medium, low, info)")
	if err := e.parse(fs, verbose, args); err != nil {
		return err
	}
	if *format != "md" && *format != "json" {
		return usageErr("-format must be md or json")
	}
	threshold, err := parseSeverity(*failOn)
	if err != nil {
		return err
	}
	n, err := e.load(*snap)
	if err != nil {
		return err
	}
	an := engine.New(n, e.log)

	var results []engine.Result
	var kind engine.Kind
	var remote interval.Set
	switch {
	case *egress:
		kind = engine.InternetEgress
		remote = an.DefaultEgressDestinations()
		if *to != "" {
			if remote, err = parseAddresses(*to); err != nil {
				return usageErr("-to: %v", err)
			}
		}
		if *from == "all" {
			results = an.EgressAll(remote)
		} else {
			src, err := resolveENI(n, *from)
			if err != nil {
				return err
			}
			results = []engine.Result{an.Egress(src, remote)}
		}
	case isENIRef(n, *from):
		kind = engine.InternalIngress
		src, err := resolveENI(n, *from)
		if err != nil {
			return err
		}
		remote = interval.Single(src.PrivateIP)
		results = an.ExposureFrom(src)
	default:
		kind = engine.InternetIngress
		if remote, err = parseAddresses(*from); err != nil {
			return usageErr("-from: %v", err)
		}
		results = an.InternetExposure(remote)
	}
	if *target != "" {
		t, err := resolveENI(n, *target)
		if err != nil {
			return err
		}
		var kept []engine.Result
		for _, r := range results {
			if r.Subject == t {
				kept = append(kept, r)
			}
		}
		results = kept
	}
	rep := report.Build(n, kind, *from, remote, results)
	if err := e.write(*out, func(w io.Writer) error {
		if *format == "json" {
			return report.WriteJSON(w, rep)
		}
		return report.WriteMarkdown(w, rep)
	}); err != nil {
		return err
	}
	if threshold != "" {
		for _, t := range rep.Targets {
			for _, x := range t.Exposures {
				if x.Severity == threshold || report.Worse(x.Severity, threshold) {
					return &exitError{code: ExitFindings,
						err: fmt.Errorf("finding at or above %s: %s %s %s on %s", threshold, x.Severity, x.Protocol, x.Ports, t.ENI)}
				}
			}
		}
	}
	return nil
}

func parseSeverity(s string) (report.Severity, error) {
	switch sev := report.Severity(s); sev {
	case "", report.High, report.Medium, report.Low, report.Info:
		return sev, nil
	}
	return "", usageErr("-fail-on must be high, medium, low or info")
}

// write runs fn against stdout, or against a file created atomically enough
// for a CLI (written fully, then closed; errors reported).
func (e *env) write(path string, fn func(io.Writer) error) error {
	if path == "" {
		return fn(e.stdout)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(f)
	if err := fn(bw); err != nil {
		_ = f.Close()
		return err
	}
	if err := bw.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	e.errOut.printf("wrote %s\n", path)
	return nil
}

func (e *env) why(args []string) error {
	fs, verbose := e.newFlags("why")
	snap := fs.String("s", "", "snapshot JSON file")
	from := fs.String("from", "", "source: an IPv4 address (internet) or an ENI/instance ID")
	to := fs.String("to", "", "destination: an ENI/instance ID, or an IPv4 address for egress")
	proto := fs.String("proto", "tcp", "protocol: tcp, udp, icmp, or a number")
	port := fs.Uint("port", 443, "service (destination) port")
	sport := fs.Uint("sport", 49152, "initiator (source) port")
	if err := e.parse(fs, verbose, args); err != nil {
		return err
	}
	if *port > model.MaxPort || *sport > model.MaxPort {
		return usageErr("ports must be 0-65535")
	}
	n, err := e.load(*snap)
	if err != nil {
		return err
	}
	protoSet, err := model.ParseProtocol(*proto)
	if err != nil || protoSet.Size() != 1 {
		return usageErr("-proto must name a single protocol")
	}
	p, _ := protoSet.Min()
	pkt := sim.Packet{Proto: p, InitiatorPort: uint32(*sport), ServicePort: uint32(*port)}
	an := engine.New(n, e.log)

	var res engine.Result
	var remote uint32
	var simV sim.Verdict
	var desc string
	word := "from"
	switch {
	case isENIRef(n, *from) && isENIRef(n, *to):
		src, err := resolveENI(n, *from)
		if err != nil {
			return err
		}
		dst, err := resolveENI(n, *to)
		if err != nil {
			return err
		}
		if res, err = an.InternalIngress(src, dst); err != nil {
			return usageErr("%v", err)
		}
		remote = src.PrivateIP
		simV = sim.InternalIngress(n, src, dst, pkt)
		desc = fmt.Sprintf("%s -> %s", src.Label(), dst.Label())
	case isENIRef(n, *from):
		src, err := resolveENI(n, *from)
		if err != nil {
			return err
		}
		if remote, err = interval.ParseIPv4(*to); err != nil {
			return usageErr("-to must be an ENI/instance or an IPv4 address: %v", err)
		}
		res = an.Egress(src, interval.Full(interval.MaxIPv4))
		simV = sim.Egress(src, remote, pkt)
		desc = fmt.Sprintf("%s -> internet %s", src.Label(), *to)
		word = "to"
	default:
		if remote, err = interval.ParseIPv4(*from); err != nil {
			return usageErr("-from must be an ENI/instance or an IPv4 address: %v", err)
		}
		dst, err := resolveENI(n, *to)
		if err != nil {
			return err
		}
		res = an.InternetIngress(interval.Full(interval.MaxIPv4), dst)
		simV = sim.InternetIngress(remote, dst, pkt)
		desc = fmt.Sprintf("internet %s -> %s", *from, dst.Label())
	}
	flow := engine.Flow{Remote: remote, Proto: p, InitiatorPort: pkt.InitiatorPort, ServicePort: pkt.ServicePort}
	frag, allowed, _ := res.Locate(flow)
	verdict := "BLOCKED"
	if allowed {
		verdict = "ALLOWED"
	}
	c := flow.Canonical()
	e.out.printf("%s: %s %s, initiator port %d -> service port %d\n", verdict, desc,
		model.ProtocolName(protoSet), c.InitiatorPort, c.ServicePort)
	for i, h := range frag.Hops {
		mark := "ok  "
		if !h.Allowed {
			mark = "DROP"
		}
		e.out.printf("  %2d. [%s] %-24s %-16s %s\n", i+1, mark, h.Step, h.Component, h.Detail)
		if !h.Allowed && h.Step == engine.StepNATReturnPorts {
			if acl := n.ACL(h.Component); acl != nil {
				e.out.printf("      denied NAT ports for this destination and protocol: %s\n",
					engine.NATReturnDenied(acl, remote, p))
			}
		}
	}
	sum := report.Summarize(frag.Space)
	e.out.printf("Same decision for: %s %s %s\n", sum, word, report.DescribeAddresses(frag.Space.Project(engine.DimRemote)))
	engineV := sim.Verdict{Allowed: allowed}
	if !allowed {
		h := frag.Blocker()
		engineV.Step, engineV.Component = string(h.Step), h.Component
	}
	if engineV != simV {
		return fmt.Errorf("internal inconsistency: simulator says %+v", simV)
	}
	e.out.printf("Reference simulator: agrees\n")
	return nil
}

func (e *env) validate(args []string) error {
	fs, verbose := e.newFlags("validate")
	snap := fs.String("s", "", "snapshot JSON file")
	if err := e.parse(fs, verbose, args); err != nil {
		return err
	}
	n, err := e.load(*snap)
	if err != nil {
		return err
	}
	rules := 0
	for _, a := range n.ACLs {
		rules += len(a.Inbound) + len(a.Outbound)
	}
	for _, g := range n.SGs {
		rules += len(g.Inbound) + len(g.Outbound)
	}
	routes := 0
	for _, rt := range n.RouteTables {
		routes += len(rt.Routes)
	}
	e.out.printf("ok: %s: %d VPCs, %d subnets, %d route tables (%d routes), %d SGs + %d NACLs (%d rules), %d ENIs\n",
		n.Name, len(n.VPCs), len(n.Subnets), len(n.RouteTables), routes, len(n.SGs), len(n.ACLs), rules, len(n.ENIs))
	warnings := engine.Lint(n)
	for _, w := range warnings {
		e.out.printf("warning: %s\n", w)
	}
	if len(warnings) == 0 {
		e.out.printf("no warnings\n")
	}
	return nil
}

func writeJSONFile(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
