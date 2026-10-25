package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/archit2501/netreach/engine"
	"github.com/archit2501/netreach/interval"
	"github.com/archit2501/netreach/model"
)

func set(t *testing.T, text string) interval.Set {
	t.Helper()
	s, err := interval.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestAssess(t *testing.T) {
	all := interval.Full(interval.MaxIPv4)
	office := interval.MustParseCIDR("203.0.113.0/24").Set()
	cases := []struct {
		proto  uint32
		ports  string
		remote interval.Set
		want   Severity
		reason string
	}{
		{model.ProtoTCP, "22", all, High, "SSH (22) open to the internet"},
		{model.ProtoTCP, "3300-3400", all, High, "MySQL (3306)"},
		{model.ProtoTCP, "0-65535", all, High, "every port"},
		{model.ProtoTCP, "22", office, Low, "restricted"},
		{model.ProtoTCP, "80,443", all, Info, "web ports"},
		{model.ProtoUDP, "443", all, Medium, "non-web"},
		{model.ProtoTCP, "8080", all, Medium, "non-web"},
		{model.ProtoUDP, "161", all, High, "SNMP"},
		{model.ProtoICMP, "", all, Info, "ICMP"},
		{47, "", all, Medium, "protocol 47"},
	}
	for _, c := range cases {
		sev, reason := Assess(c.proto, set(t, c.ports), c.remote)
		if sev != c.want || !strings.Contains(reason, c.reason) {
			t.Errorf("Assess(%d, %s) = %s %q, want %s containing %q", c.proto, c.ports, sev, reason, c.want, c.reason)
		}
	}
	if !Worse(High, Low) || Worse(Info, Medium) {
		t.Fatal("Worse ordering")
	}
}

func TestDescribeAddresses(t *testing.T) {
	all := interval.Full(interval.MaxIPv4)
	vpc := interval.MustParseCIDR("10.0.0.0/16").Set()
	cases := []struct {
		in   interval.Set
		want string
	}{
		{interval.Set{}, "none"},
		{all, "0.0.0.0/0"},
		{all.Subtract(vpc), "0.0.0.0/0 except 10.0.0.0/16"},
		{interval.MustParseCIDR("203.0.113.0/24").Set(), "203.0.113.0/24"},
		{interval.Span(1, 14), "0.0.0.1/32, 0.0.0.2/31, 0.0.0.4/30, 0.0.0.8/30, 0.0.0.12/31, 0.0.0.14/32"},
		{interval.Span(1, 30), "0.0.0.1/32, 0.0.0.2/31, 0.0.0.4/30, 0.0.0.8/29, 0.0.0.16/29, 0.0.0.24/30 (+2 more)"},
	}
	for _, c := range cases {
		if got := DescribeAddresses(c.in); got != c.want {
			t.Errorf("DescribeAddresses(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildAndRender(t *testing.T) {
	n, err := model.Load("../testdata/topologies/nacl-ordering/snapshot.json")
	if err != nil {
		t.Fatal(err)
	}
	an := engine.New(n, nil)
	all := interval.Full(interval.MaxIPv4)
	rep := Build(n, engine.InternetIngress, "internet", all, an.InternetExposure(all))
	if rep.Summary.Targets != 1 || rep.Summary.Reachable != 1 {
		t.Fatalf("summary %+v", rep.Summary)
	}
	tgt := rep.Targets[0]
	if tgt.Open.TCP != "22,443" || tgt.Open.Other != "1" || tgt.Severity != High {
		t.Fatalf("target %+v", tgt)
	}
	if tgt.Exposures[0].Severity != High || tgt.Exposures[0].Ports != "22" ||
		tgt.Exposures[0].InitiatorPorts != "1024-65535" {
		t.Fatalf("first exposure should be SSH with ephemeral client ports: %+v", tgt.Exposures[0])
	}
	var md, js bytes.Buffer
	if err := WriteMarkdown(&md, rep); err != nil {
		t.Fatal(err)
	}
	if err := WriteJSON(&js, rep); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"# netreach report: nacl-ordering", "| high | tcp | 22 |",
		"inbound rule 90 deny tcp 22 from 198.51.100.0/24", "Findings: 1 high"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || back.Targets[0].ENI != "eni-vpn" {
		t.Fatalf("json round trip: %v", err)
	}

	// Egress reports label remotes as destinations and are not graded.
	eg := Build(n, engine.InternetEgress, "eni-vpn", all, an.EgressAll(all))
	md.Reset()
	if err := WriteMarkdown(&md, eg); err != nil {
		t.Fatal(err)
	}
	if eg.Query.RemoteRole != "destination" || !strings.Contains(md.String(), "| Destinations |") {
		t.Fatal("egress labelling")
	}
	for _, x := range eg.Targets[0].Exposures {
		if x.Severity != Info {
			t.Fatalf("egress exposure graded %s", x.Severity)
		}
	}
}

func TestPortSummaryString(t *testing.T) {
	p := PortSummary{TCP: interval.Full(model.MaxPort), UDP: interval.Single(53), Other: interval.Single(1)}
	if got := p.String(); got != "tcp all ports; udp 53; proto icmp" {
		t.Fatal(got)
	}
	if (PortSummary{}).String() != "nothing" || !(PortSummary{}).IsEmpty() {
		t.Fatal("empty summary")
	}
}

func TestMarkdownTruncatesBlockedRows(t *testing.T) {
	tgt := Target{ENI: "eni-x", Subnet: "s", VPC: "v"}
	for range maxBlockedRows + 3 {
		tgt.Blocked = append(tgt.Blocked, Blocked{Step: engine.StepSGInbound, Component: "sg", Detail: "a|b", Flows: "tcp 1"})
	}
	var md bytes.Buffer
	if err := WriteMarkdown(&md, Report{Snapshot: "x", Targets: []Target{tgt}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "3 more blocked classes") || !strings.Contains(md.String(), `a\|b`) {
		t.Fatal(md.String())
	}
}
