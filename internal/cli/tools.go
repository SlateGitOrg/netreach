package cli

import (
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/archit2501/netreach/engine"
	"github.com/archit2501/netreach/internal/groundtruth"
	"github.com/archit2501/netreach/interval"
	"github.com/archit2501/netreach/model"
	"github.com/archit2501/netreach/topogen"
)

func (e *env) verify(args []string) error {
	fs, verbose := e.newFlags("verify")
	dir := fs.String("dir", "testdata/topologies", "directory of fixture topologies (snapshot.json + expected.json)")
	if err := e.parse(fs, verbose, args); err != nil {
		return err
	}
	fixtures, err := groundtruth.LoadDir(*dir)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, "%-16s %7s %7s %9s\n", "fixture", "checks", "probes", "failures")
	checks, probes, failures := 0, 0, 0
	for _, fx := range fixtures {
		out := groundtruth.Check(fx)
		fmt.Fprintf(e.stdout, "%-16s %7d %7d %9d\n", out.Name, out.Checks, out.Probes, len(out.Failures))
		for _, f := range out.Failures {
			fmt.Fprintf(e.stdout, "    FAIL %s\n", f)
		}
		checks += out.Checks
		probes += out.Probes
		failures += len(out.Failures)
	}
	fmt.Fprintf(e.stdout, "%-16s %7d %7d %9d\n", "total", checks, probes, failures)
	if failures > 0 {
		return fmt.Errorf("%d ground-truth checks failed", failures)
	}
	return nil
}

func (e *env) gen(args []string) error {
	fs, verbose := e.newFlags("gen")
	seed := fs.Uint64("seed", 1, "random seed")
	vpcs := fs.Int("vpcs", 2, "number of VPCs")
	subnets := fs.Int("subnets", 2, "subnets per VPC")
	enis := fs.Int("enis", 2, "ENIs per subnet")
	rules := fs.Int("rules", 5, "rules per NACL direction and per security group")
	out := fs.String("o", "", "output file (default stdout)")
	if err := e.parse(fs, verbose, args); err != nil {
		return err
	}
	p := topogen.Small(*seed)
	p.VPCs, p.SubnetsPerVPC, p.ENIsPerSubnet, p.ACLRules, p.SGRules = *vpcs, *subnets, *enis, *rules, *rules
	snap, err := topogen.Generate(p)
	if err != nil {
		return usageErr("%v", err)
	}
	return e.write(*out, func(w io.Writer) error { return writeJSONFile(w, snap) })
}

type benchRow struct {
	label             string
	enis, rules       int
	ingress, egress   time.Duration
	internal          time.Duration
	boxes, fragments  int
}

func (e *env) bench(args []string) error {
	fs, verbose := e.newFlags("bench")
	sizes := fs.String("sizes", "1,2,4,8", "VPC counts for the scale-out table")
	depths := fs.String("depths", "5,10,20,40,80", "rules per NACL direction / SG for the rule-depth table")
	seed := fs.Uint64("seed", 7, "random seed")
	repeats := fs.Int("repeats", 3, "runs per row; the median is reported")
	if err := e.parse(fs, verbose, args); err != nil {
		return err
	}
	sizeList, err := intList(*sizes)
	if err != nil {
		return usageErr("-sizes: %v", err)
	}
	depthList, err := intList(*depths)
	if err != nil {
		return usageErr("-depths: %v", err)
	}
	if *repeats < 1 {
		return usageErr("-repeats must be >= 1")
	}
	base := topogen.Params{Seed: *seed, VPCs: 1, SubnetsPerVPC: 4, ENIsPerSubnet: 4, SGsPerVPC: 4,
		SGRules: 8, ACLRules: 10, ExtraRoutes: 4, PeeringProbability: 0.5}

	fmt.Fprintf(e.stdout, "Scale-out (4 subnets x 4 ENIs per VPC, 8 SG rules, 10 NACL rules/direction, seed %d)\n\n", *seed)
	var rows []benchRow
	for _, v := range sizeList {
		p := base
		p.VPCs = v
		row, err := benchOne(fmt.Sprintf("%d VPCs", v), p, *repeats)
		if err != nil {
			return err
		}
		rows = append(rows, row)
	}
	printBench(e.stdout, rows)

	fmt.Fprintf(e.stdout, "\nRule depth (2 VPCs, 4 subnets x 4 ENIs each, seed %d)\n\n", *seed)
	rows = rows[:0]
	for _, d := range depthList {
		p := base
		p.VPCs, p.ACLRules, p.SGRules = 2, d, d
		row, err := benchOne(fmt.Sprintf("%d rules", d), p, *repeats)
		if err != nil {
			return err
		}
		rows = append(rows, row)
	}
	printBench(e.stdout, rows)
	return nil
}

func intList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("bad value %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}

func benchOne(label string, p topogen.Params, repeats int) (benchRow, error) {
	snap, err := topogen.Generate(p)
	if err != nil {
		return benchRow{}, usageErr("%v", err)
	}
	n, err := model.Compile(snap)
	if err != nil {
		return benchRow{}, fmt.Errorf("generated snapshot invalid: %w", err)
	}
	row := benchRow{label: label, enis: len(n.ENIs)}
	for _, a := range n.ACLs {
		row.rules += len(a.Inbound) + len(a.Outbound)
	}
	for _, g := range n.SGs {
		row.rules += len(g.Inbound) + len(g.Outbound)
	}
	all := interval.Full(interval.MaxIPv4)
	var ing, egr, inte []time.Duration
	for range repeats {
		an := engine.New(n, nil)
		start := time.Now()
		results := an.InternetExposure(all)
		ing = append(ing, time.Since(start))

		start = time.Now()
		_ = an.EgressAll(an.DefaultEgressDestinations())
		egr = append(egr, time.Since(start))

		start = time.Now()
		_ = an.ExposureFrom(n.ENIs[0])
		inte = append(inte, time.Since(start))

		row.boxes, row.fragments = 0, 0
		for _, r := range results {
			for _, f := range append(slices.Clone(r.Allowed), r.Blocked...) {
				row.boxes += f.Space.NumBoxes()
				row.fragments++
			}
		}
	}
	row.ingress, row.egress, row.internal = median(ing), median(egr), median(inte)
	return row, nil
}

func median(ds []time.Duration) time.Duration {
	s := slices.Clone(ds)
	slices.Sort(s)
	return s[len(s)/2]
}

func printBench(w io.Writer, rows []benchRow) {
	fmt.Fprintln(w, "| Shape | ENIs | Rules | Internet ingress (all ENIs) | Egress (all ENIs) | Internal (1 src -> all) | Fragments | Boxes |")
	fmt.Fprintln(w, "|---|---|---|---|---|---|---|---|")
	for _, r := range rows {
		fmt.Fprintf(w, "| %s | %d | %d | %s | %s | %s | %d | %d |\n", r.label, r.enis, r.rules,
			round(r.ingress), round(r.egress), round(r.internal), r.fragments, r.boxes)
	}
}

func round(d time.Duration) string {
	switch {
	case d >= time.Second:
		return d.Round(10 * time.Millisecond).String()
	case d >= time.Millisecond:
		return d.Round(10 * time.Microsecond).String()
	}
	return d.Round(time.Microsecond).String()
}
