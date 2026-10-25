package engine

import (
	"strings"

	"github.com/archit2501/netreach/hspace"
)

// Step names the kind of check a hop records. Each step appears at most once
// on any path, so (Step, Component) identifies where a flow was decided.
type Step string

// Steps, in the order they can occur.
const (
	StepSGOutbound       Step = "sg-outbound"
	StepRoute            Step = "route"
	StepNACLOutbound     Step = "nacl-outbound"
	StepIGW              Step = "internet-gateway"
	StepPublicIP         Step = "public-ip"
	StepNACLInbound      Step = "nacl-inbound"
	StepSGInbound        Step = "sg-inbound"
	StepNACLOutReturn    Step = "nacl-outbound-return"
	StepRouteReturn      Step = "route-return"
	StepNACLInReturn     Step = "nacl-inbound-return"
	StepNATNACLInbound   Step = "nat-nacl-inbound"
	StepNAT              Step = "nat-gateway"
	StepNATRoute         Step = "nat-route"
	StepNATNACLOutbound  Step = "nat-nacl-outbound"
	StepNATReturnPorts   Step = "nat-nacl-inbound-return"
	StepNATNACLOutReturn Step = "nat-nacl-outbound-return"
)

// Hop is one decision on a flow's path.
type Hop struct {
	Step      Step   `json:"step"`
	Component string `json:"component"`
	Allowed   bool   `json:"allowed"`
	Detail    string `json:"detail"`
}

// Fragment is a set of flows that took exactly the same decisions. For an
// allowed fragment every hop is an allow; for a blocked fragment the last hop
// is the one that dropped it.
type Fragment struct {
	Space hspace.Space
	Hops  []Hop
}

// Blocker returns the deciding hop of a blocked fragment.
func (f Fragment) Blocker() Hop { return f.Hops[len(f.Hops)-1] }

func (f Fragment) with(space hspace.Space, h Hop) Fragment {
	hops := make([]Hop, len(f.Hops), len(f.Hops)+1)
	copy(hops, f.Hops)
	return Fragment{Space: space, Hops: append(hops, h)}
}

func (f Fragment) key() string {
	var sb strings.Builder
	for _, h := range f.Hops {
		sb.WriteString(string(h.Step))
		sb.WriteByte('\x00')
		sb.WriteString(h.Component)
		sb.WriteByte('\x00')
		sb.WriteString(h.Detail)
		sb.WriteByte('\x01')
	}
	return sb.String()
}

// stage maps one fragment to the fragments that pass and those it blocks.
type stage func(Fragment) (pass, block []Fragment)

// run pushes fragments through stages in order. Fragments with identical hop
// sequences are merged after every stage, which bounds the fragment count by
// the number of distinct decision paths rather than by box fragmentation.
func run(frags []Fragment, stages ...stage) (pass, block []Fragment) {
	for _, st := range stages {
		var next []Fragment
		for _, f := range frags {
			p, b := st(f)
			next = append(next, p...)
			block = append(block, b...)
		}
		frags = merge(next)
		if len(frags) == 0 {
			break
		}
	}
	return frags, merge(block)
}

// merge unions fragments with identical paths and drops empty ones,
// preserving first-seen order.
func merge(frags []Fragment) []Fragment {
	index := map[string]int{}
	var out []Fragment
	for _, f := range frags {
		if f.Space.IsEmpty() {
			continue
		}
		k := f.key()
		if i, ok := index[k]; ok {
			out[i].Space = out[i].Space.Union(f.Space)
			continue
		}
		index[k] = len(out)
		out = append(out, f)
	}
	return out
}

// gate passes the whole fragment if ok, otherwise blocks it.
func gate(ok bool, h Hop) stage {
	h.Allowed = ok
	return func(f Fragment) ([]Fragment, []Fragment) {
		if ok {
			return []Fragment{f.with(f.Space, h)}, nil
		}
		return nil, []Fragment{f.with(f.Space, h)}
	}
}

// constrain passes the part of the fragment inside region with allowHop and
// blocks the rest with denyHop.
func constrain(region hspace.Space, allowHop, denyHop Hop) stage {
	allowHop.Allowed, denyHop.Allowed = true, false
	return func(f Fragment) (pass, block []Fragment) {
		in := f.Space.Intersect(region)
		out := f.Space.Subtract(region)
		if !in.IsEmpty() {
			pass = append(pass, f.with(in, allowHop))
		}
		if !out.IsEmpty() {
			block = append(block, f.with(out, denyHop))
		}
		return pass, block
	}
}

// branch runs a different pipeline for different parts of the fragment. The
// split function partitions the fragment's space and returns, for each part,
// the hop recorded for the split and the stages to apply afterwards.
func branch(split func(hspace.Space) []branchPart) stage {
	return func(f Fragment) (pass, block []Fragment) {
		for _, part := range split(f.Space) {
			start := f.with(part.space, part.hop)
			if !part.hop.Allowed {
				block = append(block, start)
				continue
			}
			p, b := run([]Fragment{start}, part.then...)
			pass = append(pass, p...)
			block = append(block, b...)
		}
		return pass, block
	}
}

type branchPart struct {
	space hspace.Space
	hop   Hop
	then  []stage
}
