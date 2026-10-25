package engine

import (
	"fmt"
	"strings"

	"github.com/SlateGitOrg/netreach/hspace"
	"github.com/SlateGitOrg/netreach/interval"
	"github.com/SlateGitOrg/netreach/model"
)

// Direction of a rule list relative to the component that owns it.
type Direction int

// Directions.
const (
	Inbound Direction = iota
	Outbound
)

func (d Direction) String() string {
	if d == Inbound {
		return "inbound"
	}
	return "outbound"
}

func (d Direction) peerWord() string {
	if d == Inbound {
		return "from"
	}
	return "to"
}

// aclCheck describes one NACL evaluation: which rule list, which address its
// CIDRs are compared with, and which flow dimension carries the packet's
// destination port in this direction.
type aclCheck struct {
	step    Step
	acl     *model.ACLNode
	dir     Direction
	addr    Addr
	portDim int
	where   string // human context, e.g. "subnet-a (target subnet)"
}

func (c aclCheck) entries() []model.ACLEntryNode {
	if c.dir == Inbound {
		return c.acl.Inbound
	}
	return c.acl.Outbound
}

func (c aclCheck) entryRegion(e model.ACLEntryNode) hspace.Space {
	return matchRegion(e.Match, c.addr.remoteSet(e.CIDR), c.portDim)
}

func (c aclCheck) describe(e model.ACLEntryNode) string {
	return fmt.Sprintf("%s rule %d %s %s %s %s [%s]", c.dir, e.Number, e.Action(), e.Match,
		c.dir.peerWord(), e.CIDR, c.where)
}

// aclStage evaluates a stateless NACL: entries in rule-number order, first
// match decides, implicit deny at the end. Each entry claims the part of the
// still-undecided space it matches, so the cost is O(R) region operations.
func aclStage(c aclCheck) stage {
	return func(f Fragment) (pass, block []Fragment) {
		remaining := f.Space
		for _, e := range c.entries() {
			if remaining.IsEmpty() {
				break
			}
			region := c.entryRegion(e)
			hit := remaining.Intersect(region)
			if hit.IsEmpty() {
				continue
			}
			remaining = remaining.Subtract(region)
			h := Hop{Step: c.step, Component: c.acl.ID, Allowed: e.Allow, Detail: c.describe(e)}
			if e.Allow {
				pass = append(pass, f.with(hit, h))
			} else {
				block = append(block, f.with(hit, h))
			}
		}
		if !remaining.IsEmpty() {
			block = append(block, f.with(remaining, Hop{Step: c.step, Component: c.acl.ID,
				Detail: fmt.Sprintf("%s rule * deny all traffic (implicit default) [%s]", c.dir, c.where)}))
		}
		return pass, block
	}
}

// aclAllowed returns the part of the universe a NACL admits.
func aclAllowed(c aclCheck) hspace.Space {
	pass, _ := aclStage(c)(Fragment{Space: Universe()})
	out := emptyFlowSpace
	for _, p := range pass {
		out = out.Union(p.Space)
	}
	return out
}

// sgCheck describes a security group evaluation. Security groups are an
// unordered union of allow rules; for explanation purposes a flow is
// attributed to the first rule (in group order, then rule order) admitting it.
type sgCheck struct {
	step Step
	sgs  []*model.SGNode
	dir  Direction
	addr Addr
	// peer is the ENI on the other side of the flow when it is inside the
	// snapshot; group-reference rules match only if peer is a member and
	// groupOK(peer's VPC) holds. For internet flows peer is nil.
	peer    *model.ENINode
	groupOK func(*model.SGNode) bool
}

func (c sgCheck) ruleRegion(r model.SGRuleNode) hspace.Space {
	if r.HasCIDR {
		return matchRegion(r.Match, c.addr.remoteSet(r.CIDR), DimServicePort)
	}
	if c.peer != nil && r.Group.HasMember(c.peer) && c.groupOK(r.Group) {
		return matchRegion(r.Match, allIPs, DimServicePort)
	}
	return emptyFlowSpace
}

func sgStage(c sgCheck) stage {
	return func(f Fragment) (pass, block []Fragment) {
		remaining := f.Space
		ids := make([]string, len(c.sgs))
		for i, sg := range c.sgs {
			ids[i] = sg.ID
			rules := sg.Inbound
			if c.dir == Outbound {
				rules = sg.Outbound
			}
			for _, r := range rules {
				if remaining.IsEmpty() {
					break
				}
				region := c.ruleRegion(r)
				hit := remaining.Intersect(region)
				if hit.IsEmpty() {
					continue
				}
				remaining = remaining.Subtract(region)
				detail := fmt.Sprintf("%s rule #%d allows %s %s %s", c.dir, r.Index, r.Match, c.dir.peerWord(), r.Peer())
				if r.Description != "" {
					detail += " (" + r.Description + ")"
				}
				pass = append(pass, f.with(hit, Hop{Step: c.step, Component: sg.ID, Allowed: true, Detail: detail}))
			}
		}
		if !remaining.IsEmpty() {
			block = append(block, f.with(remaining, Hop{Step: c.step, Component: strings.Join(ids, ","),
				Detail: fmt.Sprintf("no %s rule in %s allows this traffic", c.dir, strings.Join(ids, ", "))}))
		}
		return pass, block
	}
}

// routePart is one longest-prefix-match class: the flows routed by route
// (nil for "no matching route").
type routePart struct {
	space hspace.Space
	route *model.RouteNode
}

// routeSplit partitions space by the route table's longest-prefix match on
// addr. Routes are pre-sorted most-specific first and CIDRs either nest or
// are disjoint, so taking each route's CIDR out of the remainder in that
// order is exactly LPM: O(R) interval operations, no per-address work.
func routeSplit(rt *model.RouteTableNode, addr Addr, space hspace.Space) []routePart {
	var parts []routePart
	remaining := space
	for i := range rt.Routes {
		if remaining.IsEmpty() {
			return parts
		}
		r := &rt.Routes[i]
		var hit hspace.Space
		if addr.fixed {
			if !r.Dest.Contains(addr.ip) {
				continue
			}
			hit = remaining
		} else {
			hit = remaining.Restrict(DimRemote, r.Dest.Set())
		}
		if hit.IsEmpty() {
			continue
		}
		parts = append(parts, routePart{space: hit, route: r})
		if addr.fixed {
			return parts
		}
		remaining = remaining.Restrict(DimRemote, r.Dest.Set().Complement(interval.MaxIPv4))
	}
	if !remaining.IsEmpty() {
		parts = append(parts, routePart{space: remaining})
	}
	return parts
}

func routeText(rt *model.RouteTableNode, r *model.RouteNode, lookedUp string) string {
	if r == nil {
		return fmt.Sprintf("no route in %s matches %s", rt.ID, lookedUp)
	}
	return fmt.Sprintf("%s -> %s (%s)", r.Dest, r.Target, r.Kind)
}

// routeStage partitions by LPM and accepts the parts for which ok returns
// true. ok also returns a note appended to the hop detail.
func routeStage(step Step, rt *model.RouteTableNode, addr Addr, lookedUp string,
	ok func(*model.RouteNode) (bool, string)) stage {
	return branch(func(space hspace.Space) []branchPart {
		var out []branchPart
		for _, p := range routeSplit(rt, addr, space) {
			good, note := false, "packet dropped"
			if p.route != nil {
				good, note = ok(p.route)
			}
			detail := routeText(rt, p.route, lookedUp)
			if note != "" {
				detail += "; " + note
			}
			out = append(out, branchPart{space: p.space,
				hop: Hop{Step: step, Component: rt.ID, Allowed: good, Detail: detail}})
		}
		return out
	})
}
