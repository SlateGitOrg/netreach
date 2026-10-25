package model

import (
	"slices"

	"github.com/SlateGitOrg/netreach/interval"
)

// Network is a compiled, validated snapshot. All references are resolved to
// pointers and every address is parsed, so the engine and simulator never
// handle strings or lookup failures.
type Network struct {
	Name        string
	Description string
	VPCs        []*VPCNode
	Subnets     []*SubnetNode
	RouteTables []*RouteTableNode
	IGWs        []*IGWNode
	NATs        []*NATNode
	Peerings    []*PeeringNode
	SGs         []*SGNode
	ACLs        []*ACLNode
	ENIs        []*ENINode // sorted by ID

	byID map[string]any
}

// VPCNode is a compiled VPC.
type VPCNode struct {
	ID      string
	CIDRs   []interval.CIDR
	Space   interval.Set // union of CIDRs
	IGW     *IGWNode     // attached internet gateway, if any
	Subnets []*SubnetNode
}

// SubnetNode is a compiled subnet.
type SubnetNode struct {
	ID         string
	VPC        *VPCNode
	CIDR       interval.CIDR
	RouteTable *RouteTableNode
	ACL        *ACLNode
}

// RouteKind classifies a route target.
type RouteKind int

// Route target kinds.
const (
	RouteLocal RouteKind = iota
	RouteIGW
	RouteNAT
	RoutePeering
	RouteBlackhole
)

func (k RouteKind) String() string {
	return [...]string{"local", "internet-gateway", "nat-gateway", "peering", "blackhole"}[k]
}

// RouteNode is one resolved route.
type RouteNode struct {
	Dest    interval.CIDR
	Kind    RouteKind
	Target  string // target ID; "local" or "blackhole" for those kinds
	IGW     *IGWNode
	NAT     *NATNode
	Peering *PeeringNode
}

// RouteTableNode holds the effective routes: one local route per VPC CIDR plus
// the explicit routes, ordered by descending prefix length (then address), the
// order in which longest-prefix matching examines them.
type RouteTableNode struct {
	ID     string
	VPC    *VPCNode
	Routes []RouteNode
}

// Lookup returns the longest-prefix-match route for ip, or nil if none.
func (rt *RouteTableNode) Lookup(ip uint32) *RouteNode {
	for i := range rt.Routes {
		if rt.Routes[i].Dest.Contains(ip) {
			return &rt.Routes[i]
		}
	}
	return nil
}

// IGWNode is a compiled internet gateway.
type IGWNode struct {
	ID  string
	VPC *VPCNode // nil if detached
}

// NATNode is a compiled NAT gateway.
type NATNode struct {
	ID        string
	Subnet    *SubnetNode
	PrivateIP uint32
	PublicIP  uint32
}

// PeeringNode is a compiled peering connection.
type PeeringNode struct {
	ID     string
	A, B   *VPCNode
	Active bool
}

// Connects reports whether p is active and joins x and y (in either order).
func (p *PeeringNode) Connects(x, y *VPCNode) bool {
	return p.Active && ((p.A == x && p.B == y) || (p.A == y && p.B == x))
}

// SGRuleNode is a compiled security group rule. Exactly one of CIDR (when
// HasCIDR) and Group is meaningful.
type SGRuleNode struct {
	Index       int // position in the group's rule list
	Match       Match
	HasCIDR     bool
	CIDR        interval.CIDR
	Group       *SGNode
	Description string
}

// Peer renders the rule's remote side.
func (r SGRuleNode) Peer() string {
	if r.HasCIDR {
		return r.CIDR.String()
	}
	return r.Group.ID
}

// SGNode is a compiled security group.
type SGNode struct {
	ID       string
	VPC      *VPCNode
	Inbound  []SGRuleNode
	Outbound []SGRuleNode
	Members  []*ENINode
}

// HasMember reports whether e is attached to sg.
func (sg *SGNode) HasMember(e *ENINode) bool { return slices.Contains(sg.Members, e) }

// ACLEntryNode is a compiled NACL entry.
type ACLEntryNode struct {
	Number int
	Allow  bool
	Match  Match
	CIDR   interval.CIDR
}

// Action renders the entry's action.
func (e ACLEntryNode) Action() string {
	if e.Allow {
		return "allow"
	}
	return "deny"
}

// ACLNode is a compiled network ACL with entries sorted by rule number.
type ACLNode struct {
	ID       string
	VPC      *VPCNode
	Inbound  []ACLEntryNode
	Outbound []ACLEntryNode
}

// ENINode is a compiled network interface.
type ENINode struct {
	ID          string
	Name        string
	Instance    string
	Subnet      *SubnetNode
	PrivateIP   uint32
	PublicIP    uint32
	HasPublicIP bool
	SGs         []*SGNode
}

// VPC returns the VPC of e.
func (e *ENINode) VPC() *VPCNode { return e.Subnet.VPC }

// Label is a human-friendly identifier: "name (eni-…)" or the bare ID.
func (e *ENINode) Label() string {
	if e.Name != "" {
		return e.Name + " (" + e.ID + ")"
	}
	return e.ID
}

// ENI returns the interface with the given ID, or nil.
func (n *Network) ENI(id string) *ENINode {
	e, _ := n.byID[id].(*ENINode)
	return e
}

// ENIsOfInstance returns the interfaces attached to an instance ID.
func (n *Network) ENIsOfInstance(instance string) []*ENINode {
	var out []*ENINode
	for _, e := range n.ENIs {
		if e.Instance == instance {
			out = append(out, e)
		}
	}
	return out
}

// ACL returns the network ACL with the given ID, or nil.
func (n *Network) ACL(id string) *ACLNode {
	a, _ := n.byID[id].(*ACLNode)
	return a
}

// Subnet returns the subnet with the given ID, or nil.
func (n *Network) Subnet(id string) *SubnetNode {
	s, _ := n.byID[id].(*SubnetNode)
	return s
}

// VPCOf returns the VPC whose CIDRs contain ip, or nil.
func (n *Network) VPCOf(ip uint32) *VPCNode {
	for _, v := range n.VPCs {
		if v.Space.Contains(ip) {
			return v
		}
	}
	return nil
}

// AllVPCSpace returns the union of all VPC CIDRs.
func (n *Network) AllVPCSpace() interval.Set {
	var s interval.Set
	for _, v := range n.VPCs {
		s = s.Union(v.Space)
	}
	return s
}
