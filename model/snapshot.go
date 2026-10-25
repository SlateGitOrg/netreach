// Package model defines the VPC snapshot format netreach reads, and compiles a
// snapshot into a validated, cross-linked Network that the analysis engine and
// the reference simulator both consume.
//
// The snapshot is a simplified, provider-neutral rendering of AWS VPC
// networking objects: VPCs, subnets, route tables, internet gateways, NAT
// gateways, VPC peering connections, security groups, network ACLs and
// elastic network interfaces (ENIs). Field names follow the AWS API where
// practical so an exporter is a thin mapping.
package model

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Snapshot is the JSON document describing one network.
type Snapshot struct {
	Name             string            `json:"name"`
	Description      string            `json:"description,omitempty"`
	VPCs             []VPC             `json:"vpcs"`
	Subnets          []Subnet          `json:"subnets"`
	RouteTables      []RouteTable      `json:"routeTables"`
	InternetGateways []InternetGateway `json:"internetGateways,omitempty"`
	NATGateways      []NATGateway      `json:"natGateways,omitempty"`
	Peerings         []Peering         `json:"peerings,omitempty"`
	SecurityGroups   []SecurityGroup   `json:"securityGroups"`
	NetworkACLs      []NetworkACL      `json:"networkAcls"`
	ENIs             []ENI             `json:"enis"`
}

// VPC is a virtual network with one or more IPv4 CIDR blocks.
type VPC struct {
	ID    string   `json:"id"`
	CIDRs []string `json:"cidrs"`
}

// Subnet is a CIDR slice of a VPC bound to one route table and one network ACL.
type Subnet struct {
	ID         string `json:"id"`
	VPC        string `json:"vpc"`
	CIDR       string `json:"cidr"`
	RouteTable string `json:"routeTable"`
	NetworkACL string `json:"networkAcl"`
}

// RouteTable holds explicit routes; the VPC-local routes are implicit.
type RouteTable struct {
	ID     string  `json:"id"`
	VPC    string  `json:"vpc"`
	Routes []Route `json:"routes"`
}

// Route sends Destination to Target: an internet gateway ID, a NAT gateway ID,
// a peering connection ID, "blackhole", or "local" (only for a VPC CIDR).
type Route struct {
	Destination string `json:"destination"`
	Target      string `json:"target"`
}

// InternetGateway is attached to VPC (empty means detached).
type InternetGateway struct {
	ID  string `json:"id"`
	VPC string `json:"vpc,omitempty"`
}

// NATGateway is a public NAT gateway living in Subnet.
type NATGateway struct {
	ID        string `json:"id"`
	Subnet    string `json:"subnet"`
	PrivateIP string `json:"privateIp"`
	PublicIP  string `json:"publicIp"`
}

// Peering is a VPC peering connection; Status defaults to "active".
type Peering struct {
	ID           string `json:"id"`
	RequesterVPC string `json:"requesterVpc"`
	AccepterVPC  string `json:"accepterVpc"`
	Status       string `json:"status,omitempty"`
}

// SecurityGroup is a stateful allow-list attached to ENIs.
type SecurityGroup struct {
	ID          string   `json:"id"`
	VPC         string   `json:"vpc"`
	Description string   `json:"description,omitempty"`
	Inbound     []SGRule `json:"inbound"`
	Outbound    []SGRule `json:"outbound"`
}

// SGRule allows Protocol/Ports from (inbound) or to (outbound) either CIDR or
// the members of security group Group. Exactly one of CIDR and Group is set.
type SGRule struct {
	Protocol    string `json:"protocol"`
	Ports       string `json:"ports,omitempty"`
	CIDR        string `json:"cidr,omitempty"`
	Group       string `json:"group,omitempty"`
	Description string `json:"description,omitempty"`
}

// NetworkACL is a stateless, ordered rule list applied at the subnet boundary.
type NetworkACL struct {
	ID       string     `json:"id"`
	VPC      string     `json:"vpc"`
	Inbound  []ACLEntry `json:"inbound"`
	Outbound []ACLEntry `json:"outbound"`
}

// ACLEntry is one numbered NACL rule. Lower numbers are evaluated first and
// the first match decides; an implicit final rule denies everything.
type ACLEntry struct {
	RuleNumber int    `json:"ruleNumber"`
	Protocol   string `json:"protocol"`
	Ports      string `json:"ports,omitempty"`
	Action     string `json:"action"`
	CIDR       string `json:"cidr"`
}

// ENI is a network interface with one private IPv4 address and an optional
// public (or elastic) IPv4 address.
type ENI struct {
	ID             string   `json:"id"`
	Name           string   `json:"name,omitempty"`
	Instance       string   `json:"instance,omitempty"`
	Subnet         string   `json:"subnet"`
	PrivateIP      string   `json:"privateIp"`
	PublicIP       string   `json:"publicIp,omitempty"`
	SecurityGroups []string `json:"securityGroups"`
}

// Decode reads a snapshot from r, rejecting unknown fields so that a typo in
// a hand-written fixture is an error rather than a silently ignored rule.
func Decode(r io.Reader) (*Snapshot, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var s Snapshot
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return &s, nil
}

// LoadFile reads and decodes a snapshot file.
func LoadFile(path string) (*Snapshot, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	s, err := Decode(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// Load reads, decodes and compiles a snapshot file.
func Load(path string) (*Network, error) {
	s, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	n, err := Compile(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return n, nil
}
