package report

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SlateGitOrg/netreach/interval"
	"github.com/SlateGitOrg/netreach/model"
)

// Severity of an exposure finding.
type Severity string

// Severities, most severe first.
const (
	High   Severity = "high"
	Medium Severity = "medium"
	Low    Severity = "low"
	Info   Severity = "info"
)

var severityRank = map[Severity]int{High: 0, Medium: 1, Low: 2, Info: 3}

// Worse reports whether a is more severe than b.
func Worse(a, b Severity) bool { return severityRank[a] < severityRank[b] }

// BroadThreshold is the number of addresses (a /8) from which an exposure is
// considered "open to the internet" rather than restricted.
const BroadThreshold = 1 << 24

type sensitivePort struct {
	proto uint32
	port  uint32
	name  string
}

// sensitivePorts are administrative, database and file-sharing services that
// should not face the internet. The list is deliberately short and explicit.
var sensitivePorts = []sensitivePort{
	{model.ProtoTCP, 21, "FTP"}, {model.ProtoTCP, 22, "SSH"}, {model.ProtoTCP, 23, "Telnet"},
	{model.ProtoTCP, 135, "MS-RPC"}, {model.ProtoTCP, 139, "NetBIOS"}, {model.ProtoTCP, 445, "SMB"},
	{model.ProtoUDP, 161, "SNMP"}, {model.ProtoTCP, 1433, "SQL Server"}, {model.ProtoTCP, 1521, "Oracle"},
	{model.ProtoTCP, 2049, "NFS"}, {model.ProtoTCP, 2375, "Docker API"}, {model.ProtoTCP, 2376, "Docker API (TLS)"},
	{model.ProtoTCP, 3306, "MySQL"}, {model.ProtoTCP, 3389, "RDP"}, {model.ProtoTCP, 5432, "PostgreSQL"},
	{model.ProtoTCP, 5900, "VNC"}, {model.ProtoTCP, 5984, "CouchDB"}, {model.ProtoTCP, 6379, "Redis"},
	{model.ProtoTCP, 9042, "Cassandra"}, {model.ProtoTCP, 9200, "Elasticsearch"}, {model.ProtoTCP, 11211, "Memcached"},
	{model.ProtoUDP, 11211, "Memcached"}, {model.ProtoTCP, 27017, "MongoDB"},
}

var webPorts = func() interval.Set {
	s, _ := interval.FromRanges(interval.Range{Lo: 80, Hi: 80}, interval.Range{Lo: 443, Hi: 443})
	return s
}()

// Assess grades an internet-ingress exposure of protocol proto (with service
// ports ports, ignored for protocols without ports) from remote addresses.
//
//	high    broad source and a sensitive service port, or every port open
//	medium  broad source, any other non-web port or non-ICMP protocol
//	info    broad source, only 80/443 or ICMP (expected for public services)
//	low     anything reachable only from a restricted source range
func Assess(proto uint32, ports, remote interval.Set) (Severity, string) {
	broad := remote.Size() >= BroadThreshold
	scope := "from a restricted source range"
	if broad {
		scope = "open to the internet"
	}
	if !broad {
		return Low, scope
	}
	if model.HasPorts(proto) {
		if ports.Equal(interval.Full(model.MaxPort)) {
			return High, "every port " + scope
		}
		var hits []string
		for _, sp := range sensitivePorts {
			if sp.proto == proto && ports.Contains(sp.port) {
				hits = append(hits, fmt.Sprintf("%s (%d)", sp.name, sp.port))
			}
		}
		if len(hits) > 0 {
			return High, strings.Join(slices.Compact(hits), ", ") + " " + scope
		}
		if ports.SubsetOf(webPorts) && proto == model.ProtoTCP {
			return Info, "web ports " + scope
		}
		return Medium, "non-web ports " + scope
	}
	if proto == model.ProtoICMP {
		return Info, "ICMP " + scope
	}
	return Medium, "protocol " + model.ProtocolName(interval.Single(proto)) + " " + scope
}
