package interval

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

// MaxIPv4 is the largest IPv4 address as an integer (255.255.255.255).
const MaxIPv4 = ^uint32(0)

// CIDR is an IPv4 prefix. Addr always has its host bits cleared.
type CIDR struct {
	Addr uint32
	Bits int // prefix length, 0..32
}

// Range returns the closed address interval covered by c.
func (c CIDR) Range() Range {
	return Range{Lo: c.Addr, Hi: c.Addr | hostMask(c.Bits)}
}

// Set returns c as an interval set.
func (c CIDR) Set() Set { r := c.Range(); return Span(r.Lo, r.Hi) }

// Contains reports whether ip is inside c.
func (c CIDR) Contains(ip uint32) bool { r := c.Range(); return r.Lo <= ip && ip <= r.Hi }

// String renders c as "a.b.c.d/n".
func (c CIDR) String() string { return FormatIPv4(c.Addr) + "/" + strconv.Itoa(c.Bits) }

func hostMask(prefixBits int) uint32 {
	if prefixBits <= 0 {
		return MaxIPv4
	}
	if prefixBits >= 32 {
		return 0
	}
	return MaxIPv4 >> uint(prefixBits)
}

// ParseIPv4 parses a dotted-quad IPv4 address.
func ParseIPv4(text string) (uint32, error) {
	parts := strings.Split(strings.TrimSpace(text), ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid IPv4 address %q", text)
	}
	var ip uint32
	for _, p := range parts {
		if p == "" || len(p) > 3 || (len(p) > 1 && p[0] == '0') {
			return 0, fmt.Errorf("invalid IPv4 address %q", text)
		}
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return 0, fmt.Errorf("invalid IPv4 address %q", text)
		}
		ip = ip<<8 | uint32(n)
	}
	return ip, nil
}

// FormatIPv4 renders an integer IPv4 address in dotted-quad form.
func FormatIPv4(ip uint32) string {
	return strconv.Itoa(int(ip>>24)) + "." + strconv.Itoa(int(ip>>16&0xff)) + "." +
		strconv.Itoa(int(ip>>8&0xff)) + "." + strconv.Itoa(int(ip&0xff))
}

// ParseCIDR parses "a.b.c.d/n". A bare address is accepted as a /32. Host bits
// must be zero: "10.0.0.1/24" is rejected, matching the AWS API, because a
// silently-masked prefix in a security rule usually hides a typo.
func ParseCIDR(text string) (CIDR, error) {
	addrText, bitsText, hasBits := strings.Cut(strings.TrimSpace(text), "/")
	ip, err := ParseIPv4(addrText)
	if err != nil {
		return CIDR{}, fmt.Errorf("invalid CIDR %q: %w", text, err)
	}
	prefix := 32
	if hasBits {
		n, err := strconv.Atoi(bitsText)
		if err != nil || n < 0 || n > 32 {
			return CIDR{}, fmt.Errorf("invalid CIDR %q: bad prefix length", text)
		}
		prefix = n
	}
	if ip&hostMask(prefix) != 0 {
		return CIDR{}, fmt.Errorf("invalid CIDR %q: host bits set", text)
	}
	return CIDR{Addr: ip, Bits: prefix}, nil
}

// MustParseCIDR is ParseCIDR for constants in tests and examples; it panics on error.
func MustParseCIDR(text string) CIDR {
	c, err := ParseCIDR(text)
	if err != nil {
		panic(err)
	}
	return c
}

// Block is an aligned power-of-two block [Start, Start+2^Size-1] inside a
// domain of 2^Width values. In the IPv4 domain (Width 32) a Block is exactly a
// CIDR with prefix length Width-Size.
type Block struct {
	Start uint32
	Size  int // log2 of the block length
}

// AlignedBlocks decomposes s into the unique minimum set of disjoint aligned
// power-of-two blocks, for a domain of 2^width values (1 <= width <= 32).
// Elements of s outside the domain are ignored.
//
// Aligned blocks either nest or are disjoint, so the maximal aligned blocks
// contained in s partition it and no partition into aligned blocks can be
// smaller. The greedy below emits exactly those maximal blocks: from the
// current position it takes the largest block that is both aligned there and
// does not overrun the range. Cost: O(width) blocks per range.
func (s Set) AlignedBlocks(width int) []Block {
	limit := uint64(1) << uint(width)
	var out []Block
	for _, r := range s.r {
		lo, hi := uint64(r.Lo), uint64(r.Hi)
		if lo >= limit {
			break
		}
		if hi >= limit {
			hi = limit - 1
		}
		for lo <= hi {
			size := width
			if lo != 0 {
				size = min(width, bits.TrailingZeros64(lo))
			}
			for size > 0 && lo+(uint64(1)<<uint(size))-1 > hi {
				size--
			}
			out = append(out, Block{Start: uint32(lo), Size: size})
			lo += uint64(1) << uint(size)
		}
	}
	return out
}

// CIDRs returns the minimum list of IPv4 prefixes whose union is s.
func (s Set) CIDRs() []CIDR {
	blocks := s.AlignedBlocks(32)
	out := make([]CIDR, len(blocks))
	for i, b := range blocks {
		out[i] = CIDR{Addr: b.Start, Bits: 32 - b.Size}
	}
	return out
}

// CIDRStrings renders CIDRs() as strings.
func (s Set) CIDRStrings() []string {
	cs := s.CIDRs()
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.String()
	}
	return out
}
