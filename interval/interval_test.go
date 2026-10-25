package interval

import (
	"math/rand/v2"
	"testing"
)

// The oracle: a brute-force bitset over a small domain [0, oracleMax].
// Every interval operation is checked element-by-element against it.
const (
	oracleWidth = 6
	oracleMax   = 1<<oracleWidth - 1
)

type bitset [oracleMax + 1]bool

func toBits(s Set) bitset {
	var b bitset
	for v := uint32(0); v <= oracleMax; v++ {
		b[v] = s.Contains(v)
	}
	return b
}

func fromBits(b bitset) Set {
	var rs []Range
	for v, in := range b {
		if in {
			rs = append(rs, Range{uint32(v), uint32(v)})
		}
	}
	s, err := FromRanges(rs...)
	if err != nil {
		panic(err)
	}
	return s
}

func randomSet(rng *rand.Rand) Set {
	var rs []Range
	for range rng.IntN(5) {
		lo := uint32(rng.IntN(oracleMax + 1))
		hi := lo + uint32(rng.IntN(oracleMax+1-int(lo)))
		rs = append(rs, Range{lo, hi})
	}
	s, err := FromRanges(rs...)
	if err != nil {
		panic(err)
	}
	return s
}

// checkCanonical asserts the representation invariant.
func checkCanonical(t *testing.T, s Set) {
	t.Helper()
	for i, r := range s.r {
		if r.Lo > r.Hi {
			t.Fatalf("range %d inverted: %v", i, s.r)
		}
		if i > 0 && s.r[i-1].Hi+1 >= r.Lo {
			t.Fatalf("ranges %d,%d overlap or touch: %v", i-1, i, s.r)
		}
	}
}

func TestPropertyAgainstBitsetOracle(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	for iter := range 5000 {
		a, b := randomSet(rng), randomSet(rng)
		ba, bb := toBits(a), toBits(b)
		var wantU, wantI, wantS, wantC bitset
		for v := range wantU {
			wantU[v] = ba[v] || bb[v]
			wantI[v] = ba[v] && bb[v]
			wantS[v] = ba[v] && !bb[v]
			wantC[v] = !ba[v]
		}
		cases := []struct {
			name string
			got  Set
			want bitset
		}{
			{"union", a.Union(b), wantU},
			{"intersect", a.Intersect(b), wantI},
			{"subtract", a.Subtract(b), wantS},
			{"complement", a.Complement(oracleMax), wantC},
		}
		for _, c := range cases {
			checkCanonical(t, c.got)
			if toBits(c.got) != c.want {
				t.Fatalf("iter %d: %s(%v, %v) = %v", iter, c.name, a, b, c.got)
			}
			// Canonical form: equal sets have identical representation.
			if !c.got.Equal(fromBits(c.want)) {
				t.Fatalf("iter %d: %s not canonical: %v", iter, c.name, c.got)
			}
		}
		var size uint64
		for _, in := range ba {
			if in {
				size++
			}
		}
		if a.Size() != size {
			t.Fatalf("size(%v) = %d, want %d", a, a.Size(), size)
		}
		if a.SubsetOf(b) != (wantS == bitset{}) {
			t.Fatalf("subset(%v,%v) wrong", a, b)
		}
		checkBlocks(t, a)
	}
}

// checkBlocks verifies AlignedBlocks against the brute-force definition: the
// result must be exactly the set of maximal aligned blocks contained in s.
func checkBlocks(t *testing.T, s Set) {
	t.Helper()
	contained := func(start uint32, size int) bool {
		for v := start; v < start+1<<size; v++ {
			if !s.Contains(v) {
				return false
			}
		}
		return true
	}
	want := map[Block]bool{}
	for size := 0; size <= oracleWidth; size++ {
		for start := uint32(0); start <= oracleMax; start += 1 << size {
			if !contained(start, size) {
				continue
			}
			parentSize := size + 1
			parentStart := start &^ (1<<parentSize - 1)
			if parentSize <= oracleWidth && contained(parentStart, parentSize) {
				continue // not maximal
			}
			want[Block{start, size}] = true
		}
	}
	got := s.AlignedBlocks(oracleWidth)
	if len(got) != len(want) {
		t.Fatalf("AlignedBlocks(%v) = %v, want %d maximal blocks", s, got, len(want))
	}
	for _, b := range got {
		if !want[b] {
			t.Fatalf("AlignedBlocks(%v) produced non-maximal block %v", s, b)
		}
	}
}

func TestStringParseRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	for range 1000 {
		s := randomSet(rng)
		back, err := Parse(s.String())
		if err != nil {
			t.Fatal(err)
		}
		if !back.Equal(s) {
			t.Fatalf("round trip %v -> %v", s, back)
		}
	}
	for _, bad := range []string{"x", "1-y", "5-3", "99999999999"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

func TestBoundaryValues(t *testing.T) {
	top := Span(MaxIPv4-1, MaxIPv4)
	all := Full(MaxIPv4)
	if got := all.Subtract(top); !got.Equal(Span(0, MaxIPv4-2)) {
		t.Fatalf("subtract at top: %v", got)
	}
	if got := top.Union(Span(0, MaxIPv4-2)); !got.Equal(all) {
		t.Fatalf("union to full: %v", got)
	}
	if all.Size() != 1<<32 {
		t.Fatalf("full size %d", all.Size())
	}
	if !Empty().Complement(MaxIPv4).Equal(all) {
		t.Fatal("complement of empty")
	}
	if _, err := FromRanges(Range{5, 1}); err == nil {
		t.Fatal("inverted range accepted")
	}
	if v, ok := Span(7, 9).Min(); !ok || v != 7 {
		t.Fatal("min")
	}
	if _, ok := Empty().Min(); ok {
		t.Fatal("min of empty")
	}
	if Empty().String() != "∅" {
		t.Fatal("empty string")
	}
}

func TestCIDRParsingAndDecomposition(t *testing.T) {
	tests := []struct {
		in   string
		want string
		err  bool
	}{
		{"10.0.0.0/8", "10.0.0.0/8", false},
		{"0.0.0.0/0", "0.0.0.0/0", false},
		{"192.168.1.7", "192.168.1.7/32", false},
		{"10.0.0.1/24", "", true},
		{"10.0.0.0/33", "", true},
		{"256.0.0.0/8", "", true},
		{"01.2.3.4", "", true},
		{"1.2.3", "", true},
	}
	for _, tt := range tests {
		c, err := ParseCIDR(tt.in)
		if (err != nil) != tt.err {
			t.Fatalf("ParseCIDR(%q) err=%v", tt.in, err)
		}
		if err == nil && c.String() != tt.want {
			t.Fatalf("ParseCIDR(%q) = %s", tt.in, c)
		}
	}
	// 0.0.0.0/0 minus 10.0.0.0/8 needs exactly 8 prefixes.
	rest := Full(MaxIPv4).Subtract(MustParseCIDR("10.0.0.0/8").Set())
	want := []string{"0.0.0.0/5", "8.0.0.0/7", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4",
		"32.0.0.0/3", "64.0.0.0/2", "128.0.0.0/1"}
	got := rest.CIDRStrings()
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if !MustParseCIDR("10.1.0.0/16").Contains(0x0a0100ff) {
		t.Fatal("contains")
	}
	if FormatIPv4(0xC0A80101) != "192.168.1.1" {
		t.Fatal("format")
	}
}

func TestSpanPanicsOnInvertedInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	Span(2, 1)
}

// FuzzSetAlgebra checks algebraic identities on arbitrary inputs from the
// native Go fuzzer over the full 32-bit domain (where no oracle is feasible).
func FuzzSetAlgebra(f *testing.F) {
	f.Add(uint32(0), uint32(10), uint32(5), uint32(20), uint32(3), uint32(4))
	f.Add(uint32(0), MaxIPv4, uint32(0), uint32(0), MaxIPv4, MaxIPv4)
	f.Fuzz(func(t *testing.T, a1, a2, b1, b2, c1, c2 uint32) {
		mk := func(x, y uint32) Set { return Span(min(x, y), max(x, y)) }
		a := mk(a1, a2).Union(mk(c1, c2))
		b := mk(b1, b2)
		// (a \ b) ∪ (a ∩ b) == a, and the two parts are disjoint.
		diff, inter := a.Subtract(b), a.Intersect(b)
		if !diff.Union(inter).Equal(a) || !diff.Intersect(inter).IsEmpty() {
			t.Fatalf("partition identity failed for %v, %v", a, b)
		}
		// De Morgan.
		lhs := a.Union(b).Complement(MaxIPv4)
		rhs := a.Complement(MaxIPv4).Intersect(b.Complement(MaxIPv4))
		if !lhs.Equal(rhs) {
			t.Fatalf("de morgan failed for %v, %v", a, b)
		}
		// CIDR decomposition covers exactly the set.
		var cover Set
		for _, c := range a.CIDRs() {
			cover = cover.Union(c.Set())
		}
		if !cover.Equal(a) {
			t.Fatalf("CIDR cover of %v = %v", a, cover)
		}
	})
}
