package hspace

import (
	"math/rand/v2"
	"testing"

	"github.com/SlateGitOrg/netreach/interval"
)

// Brute-force oracle: a 4-D domain small enough (8·4·4·8 = 1024 points) to
// enumerate, so every operation can be compared point by point.
var maxes = []uint32{7, 3, 3, 7}

const points = 8 * 4 * 4 * 8

type pointSet [points]bool

func index(p []uint32) int {
	return int(((p[0]*4+p[1])*4+p[2])*8 + p[3])
}

func forEachPoint(fn func(p []uint32)) {
	p := make([]uint32, 4)
	for a := range uint32(8) {
		for b := range uint32(4) {
			for c := range uint32(4) {
				for d := range uint32(8) {
					p[0], p[1], p[2], p[3] = a, b, c, d
					fn(p)
				}
			}
		}
	}
}

func enumerate(s Space) pointSet {
	var out pointSet
	forEachPoint(func(p []uint32) { out[index(p)] = s.Contains(p...) })
	return out
}

func randomDimSet(rng *rand.Rand, maxValue uint32) interval.Set {
	var rs []interval.Range
	for range 1 + rng.IntN(2) {
		lo := uint32(rng.IntN(int(maxValue) + 1))
		hi := lo + uint32(rng.IntN(int(maxValue-lo)+1))
		rs = append(rs, interval.Range{Lo: lo, Hi: hi})
	}
	s, err := interval.FromRanges(rs...)
	if err != nil {
		panic(err)
	}
	return s
}

func randomSpace(rng *rand.Rand) Space {
	u := Universe(maxes...)
	out := u.Empty()
	for range rng.IntN(4) {
		b := make(Box, len(maxes))
		for i, m := range maxes {
			b[i] = randomDimSet(rng, m)
		}
		out = out.Union(u.Box(b))
	}
	return out
}

func checkInvariant(t *testing.T, s Space) {
	t.Helper()
	for i, a := range s.boxes {
		for j, set := range a {
			if set.IsEmpty() {
				t.Fatalf("box %d has empty dim %d", i, j)
			}
		}
		for _, b := range s.boxes[i+1:] {
			if _, overlap := a.intersect(b); overlap {
				t.Fatalf("boxes overlap: %v and %v", a, b)
			}
		}
	}
}

func TestPropertyAgainstPointOracle(t *testing.T) {
	rng := rand.New(rand.NewPCG(7, 11))
	for iter := range 1500 {
		a, b := randomSpace(rng), randomSpace(rng)
		pa, pb := enumerate(a), enumerate(b)
		var wantU, wantI, wantS, wantC pointSet
		for i := range wantU {
			wantU[i] = pa[i] || pb[i]
			wantI[i] = pa[i] && pb[i]
			wantS[i] = pa[i] && !pb[i]
			wantC[i] = !pa[i]
		}
		ops := []struct {
			name string
			got  Space
			want pointSet
		}{
			{"union", a.Union(b), wantU},
			{"intersect", a.Intersect(b), wantI},
			{"subtract", a.Subtract(b), wantS},
			{"complement", a.Complement(), wantC},
		}
		for _, op := range ops {
			checkInvariant(t, op.got)
			if enumerate(op.got) != op.want {
				t.Fatalf("iter %d: %s wrong\n a=%v\n b=%v\n got=%v", iter, op.name, a, b, op.got)
			}
		}
		if a.Equal(b) != (pa == pb) {
			t.Fatalf("iter %d: Equal wrong", iter)
		}
		if a.SubsetOf(b) != (wantS == pointSet{}) {
			t.Fatalf("iter %d: SubsetOf wrong", iter)
		}
		if a.IsEmpty() != (pa == pointSet{}) {
			t.Fatalf("iter %d: IsEmpty wrong", iter)
		}

		dim := rng.IntN(len(maxes))
		checkCylinder(t, a, pa, dim)
		checkRestrictProject(t, a, pa, dim, randomDimSet(rng, maxes[dim]))
	}
}

func checkCylinder(t *testing.T, s Space, ps pointSet, dim int) {
	t.Helper()
	got := s.Cylinder(dim)
	checkInvariant(t, got)
	q := make([]uint32, 4)
	forEachPoint(func(p []uint32) {
		want := false
		copy(q, p)
		for v := uint32(0); v <= maxes[dim]; v++ {
			q[dim] = v
			if ps[index(q)] {
				want = true
				break
			}
		}
		if got.Contains(p...) != want {
			t.Fatalf("cylinder(%d) of %v wrong at %v", dim, s, p)
		}
	})
}

func checkRestrictProject(t *testing.T, s Space, ps pointSet, dim int, set interval.Set) {
	t.Helper()
	got := s.Restrict(dim, set)
	checkInvariant(t, got)
	var proj interval.Set
	forEachPoint(func(p []uint32) {
		want := ps[index(p)] && set.Contains(p[dim])
		if got.Contains(p...) != want {
			t.Fatalf("restrict wrong at %v", p)
		}
		if ps[index(p)] {
			proj = proj.Union(interval.Single(p[dim]))
		}
	})
	if !s.Project(dim).Equal(proj) {
		t.Fatalf("project(%d) = %v want %v", dim, s.Project(dim), proj)
	}
}

func TestCompactMergesAdjacentBoxes(t *testing.T) {
	u := Universe(maxes...)
	left := u.Box(Box{interval.Span(0, 3), interval.Full(3), interval.Full(3), interval.Full(7)})
	right := u.Box(Box{interval.Span(4, 7), interval.Full(3), interval.Full(3), interval.Full(7)})
	got := left.Union(right)
	if got.NumBoxes() != 1 || !got.Equal(u) {
		t.Fatalf("expected a single universe box, got %v", got)
	}
	if u.Subtract(u).String() != "∅" {
		t.Fatal("empty rendering")
	}
	if u.String() == "" || u.Dims() != 4 || u.Max(3) != 7 {
		t.Fatal("accessors")
	}
}

func TestBoxClippingAndMismatchPanics(t *testing.T) {
	u := Universe(maxes...)
	out := u.Box(Box{interval.Span(100, 200), interval.Full(3), interval.Full(3), interval.Full(7)})
	if !out.IsEmpty() {
		t.Fatal("box outside domain must clip to empty")
	}
	if u.Contains(1, 2) {
		t.Fatal("wrong arity point must not be contained")
	}
	assertPanics(t, func() { u.Box(Box{interval.Full(1)}) })
	assertPanics(t, func() { u.Union(Universe(1, 1)) })
}

func assertPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	fn()
}

func BenchmarkSubtractFragmentation(b *testing.B) {
	u := Universe(interval.MaxIPv4, 255, 65535, 65535)
	rng := rand.New(rand.NewPCG(1, 1))
	var holes []Space
	for range 64 {
		lo := rng.Uint32()
		port := uint32(rng.IntN(65536))
		holes = append(holes, u.Box(Box{interval.Span(lo, lo+1<<16), interval.Single(6),
			interval.Full(65535), interval.Single(port)}))
	}
	b.ResetTimer()
	for range b.N {
		s := u
		for _, h := range holes {
			s = s.Subtract(h)
		}
	}
}
