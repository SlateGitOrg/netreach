// Package interval implements sets of unsigned 32-bit integers represented as
// sorted, disjoint, non-adjacent closed intervals.
//
// It is the arithmetic core of netreach: IPv4 address sets, protocol sets and
// port sets are all interval sets over different domains. Every operation runs
// in time linear in the number of intervals of its operands; no element is
// ever enumerated.
package interval

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Range is the closed interval [Lo, Hi]. A Range with Lo > Hi is invalid and
// is rejected by the constructors in this package.
type Range struct {
	Lo, Hi uint32
}

// Size returns the number of integers in r.
func (r Range) Size() uint64 { return uint64(r.Hi) - uint64(r.Lo) + 1 }

// Set is an immutable set of uint32 values. The zero value is the empty set.
// Internally the ranges are sorted by Lo, pairwise disjoint and never adjacent
// (r[i].Hi+1 < r[i+1].Lo), which makes the representation canonical: two Sets
// are equal as sets if and only if their range slices are identical.
type Set struct {
	r []Range
}

// Empty returns the empty set.
func Empty() Set { return Set{} }

// Single returns the set {v}.
func Single(v uint32) Set { return Set{r: []Range{{v, v}}} }

// Span returns the set [lo, hi]. It panics if lo > hi, which is always a
// programming error in callers (user input is validated before reaching here).
func Span(lo, hi uint32) Set {
	if lo > hi {
		panic(fmt.Sprintf("interval: invalid span %d-%d", lo, hi))
	}
	return Set{r: []Range{{lo, hi}}}
}

// Full returns the set [0, max].
func Full(maxValue uint32) Set { return Span(0, maxValue) }

// FromRanges builds a Set from arbitrary (possibly overlapping, unsorted)
// ranges. It returns an error if any range has Lo > Hi.
func FromRanges(rs ...Range) (Set, error) {
	for _, r := range rs {
		if r.Lo > r.Hi {
			return Set{}, fmt.Errorf("interval: invalid range %d-%d", r.Lo, r.Hi)
		}
	}
	return normalize(slices.Clone(rs)), nil
}

// normalize sorts and coalesces rs in place and wraps it in a Set.
func normalize(rs []Range) Set {
	if len(rs) == 0 {
		return Set{}
	}
	slices.SortFunc(rs, func(a, b Range) int {
		switch {
		case a.Lo < b.Lo:
			return -1
		case a.Lo > b.Lo:
			return 1
		}
		return 0
	})
	out := rs[:1]
	for _, r := range rs[1:] {
		last := &out[len(out)-1]
		// Adjacent or overlapping: extend. Guard the +1 against overflow.
		if last.Hi == ^uint32(0) || r.Lo <= last.Hi+1 {
			if r.Hi > last.Hi {
				last.Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return Set{r: out}
}

// Ranges returns a copy of the canonical ranges of s.
func (s Set) Ranges() []Range { return slices.Clone(s.r) }

// Len returns the number of canonical ranges in s.
func (s Set) Len() int { return len(s.r) }

// IsEmpty reports whether s has no elements.
func (s Set) IsEmpty() bool { return len(s.r) == 0 }

// Size returns the number of elements of s.
func (s Set) Size() uint64 {
	var n uint64
	for _, r := range s.r {
		n += r.Size()
	}
	return n
}

// Min returns the smallest element of s; ok is false if s is empty.
func (s Set) Min() (v uint32, ok bool) {
	if len(s.r) == 0 {
		return 0, false
	}
	return s.r[0].Lo, true
}

// Contains reports whether v is in s. It runs in O(log n).
func (s Set) Contains(v uint32) bool {
	i, _ := slices.BinarySearchFunc(s.r, v, func(r Range, v uint32) int {
		switch {
		case r.Hi < v:
			return -1
		case r.Lo > v:
			return 1
		}
		return 0
	})
	return i < len(s.r) && s.r[i].Lo <= v && v <= s.r[i].Hi
}

// Equal reports whether s and t contain the same elements.
func (s Set) Equal(t Set) bool { return slices.Equal(s.r, t.r) }

// SubsetOf reports whether every element of s is in t.
func (s Set) SubsetOf(t Set) bool { return s.Subtract(t).IsEmpty() }

// Union returns s ∪ t in O(n+m).
func (s Set) Union(t Set) Set {
	if len(s.r) == 0 {
		return t
	}
	if len(t.r) == 0 {
		return s
	}
	merged := make([]Range, 0, len(s.r)+len(t.r))
	i, j := 0, 0
	for i < len(s.r) || j < len(t.r) {
		var next Range
		if j >= len(t.r) || (i < len(s.r) && s.r[i].Lo <= t.r[j].Lo) {
			next = s.r[i]
			i++
		} else {
			next = t.r[j]
			j++
		}
		if n := len(merged); n > 0 {
			last := &merged[n-1]
			if last.Hi == ^uint32(0) || next.Lo <= last.Hi+1 {
				if next.Hi > last.Hi {
					last.Hi = next.Hi
				}
				continue
			}
		}
		merged = append(merged, next)
	}
	return Set{r: merged}
}

// Intersect returns s ∩ t in O(n+m).
func (s Set) Intersect(t Set) Set {
	var out []Range
	i, j := 0, 0
	for i < len(s.r) && j < len(t.r) {
		a, b := s.r[i], t.r[j]
		lo, hi := max(a.Lo, b.Lo), min(a.Hi, b.Hi)
		if lo <= hi {
			out = append(out, Range{lo, hi})
		}
		if a.Hi < b.Hi {
			i++
		} else {
			j++
		}
	}
	return Set{r: out}
}

// Subtract returns s \ t in O(n+m).
func (s Set) Subtract(t Set) Set {
	if len(s.r) == 0 || len(t.r) == 0 {
		return s
	}
	var out []Range
	j := 0
	for _, a := range s.r {
		lo := a.Lo
		done := false
		for j < len(t.r) && t.r[j].Hi < lo {
			j++
		}
		for k := j; k < len(t.r) && t.r[k].Lo <= a.Hi; k++ {
			b := t.r[k]
			if b.Lo > lo {
				out = append(out, Range{lo, b.Lo - 1})
			}
			if b.Hi >= a.Hi {
				done = true
				break
			}
			lo = b.Hi + 1
		}
		if !done {
			out = append(out, Range{lo, a.Hi})
		}
	}
	return Set{r: out}
}

// Complement returns [0, maxValue] \ s.
func (s Set) Complement(maxValue uint32) Set { return Full(maxValue).Subtract(s) }

// String renders s as comma-separated ranges, e.g. "22,80-81,443".
// The empty set renders as "∅".
func (s Set) String() string {
	return s.Format(func(v uint32) string { return strconv.FormatUint(uint64(v), 10) })
}

// Format renders s with a custom element formatter.
func (s Set) Format(f func(uint32) string) string {
	if len(s.r) == 0 {
		return "∅"
	}
	parts := make([]string, 0, len(s.r))
	for _, r := range s.r {
		if r.Lo == r.Hi {
			parts = append(parts, f(r.Lo))
		} else {
			parts = append(parts, f(r.Lo)+"-"+f(r.Hi))
		}
	}
	return strings.Join(parts, ",")
}

// Parse parses the String format ("22,80-81,443"); "∅" or "" is the empty set.
func Parse(text string) (Set, error) {
	text = strings.TrimSpace(text)
	if text == "" || text == "∅" {
		return Set{}, nil
	}
	var rs []Range
	for _, part := range strings.Split(text, ",") {
		part = strings.TrimSpace(part)
		loText, hiText, isRange := strings.Cut(part, "-")
		lo, err := strconv.ParseUint(strings.TrimSpace(loText), 10, 32)
		if err != nil {
			return Set{}, fmt.Errorf("interval: bad value %q: %w", loText, err)
		}
		hi := lo
		if isRange {
			hi, err = strconv.ParseUint(strings.TrimSpace(hiText), 10, 32)
			if err != nil {
				return Set{}, fmt.Errorf("interval: bad value %q: %w", hiText, err)
			}
		}
		rs = append(rs, Range{uint32(lo), uint32(hi)})
	}
	return FromRanges(rs...)
}
