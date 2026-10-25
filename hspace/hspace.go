// Package hspace implements header spaces: finite unions of disjoint
// axis-aligned boxes in a product of integer domains.
//
// netreach describes a set of flows as a 4-dimensional header space
// (remote IP × protocol × source port × destination port). Each box stores an
// interval.Set per dimension, so a rule such as "tcp 80,443 from 10.0.0.0/8"
// is a single box regardless of how many packets it admits.
//
// Representation invariant: the boxes of a Space are non-empty in every
// dimension and pairwise disjoint. All operations preserve it, which keeps
// subtraction (the operation that ordered, first-match-wins rule lists need)
// exact without ever enumerating points.
package hspace

import (
	"fmt"
	"slices"
	"strings"

	"github.com/SlateGitOrg/netreach/interval"
)

// Box is a product of non-empty interval sets, one per dimension.
type Box []interval.Set

// Clone returns a copy of b that shares no slice with it.
func (b Box) Clone() Box { return slices.Clone(b) }

// String renders b as "[d0 × d1 × ...]".
func (b Box) String() string {
	parts := make([]string, len(b))
	for i, s := range b {
		parts[i] = s.String()
	}
	return "[" + strings.Join(parts, " × ") + "]"
}

// intersect returns a ∩ b and whether it is non-empty.
func (b Box) intersect(o Box) (Box, bool) {
	out := make(Box, len(b))
	for i := range b {
		out[i] = b[i].Intersect(o[i])
		if out[i].IsEmpty() {
			return nil, false
		}
	}
	return out, true
}

// subtract returns a \ o as at most len(a) pairwise-disjoint boxes.
//
// Writing X = a ∩ o, the pieces are, for each dimension i,
//
//	X_0 × … × X_{i-1} × (a_i \ o_i) × a_{i+1} × … × a_{d-1}
//
// Piece i differs from every later piece in dimension i (a_i\o_i versus
// a_i∩o_i), so the pieces are disjoint, and together with X they cover a.
func (b Box) subtract(o Box) []Box {
	inter, ok := b.intersect(o)
	if !ok {
		return []Box{b}
	}
	var out []Box
	for i := range b {
		rest := b[i].Subtract(o[i])
		if rest.IsEmpty() {
			continue
		}
		piece := make(Box, len(b))
		copy(piece[:i], inter[:i])
		piece[i] = rest
		copy(piece[i+1:], b[i+1:])
		out = append(out, piece)
	}
	return out
}

func (b Box) contains(p []uint32) bool {
	for i, s := range b {
		if !s.Contains(p[i]) {
			return false
		}
	}
	return true
}

// Space is an immutable set of points in [0,max_0] × … × [0,max_{d-1}].
type Space struct {
	maxes []uint32
	boxes []Box
}

// Universe returns the whole domain with the given per-dimension maxima.
func Universe(maxes ...uint32) Space {
	b := make(Box, len(maxes))
	for i, m := range maxes {
		b[i] = interval.Full(m)
	}
	return Space{maxes: slices.Clone(maxes), boxes: []Box{b}}
}

// Dims returns the number of dimensions.
func (s Space) Dims() int { return len(s.maxes) }

// Max returns the maximum value of dimension dim.
func (s Space) Max(dim int) uint32 { return s.maxes[dim] }

// Empty returns the empty space with the same dimensions as s.
func (s Space) Empty() Space { return Space{maxes: s.maxes} }

// Box returns the space containing the single box b (clipped to the domain).
// The box must have one set per dimension.
func (s Space) Box(b Box) Space {
	if len(b) != len(s.maxes) {
		panic(fmt.Sprintf("hspace: box has %d dims, space has %d", len(b), len(s.maxes)))
	}
	clipped := make(Box, len(b))
	for i, set := range b {
		clipped[i] = set.Intersect(interval.Full(s.maxes[i]))
		if clipped[i].IsEmpty() {
			return s.Empty()
		}
	}
	return Space{maxes: s.maxes, boxes: []Box{clipped}}
}

// IsEmpty reports whether s contains no point.
func (s Space) IsEmpty() bool { return len(s.boxes) == 0 }

// NumBoxes returns the number of disjoint boxes in the representation.
func (s Space) NumBoxes() int { return len(s.boxes) }

// Boxes returns copies of the disjoint boxes of s.
func (s Space) Boxes() []Box {
	out := make([]Box, len(s.boxes))
	for i, b := range s.boxes {
		out[i] = b.Clone()
	}
	return out
}

func (s Space) check(o Space) {
	if !slices.Equal(s.maxes, o.maxes) {
		panic(fmt.Sprintf("hspace: dimension mismatch %v vs %v", s.maxes, o.maxes))
	}
}

// Contains reports whether point p (one coordinate per dimension) is in s.
func (s Space) Contains(p ...uint32) bool {
	if len(p) != len(s.maxes) {
		return false
	}
	for _, b := range s.boxes {
		if b.contains(p) {
			return true
		}
	}
	return false
}

// Intersect returns s ∩ o. Cost O(|s|·|o|·d·k) where k bounds the ranges per
// dimension set.
func (s Space) Intersect(o Space) Space {
	s.check(o)
	out := s.Empty()
	for _, a := range s.boxes {
		for _, b := range o.boxes {
			if x, ok := a.intersect(b); ok {
				out.boxes = append(out.boxes, x)
			}
		}
	}
	return out.Compact()
}

// Subtract returns s \ o. Each box of s is split against each box of o in
// turn; a split produces at most d disjoint pieces.
func (s Space) Subtract(o Space) Space {
	s.check(o)
	if s.IsEmpty() || o.IsEmpty() {
		return s
	}
	out := s.Empty()
	for _, a := range s.boxes {
		pieces := []Box{a}
		for _, b := range o.boxes {
			var next []Box
			for _, p := range pieces {
				next = append(next, p.subtract(b)...)
			}
			pieces = next
			if len(pieces) == 0 {
				break
			}
		}
		out.boxes = append(out.boxes, pieces...)
	}
	return out.Compact()
}

// Union returns s ∪ o, computed as s plus the disjoint remainder o \ s.
func (s Space) Union(o Space) Space {
	s.check(o)
	if s.IsEmpty() {
		return o
	}
	if o.IsEmpty() {
		return s
	}
	rest := o.Subtract(s)
	out := Space{maxes: s.maxes, boxes: make([]Box, 0, len(s.boxes)+len(rest.boxes))}
	out.boxes = append(out.boxes, s.boxes...)
	out.boxes = append(out.boxes, rest.boxes...)
	return out.Compact()
}

// Complement returns the domain minus s.
func (s Space) Complement() Space { return Universe(s.maxes...).Subtract(s) }

// Equal reports whether s and o contain exactly the same points.
func (s Space) Equal(o Space) bool {
	return s.Subtract(o).IsEmpty() && o.Subtract(s).IsEmpty()
}

// SubsetOf reports whether s ⊆ o.
func (s Space) SubsetOf(o Space) bool { return s.Subtract(o).IsEmpty() }

// Restrict returns s with dimension dim intersected with set.
func (s Space) Restrict(dim int, set interval.Set) Space {
	out := s.Empty()
	for _, b := range s.boxes {
		x := b[dim].Intersect(set)
		if x.IsEmpty() {
			continue
		}
		nb := b.Clone()
		nb[dim] = x
		out.boxes = append(out.boxes, nb)
	}
	return out
}

// Cylinder returns the set of points that agree with some point of s in every
// dimension except dim: it "forgets" dimension dim. Together with Complement
// this expresses universal quantification over a dimension:
//
//	{x : ∀y∈Y. (x,y) ∈ A}  =  ¬ Cylinder(¬A ∩ (dim∈Y)).
func (s Space) Cylinder(dim int) Space {
	out := s.Empty()
	for _, b := range s.boxes {
		nb := b.Clone()
		nb[dim] = interval.Full(s.maxes[dim])
		out = out.Union(Space{maxes: s.maxes, boxes: []Box{nb}})
	}
	return out
}

// Project returns the union over all boxes of dimension dim.
func (s Space) Project(dim int) interval.Set {
	var out interval.Set
	for _, b := range s.boxes {
		out = out.Union(b[dim])
	}
	return out
}

// Compact merges boxes that agree in all dimensions but one, repeating until
// no merge applies. It never changes the point set, only the representation,
// and keeps boxes disjoint (merged boxes were disjoint in the differing
// dimension). Cost per pass is O(n·d) map operations.
func (s Space) Compact() Space {
	if len(s.boxes) < 2 {
		return s
	}
	boxes := s.boxes
	for changed := true; changed; {
		changed = false
		for dim := range s.maxes {
			groups := make(map[string]int, len(boxes))
			merged := boxes[:0:0]
			for _, b := range boxes {
				key := keyWithout(b, dim)
				if idx, ok := groups[key]; ok {
					nb := merged[idx].Clone()
					nb[dim] = nb[dim].Union(b[dim])
					merged[idx] = nb
					changed = true
					continue
				}
				groups[key] = len(merged)
				merged = append(merged, b)
			}
			boxes = merged
		}
	}
	return Space{maxes: s.maxes, boxes: boxes}
}

func keyWithout(b Box, skip int) string {
	var sb strings.Builder
	for i, set := range b {
		if i == skip {
			sb.WriteString("|*")
			continue
		}
		sb.WriteByte('|')
		for _, r := range set.Ranges() {
			fmt.Fprintf(&sb, "%d-%d,", r.Lo, r.Hi)
		}
	}
	return sb.String()
}

// String renders s for debugging.
func (s Space) String() string {
	if s.IsEmpty() {
		return "∅"
	}
	parts := make([]string, len(s.boxes))
	for i, b := range s.boxes {
		parts[i] = b.String()
	}
	return strings.Join(parts, " ∪ ")
}
