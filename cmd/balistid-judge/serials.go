package main

import (
	"sort"
)

// seen is a run of kernel serials the store holds, with the receive time of its lowest serial: the later end of
// the hole below it.
type seen struct {
	lo, hi uint64
	loAt   int64
}

// segment is the serials of one run of the kernel's counter. A serial is missing only if no record of its run holds
// it, however late it came (ADR 0062's hold is for a live count). The kernel's first serials, from before auditd,
// are not counted: nothing below the lowest is a gap.
type segment struct {
	boot   string
	ranges []seen
}

func (g *segment) high() uint64 { return g.ranges[len(g.ranges)-1].hi }

// holes calls gap with every hole's missing serials and the receive time of its later end.
func (g *segment) holes(gap func(missing uint64, at int64)) {
	for i := 1; i < len(g.ranges); i++ {
		gap(g.ranges[i].lo-g.ranges[i-1].hi-1, g.ranges[i].loAt)
	}
}

// serials is the forward count of the kernel's serials: the run of the counter being read, and a started record
// waiting for the next serial. Holes are counted when their run ends, or past maxHeld at once, the oldest first.
type serials struct {
	cur       *segment
	segments  int
	startNext bool
	startBoot string
	duplicate uint64
	overCap   uint64
}

// started is a started record: the collector began again, on a new boot or the same.
func (s *serials) started(boot string) {
	s.startNext, s.startBoot = true, boot
}

// add takes the next serial. A started record begins a new run unless its boot is known to be the run's and the
// serial goes on above it; a serial far below the highest is the counter wrapping.
func (s *serials) add(serial uint64, at int64, gap func(uint64, int64)) {
	switch g := s.cur; {
	case g == nil:
		s.begin(s.startBoot)
	case s.startNext && (s.startBoot == "" || s.startBoot != g.boot || serial <= g.high()):
		g.holes(gap)
		s.begin(s.startBoot)
	case serial+1<<31 < g.high():
		g.holes(gap)
		s.begin(g.boot)
	}
	s.startNext = false
	s.cur.add(serial, at, s, gap)
}

func (s *serials) begin(boot string) {
	s.cur = &segment{boot: boot}
	s.segments++
}

func (g *segment) add(serial uint64, at int64, s *serials, gap func(uint64, int64)) {
	n := len(g.ranges)
	switch {
	case n == 0 || serial > g.ranges[n-1].hi+1:
		g.ranges = append(g.ranges, seen{lo: serial, hi: serial, loAt: at})
	case serial == g.ranges[n-1].hi+1:
		g.ranges[n-1].hi = serial
	default:
		g.insert(serial, at, s)
	}
	for len(g.ranges) > maxHeld {
		a, b := g.ranges[0], g.ranges[1]
		gap(b.lo-a.hi-1, b.loAt)
		s.overCap++
		g.ranges[1] = seen{lo: a.lo, hi: b.hi, loAt: a.loAt}
		g.ranges = g.ranges[1:]
	}
}

// insert places a serial below the highest: a late one fills a hole, one already held is a duplicate.
func (g *segment) insert(serial uint64, at int64, s *serials) {
	i := sort.Search(len(g.ranges), func(i int) bool { return g.ranges[i].hi >= serial })
	if g.ranges[i].lo <= serial {
		s.duplicate++
		return
	}
	// serial is between ranges[i-1].hi and ranges[i].lo, or below the first.
	joinsPrev := i > 0 && g.ranges[i-1].hi+1 == serial
	joinsNext := g.ranges[i].lo == serial+1
	switch {
	case joinsPrev && joinsNext:
		g.ranges[i-1].hi = g.ranges[i].hi
		g.ranges = append(g.ranges[:i], g.ranges[i+1:]...)
	case joinsPrev:
		g.ranges[i-1].hi = serial
	case joinsNext:
		g.ranges[i].lo, g.ranges[i].loAt = serial, at
	default:
		g.ranges = append(g.ranges[:i], append([]seen{{lo: serial, hi: serial, loAt: at}}, g.ranges[i:]...)...)
	}
}
