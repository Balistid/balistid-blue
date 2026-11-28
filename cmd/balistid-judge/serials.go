package main

import (
	"sort"
)

// seen is a run of kernel serials the store holds, with the receive times of its two ends.
type seen struct {
	lo, hi     uint64
	loAt, hiAt int64
}

// segment is the serials of one run of the kernel's counter: one boot, or what followed a collector start whose
// boot the judge cannot tell from the one before. The judge reads after the fact, so a serial is missing only if
// no record of the segment holds it, however late it came (ADR 0062's hold is for a live count); a hole between
// two runs is a gap. The kernel's first serials, from before auditd, are not counted: nothing below lo is a gap.
type segment struct {
	boot    string
	started bool // began at a started record, not in a shard not read yet
	ranges  []seen
	// holes past maxHeld are counted at once, the oldest first, and their serials no longer fill them
	forced, forcedMissing uint64
	forcedSpans           []span
	duplicate             uint64
}

func (g *segment) high() uint64 { return g.ranges[len(g.ranges)-1].hi }

func (g *segment) add(s uint64, at int64) {
	n := len(g.ranges)
	switch {
	case n == 0 || s > g.ranges[n-1].hi+1:
		g.ranges = append(g.ranges, seen{lo: s, hi: s, loAt: at, hiAt: at})
	case s == g.ranges[n-1].hi+1:
		g.ranges[n-1].hi, g.ranges[n-1].hiAt = s, at
	default:
		g.insert(s, at)
	}
	g.cap()
}

// insert places a serial below the highest: a late one fills a hole, one already held is a duplicate.
func (g *segment) insert(s uint64, at int64) {
	i := sort.Search(len(g.ranges), func(i int) bool { return g.ranges[i].hi >= s })
	if i < len(g.ranges) && g.ranges[i].lo <= s {
		g.duplicate++
		return
	}
	// s is between ranges[i-1].hi and ranges[i].lo (or below the first).
	joinsPrev := i > 0 && g.ranges[i-1].hi+1 == s
	joinsNext := g.ranges[i].lo == s+1
	switch {
	case joinsPrev && joinsNext:
		g.ranges[i-1].hi, g.ranges[i-1].hiAt = g.ranges[i].hi, g.ranges[i].hiAt
		g.ranges = append(g.ranges[:i], g.ranges[i+1:]...)
	case joinsPrev:
		g.ranges[i-1].hi, g.ranges[i-1].hiAt = s, at
	case joinsNext:
		g.ranges[i].lo, g.ranges[i].loAt = s, at
	default:
		g.ranges = append(g.ranges[:i], append([]seen{{lo: s, hi: s, loAt: at, hiAt: at}}, g.ranges[i:]...)...)
	}
}

func (g *segment) cap() {
	for len(g.ranges) > maxHeld {
		a, b := g.ranges[0], g.ranges[1]
		g.forced++
		g.forcedMissing = satAdd(g.forcedMissing, b.lo-a.hi-1)
		g.forcedSpans = append(g.forcedSpans, holeSpan(a, b))
		g.ranges[1] = seen{lo: a.lo, hi: b.hi, loAt: a.loAt, hiAt: b.hiAt}
		g.ranges = g.ranges[1:]
	}
}

// holeSpan is the time the records of a hole would have come in: between the ends that bound it, in either order.
func holeSpan(a, b seen) span {
	return span{From: min(a.hiAt, b.loAt), To: max(a.hiAt, b.loAt)}
}

// gapCount is a segment's gaps and missing serials; holes whose later end came after heldFrom are not counted but
// held, as the unsealed shard may still hold them. A held hole still cuts a clean interval: it is not known.
type gapCount struct {
	gaps, missing, held, overCap, duplicate uint64
	spans                                   []span
}

func (c *gapCount) add(g *segment, heldFrom int64) {
	c.gaps += g.forced
	c.overCap += g.forced
	c.missing = satAdd(c.missing, g.forcedMissing)
	c.duplicate += g.duplicate
	c.spans = append(c.spans, g.forcedSpans...)
	for i := 1; i < len(g.ranges); i++ {
		a, b := g.ranges[i-1], g.ranges[i]
		c.spans = append(c.spans, holeSpan(a, b))
		if b.loAt >= heldFrom {
			c.held = satAdd(c.held, b.lo-a.hi-1)
			continue
		}
		c.gaps++
		c.missing = satAdd(c.missing, b.lo-a.hi-1)
	}
}

// continues reports whether newer is the same run of the counter as older, the segment before it: it did not
// begin at a started record, or that record's boot is older's (or unknown) and its serials went on above older's.
func continues(older, newer *segment) bool {
	if !newer.started {
		return true
	}
	return (newer.boot == "" || older.boot == "" || newer.boot == older.boot) && newer.ranges[0].lo > older.high()
}

// merge puts older's serials into newer, the segment that continues it.
func merge(older, newer *segment) {
	all := append(append([]seen(nil), older.ranges...), newer.ranges...)
	sort.Slice(all, func(i, j int) bool { return all[i].lo < all[j].lo })
	out := all[:0]
	for _, r := range all {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			if r.hi > out[n-1].hi {
				out[n-1].hi, out[n-1].hiAt = r.hi, r.hiAt
			}
			continue
		}
		out = append(out, r)
	}
	newer.ranges = out
	newer.boot = older.boot
	newer.started = older.started
	newer.forced += older.forced
	newer.forcedMissing = satAdd(newer.forcedMissing, older.forcedMissing)
	newer.forcedSpans = append(newer.forcedSpans, older.forcedSpans...)
	newer.duplicate += older.duplicate
	newer.cap()
}

// serials is one shard's segments, oldest first, and a started record waiting for the next serial.
type serials struct {
	segs      []*segment
	startNext bool
	startBoot string
}

// started is a started record: the collector began again, on a new boot or the same.
func (s *serials) started(boot string) {
	s.startNext, s.startBoot = true, boot
}

func (s *serials) add(serial uint64, at int64) {
	n := len(s.segs)
	switch {
	case n == 0 || s.startNext && s.splits(serial) || serial+1<<31 < s.segs[n-1].high(): // the last: the counter wrapped
		s.segs = append(s.segs, &segment{boot: s.startBoot, started: s.startNext})
		n++
	case s.startNext && s.segs[n-1].boot == "": // a restart within the segment's boot
		s.segs[n-1].boot = s.startBoot
	}
	s.startNext = false
	s.segs[n-1].add(serial, at)
}

// splits reports whether serial, the first after a started record, begins a new run of the counter.
func (s *serials) splits(serial uint64) bool {
	cur := s.segs[len(s.segs)-1]
	return s.startBoot != "" && cur.boot != "" && s.startBoot != cur.boot || serial <= cur.high()
}

func sortSpans(spans []span) {
	sort.Slice(spans, func(i, j int) bool { return spans[i].From < spans[j].From })
}
