package main

// serialStep compares a sensor record's kernel serial with the previous stored one's, on the day it was received: a
// jump is a serial above the previous plus one, and skips the serials between; a step back is one at or below the
// previous. They say how often neighbouring stored records are not consecutive and bound no loss: a late record is
// a jump and then a step back, a restart of the collector or of the kernel's counter is a step back.
func (rd *reader) serialStep(row *dayRow, serial uint64) {
	switch prev := rd.prevSerial; {
	case prev == 0:
	case serial-1 > prev: // serial is never 0 here, so serial-1 does not wrap
		row.Jumps++
		row.Skipped = satAdd(row.Skipped, serial-1-prev)
	case serial <= prev:
		row.StepsBack++
	}
	rd.prevSerial = serial
}
