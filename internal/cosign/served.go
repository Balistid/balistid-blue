package cosign

import (
	"fmt"
	"regexp"
	"strconv"
)

// ServedName is the relay's record of how far it served the log's entry bundles to the Pi, beside the
// cosigned checkpoint in its directory (ADR 0030, point 4; ADR 0031).
const ServedName = "served"

const maxServed = 256

var servedFile = regexp.MustCompile(`^balistid-served 1\n([!-~]{1,128})\n(0|[1-9][0-9]{0,19})\n$`)

// AppendServed encodes the record: the origin of the log it counts, then the number of its first entries
// the relay served in full.
func AppendServed(b []byte, origin string, entries uint64) []byte {
	return fmt.Appendf(b, "balistid-served 1\n%s\n%d\n", origin, entries)
}

// ReadServed reads the record at path for origin: no link followed, capped, decoded strictly. A record
// of another origin counts as nothing served, as after a rollover.
func ReadServed(path, origin string) (uint64, error) {
	b, err := ReadFile(nil, path, maxServed)
	if err != nil {
		return 0, fmt.Errorf("cosign: served: %w", err)
	}
	m := servedFile.FindSubmatch(b)
	if m == nil {
		return 0, fmt.Errorf("cosign: %s is not a served record", path)
	}
	if string(m[1]) != origin {
		return 0, nil
	}
	n, err := strconv.ParseUint(string(m[2]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("cosign: served: %w", err)
	}
	return n, nil
}
