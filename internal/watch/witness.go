// Package watch is the Pi's side of the log (ADR 0031): it follows the size and root its own witness
// cosigned, verifies the relay's entry bundles against them, checks what the entries say and alerts the
// maintainer's phone. Everything the relay serves comes from the host, whose root is the adversary (A2):
// it is read with a cap, parsed strictly and counts only once it matches the witness's root.
package watch

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html"
	"regexp"
	"strconv"
	"strings"
)

// maxIndex caps litewitness's index page: a few lines per log it witnesses.
const maxIndex = 64 << 10

// Head is what the witness keeps of one log: the size and root it last cosigned.
type Head struct {
	Size uint64
	Root [32]byte
}

// ErrNotListed: the witness does not witness the origin, or not yet (`witnessctl add-log`).
var ErrNotListed = errors.New("watch: origin not listed by the witness")

// indexSize is the line after the origin's in litewitness v0.10.0's index: tree size and base64 root.
var indexSize = regexp.MustCompile(`^  \(size (0|[1-9][0-9]{0,19}), root ([A-Za-z0-9+/]{43}=)\)$`)

// ParseIndex reads origin's size and root from litewitness's index page, which lists each log as
// "- <origin, HTML-escaped>" followed by "  (size N, root B64)". The origin listed twice, or a line that
// does not parse, is refused rather than skipped (R6).
func ParseIndex(b []byte, origin string) (Head, error) {
	if len(b) > maxIndex {
		return Head{}, fmt.Errorf("watch: witness index over %d bytes", maxIndex)
	}
	want := "- " + html.EscapeString(origin)
	lines := strings.Split(string(b), "\n")
	var h Head
	found := false
	for i, l := range lines {
		if l != want {
			continue
		}
		if found {
			return Head{}, errors.New("watch: origin listed twice by the witness")
		}
		found = true
		var m []string
		if i+1 < len(lines) {
			m = indexSize.FindStringSubmatch(lines[i+1])
		}
		if m == nil {
			return Head{}, errors.New("watch: witness index: no size and root after the origin")
		}
		size, err := strconv.ParseUint(m[1], 10, 64)
		if err != nil {
			return Head{}, fmt.Errorf("watch: witness index size: %w", err)
		}
		root, err := base64.StdEncoding.Strict().DecodeString(m[2])
		if err != nil || len(root) != len(h.Root) {
			return Head{}, errors.New("watch: witness index root is not 32 bytes of base64")
		}
		h.Size = size
		copy(h.Root[:], root)
	}
	if !found {
		return Head{}, ErrNotListed
	}
	return h, nil
}
