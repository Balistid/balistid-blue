package watch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/Balistid/balistid-blue/internal/entry"
)

// maxBundle caps one entry bundle: 256 entries of at most entry.MaxBytes, each with its length.
const maxBundle = layout.EntryBundleWidth * (2 + entry.MaxBytes)

// errMissing is a 404: the relay has no such bundle, or no partial one any more.
var errMissing = errors.New("not served")

// Source is where the Pi reads: its witness's index page and the relay's base URL. HTTP has a timeout
// and follows no redirect.
type Source struct {
	Witness string
	Relay   string
	HTTP    *http.Client
}

// CheckURLs refuses a URL with a user, query or fragment, and a relay base without its final slash.
func CheckURLs(witness, relay string) error {
	if err := errors.Join(checkURL(witness), checkURL(relay)); err != nil {
		return err
	}
	if !strings.HasSuffix(relay, "/") {
		return errors.New("watch: the relay URL must end with /")
	}
	return nil
}

func checkURL(s string) error {
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return errors.New("watch: a URL must be http(s)://host/..., no user, query or fragment")
	}
	return nil
}

// checkPushURL: the token goes out with every alert, so the ntfy URL is https, or plain http only to a
// loopback address (the range's stand-in).
func checkPushURL(s string) error {
	if err := checkURL(s); err != nil {
		return err
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("watch: push URL: %w", err)
	}
	if ip := net.ParseIP(u.Hostname()); u.Scheme != "https" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("watch: the push URL must be https, or http to a loopback address")
	}
	return nil
}

// Head reads the witness's size and root for origin.
func (s Source) Head(ctx context.Context, origin string) (Head, error) {
	b, err := s.get(ctx, s.Witness, maxIndex)
	if err != nil {
		return Head{}, fmt.Errorf("watch: witness: %w", err)
	}
	return ParseIndex(b, origin)
}

// Bundle returns the first width entries of bundle idx, 1 to 256, asked for at exactly that width: the
// relay serves a partial bundle Tessera replaced from its full one, and records what was asked, which
// the announce client waits for (ADR 0030, point 4).
func (s Source) Bundle(ctx context.Context, idx, width uint64) ([][]byte, error) {
	if width == 0 || width > layout.EntryBundleWidth {
		return nil, fmt.Errorf("watch: bundle width %d", width)
	}
	p := uint8(width % layout.EntryBundleWidth)
	b, err := s.get(ctx, s.Relay+layout.EntriesPath(idx, p), maxBundle)
	if err != nil {
		return nil, fmt.Errorf("watch: bundle %d: %w", idx, err)
	}
	entries, err := ParseBundle(b)
	if err != nil {
		return nil, fmt.Errorf("watch: bundle %d: %w", idx, err)
	}
	want := uint64(layout.EntryBundleWidth)
	if p != 0 {
		want = uint64(p)
	}
	if uint64(len(entries)) != want {
		return nil, fmt.Errorf("watch: bundle %d.p/%d holds %d entries", idx, p, len(entries))
	}
	return entries[:width], nil
}

// get reads one URL: 200 only, at most limit bytes.
func (s Source) get(ctx context.Context, u string, limit int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get: %w", localError(err))
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, errMissing
	default:
		return nil, fmt.Errorf("get: status %d", resp.StatusCode) // the reason phrase is the server's text
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("get: body over %d bytes", limit)
	}
	return b, nil
}

// localError keeps of a failed request only what this side knows: the context's end, or a socket
// error. Anything else came from the peer's bytes (a malformed status line, a bad header), whose text
// would reach the journal; it becomes one fixed error.
func localError(err error) error {
	var op *net.OpError
	var nerr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &nerr) && nerr.Timeout()):
		return context.DeadlineExceeded
	case errors.As(err, &op) && op.Op == "dial":
		return fmt.Errorf("dial: %w", op.Err)
	}
	return errInvalid
}

var errInvalid = errors.New("no valid HTTP response")

// ParseBundle splits a tlog-tiles entry bundle: each entry a big-endian 2-byte length and its bytes. At
// most 256 entries of 1 to entry.MaxBytes bytes each, and nothing after the last one.
func ParseBundle(b []byte) ([][]byte, error) {
	if len(b) > maxBundle {
		return nil, fmt.Errorf("bundle over %d bytes", maxBundle)
	}
	var out [][]byte
	for len(b) > 0 {
		if len(out) == layout.EntryBundleWidth {
			return nil, errors.New("bundle of more than 256 entries")
		}
		if len(b) < 2 {
			return nil, errors.New("bundle ends inside a length")
		}
		n := int(binary.BigEndian.Uint16(b))
		if n == 0 || n > entry.MaxBytes || len(b)-2 < n {
			return nil, fmt.Errorf("bundle entry of %d bytes", n)
		}
		out = append(out, b[2:2+n:2+n])
		b = b[2+n:]
	}
	if len(out) == 0 {
		return nil, errors.New("empty bundle")
	}
	return out, nil
}
