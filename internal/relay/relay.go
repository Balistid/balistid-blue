// Package relay carries the ledger's signed checkpoints to the witness and keeps what the witness
// cosigns (ADR 0006, 0026). It holds no signing key: it reads the ledger's log, proves each new
// checkpoint consistent with the last one the witness cosigned and stores a cosigned checkpoint only
// after the witness's key verifies the cosignature. The protocol is c2sp.org/tlog-witness add-checkpoint.
package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/wholefile"
)

// CosignedName is the file, in the relay's directory, that holds the last checkpoint the witness
// cosigned: the ledger's checkpoint note with the witness's verified cosignature lines appended.
const CosignedName = "checkpoint.cosigned"

const (
	maxProof    = 63       // tlog-witness: the client must not send more lines
	maxResponse = 64 << 10 // a few signature lines; anything longer is refused unread
	maxSizeBody = 21       // up to 20 decimal digits and the newline
)

var sizeLine = regexp.MustCompile(`^(0|[1-9][0-9]{0,19})\n$`)

// Config names what the relay reads, where it keeps its one file and whom it trusts.
type Config struct {
	Log     string        // the ledger's log directory, read only
	State   string        // the relay's own directory
	Origin  string        // the log's origin line
	LogKey  note.Verifier // the ledger's checkpoint key
	Witness note.Verifier // the witness's cosignature/v1 key
	Submit  string        // the witness's add-checkpoint URL
	HTTP    *http.Client  // with a timeout; the witness is the only host it reaches
}

// Relay submits checkpoints one at a time; it is not safe for concurrent use.
type Relay struct {
	cfg   Config
	log   client.FileFetcher
	size  uint64 // what the witness last told it cosigned
	known bool   // false until the witness answered once: the first request asks with old 0
}

// New checks cfg; it opens nothing.
func New(cfg Config) (*Relay, error) {
	u, err := url.Parse(cfg.Submit)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || !strings.HasSuffix(u.Path, "/add-checkpoint") {
		return nil, errors.New("relay: submit URL must be http(s)://host/.../add-checkpoint")
	}
	if !filepath.IsAbs(cfg.Log) || !filepath.IsAbs(cfg.State) || cfg.Origin == "" || cfg.LogKey == nil ||
		cfg.Witness == nil || cfg.HTTP == nil || cfg.HTTP.Timeout <= 0 {
		return nil, errors.New("relay: incomplete config")
	}
	return &Relay{cfg: cfg, log: client.FileFetcher{Root: cfg.Log}}, nil
}

// Run submits the log's checkpoint every interval until ctx ends. A failed step is logged and retried
// at the next tick: the witness being away is expected, and the Pi alarms on silence (ADR 0006).
func (r *Relay) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := r.Step(ctx); err != nil && ctx.Err() == nil {
			slog.ErrorContext(ctx, "relay: checkpoint not cosigned", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// errConflict is the witness's 409: it cosigned another size than the one the request named.
type errConflict struct{ size uint64 }

func (e errConflict) Error() string { return fmt.Sprintf("witness cosigned size %d", e.size) }

// Step submits the log's current checkpoint unless the witness already cosigned its size. A 409
// corrects the old size once; a witness ahead of the log means the log lost cosigned history (T12).
func (r *Relay) Step(ctx context.Context) error {
	cp, raw, n, err := client.FetchCheckpoint(ctx, r.log.ReadCheckpoint, r.cfg.LogKey, r.cfg.Origin)
	if err != nil {
		return fmt.Errorf("relay: ledger checkpoint: %w", err)
	}
	if r.known && r.size == cp.Size {
		return nil
	}
	for range 2 {
		if r.known && r.size > cp.Size {
			return fmt.Errorf("relay: witness cosigned size %d, the log has %d: cosigned history is gone", r.size, cp.Size)
		}
		sigs, err := r.submit(ctx, cp.Size, raw, n.Text)
		var c errConflict
		if errors.As(err, &c) {
			r.size, r.known = c.size, true
			continue
		}
		if err != nil {
			return err
		}
		if err := wholefile.Write(filepath.Join(r.cfg.State, CosignedName), append(bytes.Clone(raw), sigs...), 0o600); err != nil {
			return fmt.Errorf("relay: %w", err)
		}
		r.size, r.known = cp.Size, true
		return nil
	}
	return errors.New("relay: the witness's size changed twice in one step")
}

// submit posts one add-checkpoint request and returns the witness's verified cosignature lines.
func (r *Relay) submit(ctx context.Context, size uint64, raw []byte, text string) ([]byte, error) {
	old := uint64(0)
	if r.known {
		old = r.size
	}
	body := fmt.Appendf(nil, "old %d\n", old)
	if old != 0 && old != size {
		pb, err := client.NewProofBuilder(ctx, size, r.log.ReadTile)
		if err != nil {
			return nil, fmt.Errorf("relay: proof: %w", err)
		}
		proof, err := pb.ConsistencyProof(ctx, old, size)
		if err != nil {
			return nil, fmt.Errorf("relay: proof %d to %d: %w", old, size, err)
		}
		if len(proof) > maxProof {
			return nil, fmt.Errorf("relay: proof of %d hashes", len(proof))
		}
		for _, h := range proof {
			body = append(base64.StdEncoding.AppendEncode(body, h), '\n')
		}
	}
	body = append(append(body, '\n'), raw...)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.Submit, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("relay: request: %w", err)
	}
	resp, err := r.cfg.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("relay: witness: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	got, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return nil, fmt.Errorf("relay: witness response: %w", err)
	}
	switch {
	case resp.StatusCode == http.StatusConflict:
		return nil, conflict(resp.Header.Get("Content-Type"), got)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("relay: witness refused old %d size %d: %s", old, size, resp.Status)
	case len(got) > maxResponse:
		return nil, errors.New("relay: witness response over the cap")
	}
	return r.cosignatures(text, got)
}

func conflict(contentType string, body []byte) error {
	if contentType != "text/x.tlog.size" || len(body) > maxSizeBody || !sizeLine.Match(body) {
		return errors.New("relay: witness 409 without a size")
	}
	size, err := strconv.ParseUint(string(bytes.TrimSuffix(body, []byte("\n"))), 10, 64)
	if err != nil {
		return fmt.Errorf("relay: witness 409 size: %w", err)
	}
	return errConflict{size}
}

// cosignatures keeps the response's signature lines the witness key verifies over text; lines of
// other keys are dropped, and a response with none verified is refused (R6).
func (r *Relay) cosignatures(text string, resp []byte) ([]byte, error) {
	n, err := note.Open(append([]byte(text+"\n"), resp...), note.VerifierList(r.cfg.Witness))
	if err != nil {
		return nil, fmt.Errorf("relay: witness cosignature: %w", err)
	}
	var out []byte
	for _, s := range n.Sigs {
		out = fmt.Appendf(out, "— %s %s\n", s.Name, s.Base64)
	}
	return out, nil
}
