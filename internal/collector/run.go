package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/rawrecord"
	"github.com/Balistid/balistid-blue/internal/store"
)

const (
	// QueueBytes bounds the queue: about 3.5 s of input at the store's ~18 MB/s, so a burst the writer
	// still absorbs within crash_loss_ms is not dropped (ADR 0016, point 6; measured in the range).
	QueueBytes = 64 << 20
	// shutdownRead is how long a stopping collector still reads what Laurel already sent (ADR 0016).
	shutdownRead = 100 * time.Millisecond
)

// ClosingListener is a Listener the owner closes to stop accepting; *net.UnixListener satisfies it.
type ClosingListener interface {
	Listener
	Close() error
}

// Config is what Run needs from main.
type Config struct {
	Listener  ClosingListener
	LaurelUID int // -1 when the account could not be resolved: every peer is refused
	CanaryDir string
	OpenStore func(ctx context.Context) (Store, error)
	Notify    func(state string) error
	Log       *slog.Logger
	Started   map[string]string
	// Audit reads the kernel's and auditd's loss and health (ADR 0038); Run refuses to start without it (R6).
	Audit *Audit
	// QueueBytes bounds the queue: QueueBytes, or less in the range (ADR 0039, point 2); Run refuses more, or
	// less than one largest record.
	QueueBytes int
	// LogCommits journals the store's last durable seq on every change (Writer.LogCommits).
	LogCommits bool
	// Ledger streams to the ledger (ADR 0027); nil runs without one.
	Ledger *Ledger
	// Cosign and Retention retire shards by the ledger's cosigned frames (Writer.Cosign, ADR 0029).
	Cosign    *cosign.Keys
	Retention time.Duration
}

// Run collects until ctx is done: the acceptor and reader start before the store opens, READY=1 goes
// out once the reader runs, and on stop the reader gets shutdownRead for what Laurel already sent
// before the writer stores it and closes the store.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Audit == nil {
		return errors.New("collector: no audit source, so no kernel or dispatcher loss would show")
	}
	if least := largestRecord(); cfg.QueueBytes < least || cfg.QueueBytes > QueueBytes {
		return fmt.Errorf("collector: a queue of %d bytes, not between one largest record (%d) and %d",
			cfg.QueueBytes, least, QueueBytes)
	}
	loss := &Losses{}
	q := NewQueue(cfg.QueueBytes, loss)
	reader := NewReader(q, time.Now)
	canary, err := NewCanary(cfg.CanaryDir, os.Getuid(), os.Getpid())
	if err != nil {
		return err
	}
	refused := &Refusals{}
	acc := NewAcceptor(cfg.Listener, cfg.LaurelUID, refused, time.Now)
	w := &Writer{
		Queue: q, Losses: loss, Refusals: refused, Reader: reader, Links: &Links{}, Canary: canary,
		Open: cfg.OpenStore, Now: time.Now, Notify: cfg.Notify, Log: cfg.Log, Started: cfg.Started, Audit: cfg.Audit,
		LogCommits: cfg.LogCommits, Ledger: cfg.Ledger, Cosign: cfg.Cosign, Retention: cfg.Retention,
	}

	var wg sync.WaitGroup
	var accErr, writeErr error
	stop := make(chan struct{})
	ticker := time.NewTicker(store.FlushEvery)
	defer ticker.Stop()
	accepted := make(chan struct{})
	wg.Add(3)
	go func() {
		defer wg.Done()
		defer close(accepted)
		accErr = acc.Run(ctx)
	}()
	go func() {
		defer wg.Done()
		writeErr = w.Run(context.WithoutCancel(ctx), ticker.C, stop)
	}()
	if cfg.Ledger != nil {
		wg.Go(func() { cfg.Ledger.Run(ctx) })
	}
	go func() { // ends a pending accept on stop
		defer wg.Done()
		select {
		case <-ctx.Done():
			_ = cfg.Listener.Close() // Run reports the acceptor's error instead
		case <-accepted:
		}
	}()

	if err := cfg.Notify("READY=1"); err != nil {
		cfg.Log.Error("ready notify failed", "err", err)
	}
	for c := range acc.Conns() {
		readOne(ctx, reader, w.Links, c, cfg.Log)
		acc.Done()
	}
	close(stop)
	wg.Wait()
	if errors.Is(accErr, context.Canceled) {
		accErr = nil
	}
	return errors.Join(accErr, writeErr)
}

// readOne reads c to EOF; once ctx is done it reads only what arrives within shutdownRead.
func readOne(ctx context.Context, r *Reader, links *Links, c Conn, log *slog.Logger) {
	links.Connected(c.Peer.PID)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			if err := c.SetReadDeadline(time.Now().Add(shutdownRead)); err != nil {
				log.Error("read deadline not set", "err", err)
			}
		case <-done:
		}
	}()
	// A read error is counted with the connection's end, not logged per connection: Laurel can flap.
	err := r.ReadConn(context.WithoutCancel(ctx), c)
	if errors.Is(err, os.ErrDeadlineExceeded) { // the stop deadline, not a failure
		err = nil
	}
	close(done)
	wg.Wait()
	if err := c.Close(); err != nil {
		log.Error("connection close failed", "err", fmt.Errorf("collector: %w", err))
	}
	links.Disconnected(err)
}

// largestRecord is the encoded size of the largest record the reader queues: a sensor line kept whole up to
// rawrecord.MaxBytes.
func largestRecord() int {
	return rawrecord.New(0, store.SensorProvider, 0, 0, make([]byte, rawrecord.MaxBytes)).EncodedLen()
}
