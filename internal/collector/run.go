package collector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

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
}

// Run collects until ctx is done: the acceptor and reader start before the store opens, READY=1 goes
// out once the reader runs, and on stop the reader gets shutdownRead for what Laurel already sent
// before the writer stores it and closes the store.
func Run(ctx context.Context, cfg Config) error {
	loss := &Losses{}
	q := NewQueue(QueueBytes, loss)
	reader := NewReader(q, time.Now)
	canary, err := NewCanary(cfg.CanaryDir, os.Getuid(), os.Getpid())
	if err != nil {
		return err
	}
	refused := &Refusals{}
	acc := NewAcceptor(cfg.Listener, cfg.LaurelUID, refused, time.Now)
	w := &Writer{
		Queue: q, Losses: loss, Refusals: refused, Reader: reader, Links: &Links{}, Canary: canary,
		Open: cfg.OpenStore, Now: time.Now, Notify: cfg.Notify, Log: cfg.Log, Started: cfg.Started,
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
