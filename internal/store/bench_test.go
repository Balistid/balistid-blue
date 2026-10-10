package store

import (
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/Balistid/balistid-blue/internal/shard"
)

// BenchmarkAppend measures Append, the collector's only write path, with a Flush every FlushEvery
// as the collector makes it, against sustained_rate and burst_rate (acceptance/0.toml). Run it on the
// store's real filesystem: TMPDIR on tmpfs makes every fsync free.
// Example: TMPDIR=/var/tmp go test -run '^$' -bench Append -benchtime 20000x ./internal/store/
func BenchmarkAppend(b *testing.B) {
	for _, size := range []int{1 << 10, 64 << 10, 2048 << 10} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			s, err := Open(b.Context(), b.TempDir(), Limits{Cap: 64 << 30, ShardMax: 2 << 30, Headroom: shard.WALMaxBytes + LossChunk})
			if err != nil {
				b.Fatal(err)
			}
			onDay(s, 0)
			data := make([]byte, size)
			_, _ = rand.Read(data)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			flushed := time.Now()
			for seq := uint64(1); b.Loop(); seq++ {
				stored, _, err := s.Append(b.Context(), "laurel", seq, 0, data)
				if err != nil || !stored {
					b.Fatalf("append %d: stored %v, %v", seq, stored, err)
				}
				if time.Since(flushed) >= FlushEvery {
					if _, err := s.Flush(b.Context()); err != nil {
						b.Fatal(err)
					}
					flushed = time.Now()
				}
			}
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "records/s")
			if _, err := s.Close(b.Context()); err != nil {
				b.Fatal(err)
			}
		})
	}
}
