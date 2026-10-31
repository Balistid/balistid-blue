package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/cosign"
	"github.com/Balistid/balistid-blue/internal/entry"
	"github.com/Balistid/balistid-blue/internal/store"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

// The range stands in for the Pi (ADR 0026, point 5): the pinned litewitness runs in the Pi's namespace with
// a key made at boot, and the relay reaches it through the tunnel (ADR 0032).
const (
	witnessKeyArg     = "witness-key"
	witnessAgentArg   = "witness-agent"
	witnessPostArg    = "witness-post"
	witnessName       = "balistid-range/witness"
	witnessEnv        = "/etc/balistid-range/witness.env"
	witnessSock       = "/run/balistid-range-witness/agent.sock"
	witnessSubmit     = "http://" + piTunnel + ":" + witnessPort + "/add-checkpoint"
	relayState        = "/var/lib/balistid/relay"
	maxWitnessReply   = 4 << 10
	maxWitnessRequest = 64 << 10
	// cosignWait covers a seal's way to a cosign time: the next 5 s checkpoint, the relay's second, the
	// witness, the ledger's second and the collector's tick, with room for a restart.
	cosignWait = 60 * time.Second
)

// witnessKey writes the witness's key into dir after the ledger's (range unit balistid-range-witness-key):
// the seed as root's 0600 file the agent loads as a credential, the cosignature/v1 verifier key the
// relay trusts, and for litewitness and witnessctl its SSH fingerprint and the ledger's verifier key.
func witnessKey(dir, env string) error {
	ledgerVKey := readTrim(filepath.Join(dir, "ledger-key.pub"))
	if _, err := note.NewVerifier(ledgerVKey); err != nil {
		return fmt.Errorf("witness key: ledger verifier key: %w", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("witness key: %w", err)
	}
	vkey, err := note.NewEd25519VerifierKey(witnessName, pub)
	if err != nil {
		return fmt.Errorf("witness key: %w", err)
	}
	if vkey, err = fnote.VKeyToCosignatureV1(vkey); err != nil {
		return fmt.Errorf("witness key: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return fmt.Errorf("witness key: %w", err)
	}
	if err := mkdirOpen(filepath.Dir(env)); err != nil {
		return fmt.Errorf("witness key: %w", err)
	}
	for _, f := range []struct {
		path, body string
		mode       os.FileMode
	}{
		{filepath.Join(dir, "witness-key"), base64.StdEncoding.EncodeToString(priv.Seed()), 0o600},
		{filepath.Join(dir, "witness.vkey"), vkey, 0o644},
		{env, "WITNESS_KEY=" + ssh.FingerprintSHA256(sshPub) + "\nLEDGER_VKEY=" + ledgerVKey, 0o644},
	} {
		if err := writeNew(f.path, f.body+"\n", f.mode); err != nil {
			return fmt.Errorf("witness key: %w", err)
		}
	}
	return nil
}

// mkdirOpen makes dir 0755 whatever the umask: MkdirAll under the key units' UMask=0077 would leave it
// 0700, and the relay's uid could not reach the public keys in it.
func mkdirOpen(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // root's /etc, readable as /etc is
		return err //nolint:wrapcheck // the caller names the step
	}
	return os.Chmod(dir, 0o755) //nolint:gosec,wrapcheck // as above; the caller names the step
}

// writeNew creates path, which must not exist, with exactly mode: the key units run under UMask=0077,
// which would leave a public key unreadable to the relay, so the mode is set on the open file.
func writeNew(path, body string, mode os.FileMode) error {
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // fixed names in root's directories
	if err != nil {
		return err //nolint:wrapcheck // the caller names the step
	}
	_, err = w.WriteString(body)
	return errors.Join(err, w.Chmod(mode), w.Sync(), w.Close())
}

func witnessKeyMain(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: " + witnessKeyArg + " (no arguments): " + strings.Join(args, " "))
	}
	return witnessKey(ledgerKeyDir, witnessEnv)
}

// witnessAgentMain serves the witness key to litewitness, which signs only through ssh-agent, on a
// socket of the unit's runtime directory; the seed comes as the unit's credential.
func witnessAgentMain(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: " + witnessAgentArg + " (no arguments): " + strings.Join(args, " "))
	}
	seed, err := base64.StdEncoding.DecodeString(readTrim(filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "witness-key")))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("witness agent: no witness key credential")
	}
	keys := agent.NewKeyring()
	if err := keys.Add(agent.AddedKey{PrivateKey: ed25519.NewKeyFromSeed(seed)}); err != nil {
		return fmt.Errorf("witness agent: %w", err)
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", witnessSock)
	if err != nil {
		return fmt.Errorf("witness agent: %w", err)
	}
	defer ln.Close() //nolint:errcheck // the process ends
	if err := unixsock.Notify("READY=1"); err != nil {
		return fmt.Errorf("witness agent: %w", err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("witness agent: %w", err)
		}
		// litewitness holds one connection for its life: no goroutine per connection is needed
		if err := agent.ServeAgent(keys, c); !errors.Is(err, io.EOF) {
			fmt.Fprintln(os.Stderr, "witness agent:", err)
		}
		_ = c.Close()
	}
}

// ledgerCosigned is "yes" once the relay holds a checkpoint the witness cosigned that covers the
// ledger's checkpoint as this fact starts: both keys verify it and its size is at least that one's.
func ledgerCosigned(ctx context.Context) string {
	keys, err := rangeKeys()
	if err != nil {
		return "error: " + err.Error()
	}
	f := client.FileFetcher{Root: ledgerLog}
	want, _, _, err := client.FetchCheckpoint(ctx, f.ReadCheckpoint, keys.Log, ledgerOrigin)
	if err != nil {
		return "error: ledger checkpoint: " + err.Error()
	}
	for deadline := time.Now().Add(waitLimit); ; time.Sleep(time.Second) {
		got, err := cosign.Read(filepath.Join(relayState, cosign.Name), keys)
		if err == nil && got.Size >= want.Size {
			return "yes"
		}
		if time.Now().After(deadline) {
			if err != nil {
				return "error: " + err.Error()
			}
			return fmt.Sprintf("error: cosigned size %d, the ledger had %d", got.Size, want.Size)
		}
	}
}

func rangeKeys() (cosign.Keys, error) {
	lv, err := note.NewVerifier(readTrim(filepath.Join(ledgerKeyDir, "ledger-key.pub")))
	if err != nil {
		return cosign.Keys{}, fmt.Errorf("ledger verifier key: %w", err)
	}
	wv, err := fnote.NewVerifierForCosignatureV1(readTrim(filepath.Join(ledgerKeyDir, "witness.vkey")))
	if err != nil {
		return cosign.Keys{}, fmt.Errorf("witness verifier key: %w", err)
	}
	return cosign.Keys{Origin: ledgerOrigin, Log: lv, Witness: wv}, nil
}

// forkRefused is "yes" when the witness refuses, under the ledger's own key, a checkpoint of its
// cosigned size with another root (422) and a rollback to a smaller size (409 naming its own): T12.
func forkRefused(ctx context.Context) string {
	s, err := note.NewSigner(readTrim(filepath.Join(ledgerKeyDir, "ledger-key")))
	if err != nil {
		return "error: ledger signing key"
	}
	other := sha256.Sum256([]byte("fork"))
	size, err := witnessSize(ctx, s, other[:])
	if err != nil {
		return "error: " + err.Error()
	}
	for range 5 {
		status, body, err := addCheckpoint(ctx, s, size, size, other[:])
		if err != nil {
			return "error: " + err.Error()
		}
		if status == http.StatusConflict { // the relay moved the witness on meanwhile
			if size, err = parseSize(body); err != nil {
				return "error: " + err.Error()
			}
			continue
		}
		if status != http.StatusUnprocessableEntity {
			return fmt.Sprintf("error: fork at size %d: status %d", size, status)
		}
		// a rollback from the witness's own record: only a witness that kept size answers 409 with it;
		// size 1 would probe the empty tree, whose root the witness checks on its own
		if size < 2 {
			return fmt.Sprintf("error: witness size %d too small for a rollback probe", size)
		}
		status, body, err = addCheckpoint(ctx, s, size-1, size-1, other[:])
		if err != nil {
			return "error: " + err.Error()
		}
		// the relay may have moved the witness on meanwhile: its record is then larger, never smaller
		if got, perr := parseSize(body); status != http.StatusConflict || perr != nil || got < size {
			return fmt.Sprintf("error: rollback to size %d: status %d, size %q", size-1, status, body)
		}
		return "yes"
	}
	return "error: the witness's size kept moving"
}

// witnessSize asks the witness for the size it last cosigned: an old size of 0 draws a 409 with it.
func witnessSize(ctx context.Context, s note.Signer, hash []byte) (uint64, error) {
	status, body, err := addCheckpoint(ctx, s, 0, 1, hash)
	if err != nil {
		return 0, err
	}
	if status != http.StatusConflict {
		return 0, fmt.Errorf("witness size: status %d", status)
	}
	return parseSize(body)
}

func parseSize(body []byte) (uint64, error) {
	n, err := strconv.ParseUint(string(bytes.TrimSuffix(body, []byte("\n"))), 10, 64)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("witness size %q", body)
	}
	return n, nil
}

// addCheckpoint posts a checkpoint of size and hash signed with s, with an empty proof from old.
func addCheckpoint(ctx context.Context, s note.Signer, old, size uint64, hash []byte) (int, []byte, error) {
	text := fmt.Sprintf("%s\n%d\n%s\n", ledgerOrigin, size, base64.StdEncoding.EncodeToString(hash))
	signed, err := note.Sign(&note.Note{Text: text}, s)
	if err != nil {
		return 0, nil, fmt.Errorf("sign: %w", err)
	}
	cred, err := credential(relayUser)
	if err != nil {
		return 0, nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return 0, nil, fmt.Errorf("witness post: %w", err)
	}
	// Only the relay's uid reaches the Pi (ADR 0032): the child posts what root signed, as that uid.
	child := exec.CommandContext(ctx, self, witnessPostArg) //nolint:gosec // our own binary, fixed argv
	child.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	child.Stdin = bytes.NewReader(append(fmt.Appendf(nil, "old %d\n\n", old), signed...))
	child.Stderr = os.Stderr
	out, err := child.Output()
	if err != nil {
		return 0, nil, fmt.Errorf("witness post: %w", err)
	}
	line, body, _ := bytes.Cut(out, []byte("\n"))
	status, err := strconv.Atoi(string(line))
	if err != nil {
		return 0, nil, fmt.Errorf("witness post said %q", line)
	}
	return status, body, nil
}

// witnessPostMain is the relay-uid child of addCheckpoint: it posts its standard input to the witness and
// prints the status code, a newline and the capped reply.
func witnessPostMain(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: " + witnessPostArg + " (no arguments): " + strings.Join(args, " "))
	}
	req, err := io.ReadAll(io.LimitReader(os.Stdin, maxWitnessRequest))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, witnessSubmit, bytes.NewReader(req))
	if err != nil {
		return fmt.Errorf("request: %w", err)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return fmt.Errorf("witness: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWitnessReply))
	if err != nil {
		return fmt.Errorf("witness reply: %w", err)
	}
	_, err = fmt.Printf("%d\n%s", resp.StatusCode, body)
	return err //nolint:wrapcheck // the child's last word
}

// errNoAnnouncement is a log without an announcement of the kind asked for.
var errNoAnnouncement = errors.New("no announcement")

// announced is "yes" once systemctl verb unit ran the ledger's client to success, under the unit's
// sandbox, and an announcement of kind after index after (-1: any) in the ledger's log is proven included in
// a checkpoint the witness cosigned (ADR 0030): the client waited for that cosignature itself, so the check
// finds it at once. after keeps a second announcement from proving itself with the first.
func announced(ctx context.Context, verb, unit string, kind entry.Announcement, after int64) string {
	if verb == "stop" && strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "is-active", unit)) != "active" {
		return "error: " + unit + " was not active, so its stop announces nothing"
	}
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", verb, unit).Run(); err != nil { //nolint:gosec // two fixed verbs and units of the self-test
		return "error: " + verb + " " + unit + ": " + err.Error()
	}
	if result := strings.TrimSpace(output(ctx, "/usr/bin/systemctl", "show", "-P", "Result", unit)); result != "success" {
		return "error: " + unit + " ended with " + result
	}
	keys, err := rangeKeys()
	if err != nil {
		return "error: " + err.Error()
	}
	var last string
	for deadline := time.Now().Add(cosignWait); ; time.Sleep(time.Second) {
		cp, err := cosign.Read(filepath.Join(relayState, cosign.Name), keys)
		var at uint64
		if err == nil {
			at, err = lastAnnouncement(ctx, ledgerLog, keys.Log, kind)
		}
		if err == nil && int64(at) <= after {
			err = fmt.Errorf("the last announcement is at %d, not after %d", at, after)
		}
		if err == nil && at < cp.Size { // the bytes on disk count only as far as the cosigned root vouches for them
			var e entry.Entry
			if e, err = cosign.ProvenEntry(ctx, ledgerLog, cp, at); err == nil && e.Body != (entry.Announce{Kind: kind}) {
				err = fmt.Errorf("entry %d is %+v", at, e.Body)
			}
		}
		switch {
		case err != nil:
			last = "error: " + err.Error()
		case at < cp.Size:
			return "yes"
		default:
			last = fmt.Sprintf("no: the announcement at %d, cosigned size %d", at, cp.Size)
		}
		if time.Now().After(deadline) {
			return last
		}
	}
}

// lastAnnouncement is the index of the last announcement of kind in the log at root, under its signed
// checkpoint.
func lastAnnouncement(ctx context.Context, root string, v note.Verifier, kind entry.Announcement) (uint64, error) {
	f := client.FileFetcher{Root: root}
	cp, _, _, err := client.FetchCheckpoint(ctx, f.ReadCheckpoint, v, ledgerOrigin)
	if err != nil {
		return 0, fmt.Errorf("checkpoint: %w", err)
	}
	found, at := false, uint64(0)
	for idx := uint64(0); idx*layout.EntryBundleWidth < cp.Size; idx++ {
		b, err := client.GetEntryBundle(ctx, f.ReadEntryBundle, idx, cp.Size)
		if err != nil {
			return 0, fmt.Errorf("bundle %d: %w", idx, err)
		}
		for i, raw := range b.Entries {
			e, err := entry.Decode(raw)
			if err != nil {
				return 0, fmt.Errorf("bundle %d: %w", idx, err)
			}
			if a, ok := e.Body.(entry.Announce); ok && a.Kind == kind {
				found, at = true, idx*layout.EntryBundleWidth+uint64(i)
			}
		}
	}
	if !found {
		return 0, fmt.Errorf("%w of kind %d in %d entries", errNoAnnouncement, kind, cp.Size)
	}
	return at, nil
}

// shardCosigned is "yes" once a shard the collector sealed carries a witness time in its index: the relay's
// cosigned checkpoint reached the ledger and, as frame 5, the collector, under the units' sandbox (ADR 0029).
// A restart of the collector seals its shard (Close) without a range-only shard size, which would change the
// trials; the seal then goes to the ledger as any resent one does.
func shardCosigned(ctx context.Context) string {
	if err := exec.CommandContext(ctx, "/usr/bin/systemctl", "restart", "balistid-collector.service").Run(); err != nil {
		return "error: restart the collector: " + err.Error()
	}
	var last string
	for deadline := time.Now().Add(cosignWait); ; time.Sleep(time.Second) {
		seals, err := store.ReadSeals(ctx, storeDir)
		switch {
		case err != nil && !errors.Is(err, store.ErrUnindexed): // the open shard is not indexed yet
			last = "error: " + err.Error()
		case slices.ContainsFunc(seals, func(l store.Seal) bool { return l.Cosigned != 0 }):
			return "yes"
		default:
			last = fmt.Sprintf("no: %d seals, none cosigned", len(seals))
		}
		if time.Now().After(deadline) {
			return last
		}
	}
}
