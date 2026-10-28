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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/transparency-dev/formats/log"
	fnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/mod/sumdb/note"

	"github.com/Balistid/balistid-blue/internal/relay"
	"github.com/Balistid/balistid-blue/internal/unixsock"
)

// The range stands in for the Pi (ADR 0026, point 5): the pinned litewitness runs in the VM with a key
// made at boot, and the relay reaches it on localhost.
const (
	witnessKeyArg   = "witness-key"
	witnessAgentArg = "witness-agent"
	witnessName     = "balistid-range/witness"
	witnessEnv      = "/etc/balistid-range/witness.env"
	witnessSock     = "/run/balistid-range-witness/agent.sock"
	witnessSubmit   = "http://localhost:7380/add-checkpoint"
	relayState      = "/var/lib/balistid/relay"
	maxWitnessReply = 4 << 10
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
	if err := os.MkdirAll(filepath.Dir(env), 0o755); err != nil { //nolint:gosec // root's /etc, readable as /etc is
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
	lv, wv, err := rangeVerifiers()
	if err != nil {
		return "error: " + err.Error()
	}
	f := client.FileFetcher{Root: ledgerLog}
	want, _, _, err := client.FetchCheckpoint(ctx, f.ReadCheckpoint, lv, ledgerOrigin)
	if err != nil {
		return "error: ledger checkpoint: " + err.Error()
	}
	for deadline := time.Now().Add(waitLimit); ; time.Sleep(time.Second) {
		got, err := cosigned(lv, wv)
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

func rangeVerifiers() (note.Verifier, note.Verifier, error) {
	lv, err := note.NewVerifier(readTrim(filepath.Join(ledgerKeyDir, "ledger-key.pub")))
	if err != nil {
		return nil, nil, fmt.Errorf("ledger verifier key: %w", err)
	}
	wv, err := fnote.NewVerifierForCosignatureV1(readTrim(filepath.Join(ledgerKeyDir, "witness.vkey")))
	if err != nil {
		return nil, nil, fmt.Errorf("witness verifier key: %w", err)
	}
	return lv, wv, nil
}

// cosigned reads the relay's checkpoint; both the ledger's signature and the witness's must verify.
func cosigned(lv, wv note.Verifier) (log.Checkpoint, error) {
	var cp log.Checkpoint
	b, err := os.ReadFile(filepath.Join(relayState, relay.CosignedName))
	if err != nil {
		return cp, fmt.Errorf("cosigned checkpoint: %w", err)
	}
	n, err := note.Open(b, note.VerifierList(lv, wv))
	if err != nil || len(n.Sigs) != 2 {
		return cp, errors.Join(errors.New("cosigned checkpoint does not verify with both keys"), err)
	}
	if _, err := cp.Unmarshal([]byte(n.Text)); err != nil || cp.Origin != ledgerOrigin {
		return cp, errors.Join(errors.New("cosigned checkpoint: other origin or malformed"), err)
	}
	return cp, nil
}

// forkRefused is "yes" when the witness refuses, under the ledger's own key, a checkpoint of its
// cosigned size with another root (422) and one smaller than its cosigned size (400): T12.
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
		status, _, err = addCheckpoint(ctx, s, size, size-1, other[:])
		switch {
		case err != nil:
			return "error: " + err.Error()
		case status != http.StatusBadRequest:
			return fmt.Sprintf("error: rollback to size %d: status %d", size-1, status)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, witnessSubmit, bytes.NewReader(append(fmt.Appendf(nil, "old %d\n\n", old), signed...)))
	if err != nil {
		return 0, nil, fmt.Errorf("request: %w", err)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("witness: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // read-only
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWitnessReply))
	if err != nil {
		return 0, nil, fmt.Errorf("witness reply: %w", err)
	}
	return resp.StatusCode, body, nil
}
