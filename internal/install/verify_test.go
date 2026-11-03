package install

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The host's configuration requires the token's key type and names its tools by absolute path (R2, ADR 0058).
func TestDefaultConfigRequiresTheTokensKey(t *testing.T) {
	got := DefaultConfig()
	if got.Root != "/" || got.UID != 0 || got.GID != 0 || got.KeyType != "sk-ssh-ed25519@openssh.com" ||
		got.SSHKeygen != "/usr/bin/ssh-keygen" || got.VerifyTimeout != 10*time.Second {
		t.Fatalf("%+v", got)
	}
	if got.Run == nil || got.Show == nil || got.LookupUser == nil || got.LookupGroup == nil || got.Log == nil {
		t.Fatal("a host command is missing")
	}
}

func TestCheckAcceptsTheSignedRelease(t *testing.T) {
	h := newHost(t)
	files := h.release(t)
	before := snapshot(t, h.cfg.Root)
	r, err := Check(t.Context(), h.cfg, h.dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Manifest.Commit != testCommit || len(r.Files) != len(files) || !bytes.Equal(r.Files["tmpfiles.conf"], files["tmpfiles.conf"]) {
		t.Fatalf("%+v", r.Manifest)
	}
	if r.Signer.Fingerprint() != h.key.fingerprint(t) {
		t.Fatalf("signer %s", r.Signer.Fingerprint())
	}
	unchanged(t, "accepted", h.cfg.Root, before)
}

// refuses fails the test unless Check refuses what the release directory holds now, without blocking, and leaves
// the root as it was; its reason contains want, so a test refuses for the reason it tests.
func (h *fakeHost) refuses(t *testing.T, label, fingerprint, want string) {
	t.Helper()
	before := snapshot(t, h.cfg.Root)
	done := make(chan error, 1)
	go func() { _, err := Check(t.Context(), h.cfg, h.dir, fingerprint); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, not a refusal for %q", label, err, want)
		}
	case <-time.After(30 * time.Second):
		t.Fatalf("%s: Check blocked", label)
	}
	unchanged(t, label, h.cfg.Root, before)
}

// The four refusals ADR 0053 names: unsigned, altered after signing, another namespace, another signer.
func TestCheckRefusesWhatADR0053Names(t *testing.T) {
	h := newHost(t)
	files := runnerFiles(h.key.signers)
	m := manifestOf(files)
	good := h.key.sign(t, m, Namespace)
	altered := bytes.Replace(m, []byte("component runner"), []byte("component runnes"), 1)
	other := newKey(t)
	const bad = "the signature does not verify"
	for label, c := range map[string]struct {
		manifest, sig []byte
		why           string
	}{
		"unsigned":        {m, nil, sigName + ": missing"},
		"empty signature": {m, []byte{}, bad},
		"altered":         {altered, good, bad},
		"other namespace": {m, h.key.sign(t, m, "file"), bad},
		"other signer":    {m, other.sign(t, m, Namespace), bad},
		"a garbled sig":   {m, bytes.Replace(good, []byte("A"), []byte("B"), 3), bad},
	} {
		_ = os.Remove(filepath.Join(h.dir, sigName))
		h.publish(t, files, c.manifest, c.sig)
		h.refuses(t, label, "", c.why)
	}
}

// A good signature binds only the manifest: every file must be exactly the manifest's.
func TestCheckRefusesFilesTheManifestDoesNotMatch(t *testing.T) {
	h := newHost(t)
	sign := func(m []byte) []byte { return h.key.sign(t, m, Namespace) }
	files := runnerFiles(h.key.signers)
	m := manifestOf(files)
	changed := runnerFiles(h.key.signers)
	changed["balistid-runner"] = []byte("another binary\n")
	extra := runnerFiles(h.key.signers)
	extra["extra.conf"] = []byte("x")
	missing := runnerFiles(h.key.signers)
	delete(missing, "tmpfiles.conf")
	v2 := bytes.Replace(manifestOf(files), []byte("manifest 1"), []byte("manifest 2"), 1)
	for label, c := range map[string]struct {
		files    map[string][]byte
		manifest []byte
		why      string
	}{
		"sha256 mismatch":      {changed, m, "balistid-runner does not match its sha256"},
		"a file not listed":    {extra, m, "files are not the manifest's"},
		"a listed file absent": {missing, m, "files are not the manifest's"},
		"version 2":            {files, v2, "not version 1"},
	} {
		h.publish(t, c.files, c.manifest, sign(c.manifest))
		h.refuses(t, label, "", c.why)
	}
}

// The inputs come from a directory agents can write: only regular files with one link, within their caps.
func TestCheckRefusesInputsThatAreNotPlainFiles(t *testing.T) {
	for _, name := range []string{bundleName, sigName} {
		for label, swap := range map[string]func(p string) error{
			"a symlink": func(p string) error {
				if err := os.Rename(p, p+".real"); err != nil {
					return err
				}
				return os.Symlink(p+".real", p)
			},
			"a fifo": func(p string) error {
				if err := os.Remove(p); err != nil {
					return err
				}
				return syscall.Mkfifo(p, 0o600)
			},
			"a hard link": func(p string) error { return os.Link(p, p+".other") },
			"over the cap": func(p string) error {
				return os.Truncate(p, map[string]int64{bundleName: MaxBundleBytes, sigName: maxSigBytes}[name]+1)
			},
			"missing": os.Remove,
		} {
			h := newHost(t)
			h.release(t)
			if err := swap(filepath.Join(h.dir, name)); err != nil {
				t.Fatal(err)
			}
			h.refuses(t, name+": "+label, "", name)
		}
	}
}

// The installed key is root's, alone and exact: anything an agent or another option could widen is refused.
func TestCheckRefusesAnAllowedSignersRootDidNotLeave(t *testing.T) {
	file := "etc/balistid/allowed_signers"
	for label, spoil := range map[string]func(h *fakeHost){
		"a symlink": func(h *fakeHost) {
			real := filepath.Join(h.cfg.Root, "etc/balistid/real")
			must(t, os.Rename(filepath.Join(h.cfg.Root, file), real))
			must(t, os.Symlink(real, filepath.Join(h.cfg.Root, file)))
		},
		"the directory a symlink": func(h *fakeHost) {
			must(t, os.Rename(filepath.Join(h.cfg.Root, "etc/balistid"), filepath.Join(h.cfg.Root, "etc/real")))
			must(t, os.Symlink("real", filepath.Join(h.cfg.Root, "etc/balistid")))
		},
		"another owner":      func(h *fakeHost) { h.cfg.UID++ },
		"another group":      func(h *fakeHost) { h.cfg.GID++ },
		"group writable":     func(h *fakeHost) { must(t, os.Chmod(filepath.Join(h.cfg.Root, file), 0o664)) },           //nolint:gosec // a mode under test
		"other writable":     func(h *fakeHost) { must(t, os.Chmod(filepath.Join(h.cfg.Root, file), 0o646)) },           //nolint:gosec // a mode under test
		"directory writable": func(h *fakeHost) { must(t, os.Chmod(filepath.Join(h.cfg.Root, "etc/balistid"), 0o775)) }, //nolint:gosec // a mode under test
		"etc writable":       func(h *fakeHost) { must(t, os.Chmod(filepath.Join(h.cfg.Root, "etc"), 0o777)) },          //nolint:gosec // a mode under test
		"directory setgid":   func(h *fakeHost) { must(t, os.Chmod(filepath.Join(h.cfg.Root, "etc/balistid"), 0o755|fs.ModeSetgid)) },
		"a hard link": func(h *fakeHost) {
			must(t, os.Link(filepath.Join(h.cfg.Root, file), filepath.Join(h.cfg.Root, "etc/x")))
		},
		"missing":          func(h *fakeHost) { must(t, os.Remove(filepath.Join(h.cfg.Root, file))) },
		"two lines":        func(h *fakeHost) { h.put(t, file, append(h.key.signers, newKey(t).signers...), 0o644) },
		"a wildcard":       func(h *fakeHost) { h.replace(t, file, Principal, "*") },
		"cert-authority":   func(h *fakeHost) { h.replace(t, file, "namespaces=", "cert-authority,namespaces=") },
		"other namespaces": func(h *fakeHost) { h.replace(t, file, Namespace, "file") },
		"a software key":   func(h *fakeHost) { h.cfg.KeyType = SKKeyType },
		"another key":      func(h *fakeHost) { h.put(t, file, newKey(t).signers, 0o644) },
		"not a key":        func(h *fakeHost) { h.put(t, file, []byte("garbage\n"), 0o644) },
		"empty":            func(h *fakeHost) { h.put(t, file, nil, 0o644) },
	} {
		h := newHost(t)
		h.release(t)
		spoil(h)
		h.refuses(t, label, "", "")
	}
}

func (h *fakeHost) replace(t *testing.T, name, old, new string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.cfg.Root, name)) //nolint:gosec // test temp dir
	if err != nil {
		t.Fatal(err)
	}
	h.put(t, name, bytes.Replace(b, []byte(old), []byte(new), 1), 0o644)
}

// A bundle signed by the installed key but carrying another allowed_signers would swap the key at install.
func TestCheckRefusesABundleCarryingAnotherKey(t *testing.T) {
	h := newHost(t)
	files := runnerFiles(newKey(t).signers)
	m := manifestOf(files)
	h.publish(t, files, m, h.key.sign(t, m, Namespace))
	h.refuses(t, "another allowed_signers in the bundle", "", "not the installed one")
	delete(files, "allowed_signers")
	m = manifestOf(files)
	h.publish(t, files, m, h.key.sign(t, m, Namespace))
	h.refuses(t, "no allowed_signers in the bundle", "", "not the installed one")
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ssh-keygen failing, hanging or missing is a refusal, never a pass (R6).
func TestCheckRefusesWhenSshKeygenDoesNotAnswer(t *testing.T) {
	stand := t.TempDir()
	for name, body := range map[string]string{"fails": "exit 1", "hangs": "exec sleep 60", "says good": "echo Good; exit 3"} {
		must(t, os.WriteFile(filepath.Join(stand, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700)) //nolint:gosec // a stand-in program
	}
	for _, name := range []string{"fails", "hangs", "says good", "missing"} {
		h := newHost(t)
		h.release(t)
		h.cfg.SSHKeygen, h.cfg.VerifyTimeout = filepath.Join(stand, name), 500*time.Millisecond
		start := time.Now()
		h.refuses(t, "ssh-keygen "+name, "", "the signature does not verify")
		if time.Since(start) > 10*time.Second {
			t.Errorf("%s: took %v", name, time.Since(start))
		}
	}
}

// First install: no key installed, and the bundle's key has the fingerprint root typed; nothing else passes.
func TestCheckFirstInstallTrustsOnlyTheTypedFingerprint(t *testing.T) {
	h := newHost(t)
	h.release(t)
	fp := h.key.fingerprint(t)
	if _, err := Check(t.Context(), h.cfg, h.dir, fp); err != nil {
		t.Fatalf("the same key installed: %v", err)
	}
	h.refuses(t, "another fingerprint, the key installed", newKey(t).fingerprint(t), "installed key does not have")
	must(t, os.Remove(filepath.Join(h.cfg.Root, "etc/balistid/allowed_signers")))
	if _, err := Check(t.Context(), h.cfg, h.dir, fp); err != nil {
		t.Fatalf("first install: %v", err)
	}
	h.refuses(t, "no key and no fingerprint", "", "allowed_signers")
	h.refuses(t, "another fingerprint", newKey(t).fingerprint(t), "typed fingerprint")
	h.refuses(t, "not a fingerprint", strings.TrimPrefix(fp, "SHA256:"), "typed fingerprint")
	// The attacker's own key and signature, with the fingerprint root typed.
	other := newKey(t)
	files := runnerFiles(other.signers)
	m := manifestOf(files)
	h.publish(t, files, m, other.sign(t, m, Namespace))
	h.refuses(t, "another bundle's own key", fp, "typed fingerprint")
}
