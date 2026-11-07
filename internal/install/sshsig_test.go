package install

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// skKey is a software ed25519 key in sk-ssh-ed25519 form: it signs with any authenticator flags, as an agent
// could make a real token sign without a touch when the key file does not ask for one.
type skKey struct {
	priv ed25519.PrivateKey
	blob []byte
}

func newSKKey(seed byte) skKey { return skKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)) }

func skKeyFromSeed(seed []byte) skKey {
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return skKey{priv: priv, blob: slices.Concat(sshString([]byte(SKKeyType)), sshString(pub), sshString([]byte("ssh:")))}
}

func (k skKey) signers() []byte {
	return []byte(Principal + ` namespaces="` + Namespace + `" ` + SKKeyType + " " + base64.StdEncoding.EncodeToString(k.blob) + "\n")
}

// sign writes an SSHSIG of msg in namespace with flags, armored as ssh-keygen -Y sign writes it.
func (k skKey) sign(msg []byte, namespace string, flags byte) []byte {
	h := sha512.Sum512(msg)
	tbs := slices.Concat([]byte("SSHSIG"), sshString([]byte(namespace)), sshString(nil), sshString([]byte("sha512")), sshString(h[:]))
	app, inner := sha256.Sum256([]byte("ssh:")), sha256.Sum256(tbs)
	counter := binary.BigEndian.AppendUint32(nil, 7)
	sig := ed25519.Sign(k.priv, slices.Concat(app[:], []byte{flags}, counter, inner[:]))
	blob := slices.Concat(sshString([]byte(SKKeyType)), sshString(sig), []byte{flags}, counter)
	raw := slices.Concat([]byte("SSHSIG"), binary.BigEndian.AppendUint32(nil, 1), sshString(k.blob), sshString([]byte(namespace)),
		sshString(nil), sshString([]byte("sha512")), sshString(blob))
	return armor(raw)
}

func armor(raw []byte) []byte {
	b64 := base64.StdEncoding.EncodeToString(raw)
	var b strings.Builder
	b.WriteString(sigBegin + "\n")
	for i := 0; i < len(b64); i += 70 {
		b.WriteString(b64[i:min(i+70, len(b64))] + "\n")
	}
	b.WriteString(sigEnd + "\n")
	return []byte(b.String())
}

// skHost is a fake host whose installed key is an sk key, as DefaultConfig requires, with a release signed by it.
func skHost(t *testing.T, flags byte) *fakeHost {
	t.Helper()
	h := newHost(t)
	k := newSKKey(1)
	h.put(t, "etc/balistid/allowed_signers", k.signers(), 0o644)
	files := runnerFiles(k.signers())
	m := manifestOf(files)
	h.publish(t, files, m, k.sign(m, Namespace, flags))
	return h
}

// ssh-keygen accepts an sk signature whatever its flags; the installer takes one only with a touch and the PIN.
func TestCheckRequiresTheTokensTouchAndPIN(t *testing.T) {
	for _, flags := range []byte{0x00, skPresence, skVerified, 0x02, 0x10} {
		skHost(t, flags).refuses(t, fmt.Sprintf("flags %#x", flags), "", "sk flags")
	}
	for _, flags := range []byte{skPresence | skVerified, 0xff} {
		h := skHost(t, flags)
		if _, err := Check(t.Context(), h.cfg, "runner", h.dir, ""); err != nil {
			t.Errorf("flags %#x: %v", flags, err)
		}
	}
}

// The installer's own check stands even where ssh-keygen says yes to anything.
func TestCheckVerifiesTheSignatureBesideSshKeygen(t *testing.T) {
	stand := filepath.Join(t.TempDir(), "ssh-keygen")
	must(t, os.WriteFile(stand, []byte("#!/bin/sh\nexit 0\n"), 0o700)) //nolint:gosec // a stand-in program
	k := newSKKey(1)
	files := runnerFiles(k.signers())
	m := manifestOf(files)
	other := newSKKey(2)
	for label, sig := range map[string][]byte{
		"another key":       other.sign(m, Namespace, 0x05),
		"another namespace": k.sign(m, "file", 0x05),
		"another message":   k.sign(append(slices.Clone(m), '\n'), Namespace, 0x05),
		"garbage":           []byte("x"),
	} {
		h := newHost(t)
		h.cfg.SSHKeygen = stand
		h.put(t, "etc/balistid/allowed_signers", k.signers(), 0o644)
		h.publish(t, files, m, sig)
		h.refuses(t, label, "", "signature")
	}
}

// Anything but one armored SSHSIG v1 of the allowed key, in the install namespace, is refused.
func TestCheckSSHSIGRefusesAnythingElse(t *testing.T) {
	k := newSKKey(1)
	signer, err := ParseSigners(k.signers())
	must(t, err)
	msg := []byte("MANIFEST\n")
	good := k.sign(msg, Namespace, 0x05)
	must(t, checkSSHSIG(signer, msg, good))
	raw, err := dearmor(good)
	must(t, err)
	for label, sig := range map[string][]byte{
		"two blocks":        append(slices.Clone(good), good...),
		"text before":       append([]byte("x\n"), good...),
		"text after":        append(slices.Clone(good), "x\n"...),
		"crlf":              bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n")),
		"bytes after":       armor(append(slices.Clone(raw), 0)),
		"cut":               armor(raw[:len(raw)-1]),
		"version 2":         armor(bytes.Replace(raw, []byte("SSHSIG\x00\x00\x00\x01"), []byte("SSHSIG\x00\x00\x00\x02"), 1)),
		"another hash name": armor(bytes.Replace(raw, []byte("sha512"), []byte("sha513"), 1)),
		"empty":             nil,
	} {
		if err := checkSSHSIG(signer, msg, sig); err == nil {
			t.Errorf("%s: accepted", label)
		}
	}
	if err := checkSSHSIG(signer, []byte("another MANIFEST\n"), good); err == nil {
		t.Error("a signature of another message: accepted")
	}
}

// Whatever checkSSHSIG accepts for the seed's key and message is the seed's signature: the flags, the counter and
// every other signed byte are bound.
func FuzzCheckSSHSIG(f *testing.F) {
	k := newSKKey(1)
	signer, err := ParseSigners(k.signers())
	if err != nil {
		f.Fatal(err)
	}
	msg := []byte("MANIFEST\n")
	seed := k.sign(msg, Namespace, 0x05)
	want, err := dearmor(seed)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add(k.sign(msg, Namespace, 0x01))
	f.Fuzz(func(t *testing.T, b []byte) {
		if checkSSHSIG(signer, msg, b) != nil {
			return
		}
		if raw, err := dearmor(b); err != nil || !bytes.Equal(raw, want) {
			t.Fatalf("accepted another signature %q", b)
		}
	})
}

// Only the token's key type is ever verified: a plain ed25519 key's valid signature, which carries no flags, is not.
func TestCheckSSHSIGRefusesAPlainKey(t *testing.T) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	pub, _ := priv.Public().(ed25519.PublicKey)
	blob := slices.Concat(sshString([]byte("ssh-ed25519")), sshString(pub))
	msg := []byte("MANIFEST\n")
	h := sha512.Sum512(msg)
	tbs := slices.Concat([]byte("SSHSIG"), sshString([]byte(Namespace)), sshString(nil), sshString([]byte("sha512")), sshString(h[:]))
	sig := slices.Concat(sshString([]byte("ssh-ed25519")), sshString(ed25519.Sign(priv, tbs)))
	raw := slices.Concat([]byte("SSHSIG"), binary.BigEndian.AppendUint32(nil, 1), sshString(blob), sshString([]byte(Namespace)),
		sshString(nil), sshString([]byte("sha512")), sshString(sig))
	if err := checkSSHSIG(Signer{blob: blob}, msg, armor(raw)); err == nil || !strings.Contains(err.Error(), "another key type") {
		t.Fatalf("a plain ed25519 signature: %v", err)
	}
}
