package install

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
)

const (
	sigBegin, sigEnd = "-----BEGIN SSH SIGNATURE-----", "-----END SSH SIGNATURE-----"
	// skPresence and skVerified are the authenticator flags of an sk signature: a touch and the PIN (ADR 0053 point 1).
	skPresence, skVerified = 0x01, 0x04
)

// checkSSHSIG verifies the armored SSHSIG over msg with signer's key itself, after ssh-keygen accepted it: ssh-keygen
// 10.6 does not check an sk signature's flags, so one made without a touch or the PIN passes it. An sk signature must
// carry both flags; they are part of the signed bytes, so nobody can add them after signing.
func checkSSHSIG(signer Signer, msg, armored []byte) error {
	raw, err := dearmor(armored)
	if err != nil {
		return err
	}
	r := sshReader{b: raw}
	magic, version := r.next(6), r.uint32()
	pub, ns, reserved, hashAlg, sigBlob := r.str(), r.str(), r.str(), r.str(), r.str()
	switch {
	case !r.done() || string(magic) != "SSHSIG" || version != 1:
		return errors.New("signature: not an SSHSIG v1")
	case !bytes.Equal(pub, signer.blob):
		return errors.New("signature: by another key than the allowed one")
	case string(ns) != Namespace:
		return errors.New("signature: of another namespace")
	}
	var digest []byte
	switch string(hashAlg) {
	case "sha512":
		h := sha512.Sum512(msg)
		digest = h[:]
	case "sha256":
		h := sha256.Sum256(msg)
		digest = h[:]
	default:
		return errors.New("signature: of another hash")
	}
	signed := slices.Concat([]byte("SSHSIG"), sshString(ns), sshString(reserved), sshString(hashAlg), sshString(digest))
	key, s := sshReader{b: pub}, sshReader{b: sigBlob}
	keyType, point := key.str(), key.str()
	sigType, sig := s.str(), s.str()
	if len(point) != ed25519.PublicKeySize || !bytes.Equal(sigType, keyType) {
		return errors.New("signature: not an ed25519 signature of the allowed key's type")
	}
	if string(keyType) != SKKeyType {
		return errors.New("signature: of another key type")
	}
	app, flags, counter := key.str(), s.next(1), s.next(4)
	if s.bad || flags[0]&(skPresence|skVerified) != skPresence|skVerified {
		return errors.New("signature: made without the token's touch and PIN (sk flags)")
	}
	appHash, signedHash := sha256.Sum256(app), sha256.Sum256(signed)
	signed = slices.Concat(appHash[:], flags, counter, signedHash[:])
	if !key.done() || !s.done() || !ed25519.Verify(point, signed, sig) {
		return errors.New("signature: does not verify")
	}
	return nil
}

// dearmor reads exactly one armored block as ssh-keygen -Y sign writes it, and nothing around it.
func dearmor(b []byte) ([]byte, error) {
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) < 3 || lines[0] != sigBegin || lines[len(lines)-1] != sigEnd {
		return nil, errors.New("signature: not one armored SSH signature")
	}
	body := strings.Join(lines[1:len(lines)-1], "")
	raw, err := base64.StdEncoding.Strict().DecodeString(body)
	if !keyText.MatchString(body) || err != nil {
		return nil, errors.New("signature: not base64")
	}
	return raw, nil
}

// sshReader reads the SSH wire format strictly: once a read runs past the end, it and every later one fail.
type sshReader struct {
	b   []byte
	bad bool
}

func (r *sshReader) next(n int) []byte {
	if r.bad || n > len(r.b) {
		r.bad = true
		return make([]byte, n)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *sshReader) uint32() uint32 { return binary.BigEndian.Uint32(r.next(4)) }

func (r *sshReader) str() []byte {
	n := r.uint32()
	if r.bad || uint64(n) > uint64(len(r.b)) {
		r.bad = true
		return nil
	}
	return r.next(int(n))
}

func (r *sshReader) done() bool { return !r.bad && len(r.b) == 0 }

// sshString is b as an SSH string; every input here is capped far below 4 GiB.
func sshString(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...) //nolint:gosec // capped lengths
}
