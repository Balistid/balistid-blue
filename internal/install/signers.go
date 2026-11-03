package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"regexp"
)

const (
	// Principal and Namespace are the identity and namespace every install signature carries (ADR 0053).
	Principal = "maintainer@balistid.dev"
	Namespace = "install@balistid.dev"
	// SKKeyType is the only key type DefaultConfig accepts, a FIDO2 key's (R2, ADR 0053 point 1). The type alone
	// proves no token (nothing is attested); each signature's touch and PIN flags are checked (sshsig.go).
	SKKeyType       = "sk-ssh-ed25519@openssh.com"
	maxSignersBytes = 1024
)

var keyText = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

// Signer is the one line of allowed_signers (ADR 0058, point 3) and the key it names.
type Signer struct {
	Line []byte // the whole file, exactly as ssh-keygen gets it
	blob []byte
}

// ParseSigners reads allowed_signers strictly: one line of exactly four fields, the principal, the one option
// `namespaces="install@balistid.dev"`, keyType and its key. A wildcard or list of principals, cert-authority,
// any other option, a comment, another key type or a second line is refused: ssh-keygen would honour them.
func ParseSigners(b []byte, keyType string) (Signer, error) {
	if len(b) > maxSignersBytes || bytes.Count(b, []byte("\n")) != 1 || !bytes.HasSuffix(b, []byte("\n")) {
		return Signer{}, errors.New("allowed_signers: not one capped line")
	}
	f := bytes.Split(b[:len(b)-1], []byte(" "))
	if len(f) != 4 || string(f[0]) != Principal || string(f[1]) != `namespaces="`+Namespace+`"` || string(f[2]) != keyType {
		return Signer{}, errors.New("allowed_signers: not '" + Principal + ` namespaces="` + Namespace + `" ` + keyType + " <key>'")
	}
	// The decoder skips \r and \n inside its input, so the alphabet is checked first.
	blob, err := base64.StdEncoding.Strict().DecodeString(string(f[3]))
	if !keyText.Match(f[3]) || err != nil {
		return Signer{}, errors.New("allowed_signers: the key is not base64")
	}
	if len(blob) < 4 || uint64(binary.BigEndian.Uint32(blob)) != uint64(len(keyType)) || string(blob[4:min(len(blob), 4+len(keyType))]) != keyType {
		return Signer{}, errors.New("allowed_signers: the key's own type is not " + keyType)
	}
	return Signer{Line: b, blob: blob}, nil
}

// Fingerprint is the key's fingerprint as `ssh-keygen -l` prints it: SHA256 of the key, base64 without padding.
func (s Signer) Fingerprint() string {
	sum := sha256.Sum256(s.blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
