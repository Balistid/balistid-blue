package install

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

// manifestText formats m as release.py writes MANIFEST v1.
func manifestText(m Manifest) []byte {
	var b strings.Builder
	b.WriteString("balistid-manifest 1\ncomponent " + m.Component + "\ncommit " + m.Commit + "\n")
	for _, f := range m.Files {
		b.WriteString(hex.EncodeToString(f.SHA256[:]) + "  " + f.Name + "\n")
	}
	return []byte(b.String())
}

func TestParseManifestReadsV1(t *testing.T) {
	want := Manifest{Component: "runner", Commit: testCommit, Files: []File{
		{"allowed_signers", sha256.Sum256([]byte("a"))}, {"balistid-runner", sha256.Sum256([]byte("b"))},
		{"tmpfiles.conf", sha256.Sum256([]byte("c"))}}}
	got, err := ParseManifest(manifestText(want))
	if err != nil || got.Component != want.Component || got.Commit != want.Commit || len(got.Files) != 3 {
		t.Fatalf("%+v, %v", got, err)
	}
	for i := range want.Files {
		if got.Files[i] != want.Files[i] {
			t.Fatalf("file %d: %+v", i, got.Files[i])
		}
	}
}

// Anything but the exact form, another version included, is refused whole.
func TestParseManifestRefusesAnythingElse(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	good := "balistid-manifest 1\ncomponent runner\ncommit " + testCommit + "\n" + sum + "  a.conf\n" + sum + "  b.conf\n"
	for name, text := range map[string]string{
		"version 2":        strings.Replace(good, "manifest 1", "manifest 2", 1),
		"no version":       strings.Replace(good, "balistid-manifest 1\n", "", 1),
		"no component":     strings.Replace(good, "component runner\n", "", 1),
		"upper component":  strings.Replace(good, "runner", "Runner", 1),
		"short commit":     strings.Replace(good, testCommit, testCommit[:39], 1),
		"upper commit":     strings.Replace(good, testCommit, strings.ToUpper(testCommit), 1),
		"no file":          "balistid-manifest 1\ncomponent runner\ncommit " + testCommit + "\n",
		"out of order":     strings.Replace(strings.Replace(good, "a.conf", "x.conf", 1), "b.conf", "a.conf", 1),
		"a name twice":     strings.Replace(good, "b.conf", "a.conf", 1),
		"a path":           strings.Replace(good, "b.conf", "etc/b.conf", 1),
		"dot dot":          strings.Replace(good, "b.conf", "../b.conf", 1),
		"a leading dot":    strings.Replace(good, "b.conf", ".b.conf", 1),
		"one space":        strings.Replace(good, "  b.conf", " b.conf", 1),
		"a tab":            strings.Replace(good, "  b.conf", "\tb.conf", 1),
		"upper sha256":     strings.Replace(good, sum+"  b", strings.ToUpper(sum)+"  b", 1),
		"short sha256":     strings.Replace(good, sum+"  b", sum[:62]+"  b", 1),
		"crlf":             strings.ReplaceAll(good, "\n", "\r\n"),
		"no last newline":  strings.TrimSuffix(good, "\n"),
		"a blank line":     good + "\n",
		"a trailing space": strings.Replace(good, "b.conf", "b.conf ", 1),
		"nothing":          "",
		"over the cap":     good + strings.Repeat(sum+"  z.conf\n", MaxManifestBytes/72+1),
	} {
		if m, err := ParseManifest([]byte(text)); err == nil {
			t.Errorf("%s: read %+v", name, m)
		}
	}
}

// Whatever ParseManifest accepts prints back as the same bytes: one reading only.
func FuzzParseManifest(f *testing.F) {
	f.Add(manifestText(Manifest{Component: "runner", Commit: testCommit, Files: []File{{Name: "a"}, {Name: "b.conf"}}}))
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseManifest(b)
		if err == nil && !bytes.Equal(manifestText(m), b) {
			t.Fatalf("%q read as %+v", b, m)
		}
	})
}

func TestReadBundleReadsRegularFiles(t *testing.T) {
	files, err := ReadBundle(tarOf(t, entry{name: "MANIFEST", data: "m"}, entry{name: "balistid-runner", data: "\x7fELF"},
		entry{name: "empty.conf"}))
	if err != nil || len(files) != 3 || string(files["MANIFEST"]) != "m" || string(files["balistid-runner"]) != "\x7fELF" {
		t.Fatalf("%v, %v", files, err)
	}
}

// Nothing in a bundle is a path, a link or a second copy: the installer resolves nothing on disk from it.
func TestReadBundleRefusesAnythingElse(t *testing.T) {
	m := entry{name: "MANIFEST", data: "m"}
	many := []entry{m}
	for i := range maxEntries {
		many = append(many, entry{name: "f" + strconv.Itoa(i)})
	}
	for name, b := range map[string][]byte{
		"a symlink":      tarOf(t, m, entry{name: "balistid-runner", link: "/etc/shadow", typeflag: tar.TypeSymlink}),
		"a hard link":    tarOf(t, m, entry{name: "balistid-runner", link: "MANIFEST", typeflag: tar.TypeLink}),
		"a directory":    tarOf(t, m, entry{name: "etc", typeflag: tar.TypeDir}),
		"a fifo":         tarOf(t, m, entry{name: "fifo", typeflag: tar.TypeFifo}),
		"a device":       tarOf(t, m, entry{name: "dev", typeflag: tar.TypeChar}),
		"dot dot":        tarOf(t, m, entry{name: "../balistid-runner", data: "x"}),
		"a path":         tarOf(t, m, entry{name: "etc/balistid-runner", data: "x"}),
		"absolute":       tarOf(t, m, entry{name: "/balistid-runner", data: "x"}),
		"dot":            tarOf(t, m, entry{name: ".", data: "x"}),
		"a name twice":   tarOf(t, m, entry{name: "a", data: "1"}, entry{name: "a", data: "2"}),
		"MANIFEST twice": tarOf(t, m, m),
		"no MANIFEST":    tarOf(t, entry{name: "a", data: "1"}),
		"too many":       tarOf(t, many...),
		"cut":            tarOf(t, m, entry{name: "a", data: "12345"})[:512+512+512+3],
		"not a tar":      []byte("MANIFEST"),
		"nothing":        nil,
	} {
		if files, err := ReadBundle(b); err == nil {
			t.Errorf("%s: read %d files", name, len(files))
		}
	}
}

// Whatever ReadBundle accepts holds MANIFEST and plain names only.
func FuzzReadBundle(f *testing.F) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, name := range []string{"MANIFEST", "balistid-runner"} {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
	}
	_ = tw.Close()
	f.Add(b.Bytes())
	f.Fuzz(func(t *testing.T, b []byte) {
		files, err := ReadBundle(b)
		if err != nil {
			return
		}
		if _, ok := files["MANIFEST"]; !ok {
			t.Fatal("no MANIFEST")
		}
		for name := range files {
			if !entryName.MatchString(name) {
				t.Fatalf("name %q", name)
			}
		}
	})
}

// The line made from a key ssh-keygen wrote is accepted, and its fingerprint is the one ssh-keygen prints.
func TestParseSignersReadsTheMaintainersLine(t *testing.T) {
	k := newKey(t)
	s, err := ParseSigners(k.signers, "ssh-ed25519")
	if err != nil || !bytes.Equal(s.Line, k.signers) {
		t.Fatalf("%q: %v", s.Line, err)
	}
	if got, want := s.Fingerprint(), k.fingerprint(t); got != want {
		t.Fatalf("fingerprint %s, ssh-keygen says %s", got, want)
	}
}

// Every option ssh-keygen would honour beyond the one namespace, and every other key, is refused.
func TestParseSignersRefusesAnythingElse(t *testing.T) {
	good := string(newKey(t).signers)
	other := string(newKey(t).signers)
	ns := `namespaces="` + Namespace + `"`
	blob, err := base64.StdEncoding.DecodeString(strings.Fields(good)[3])
	if err != nil {
		t.Fatal(err)
	}
	// The same key bytes under another type inside the blob, and the software key named as the token's type.
	relabelled := strings.Replace(good, strings.Fields(good)[3],
		base64.StdEncoding.EncodeToString(append([]byte("\x00\x00\x00\x07ssh-rsa"), blob[15:]...)), 1)
	asSK := strings.Replace(good, " ssh-ed25519 ", " "+SKKeyType+" ", 1)
	for name, line := range map[string]string{
		"two lines":            good + other,
		"a blank line":         good + "\n",
		"no newline":           strings.TrimSuffix(good, "\n"),
		"crlf":                 strings.Replace(good, "\n", "\r\n", 1),
		"a wildcard":           strings.Replace(good, Principal, "*", 1),
		"a pattern":            strings.Replace(good, Principal, "*@balistid.dev", 1),
		"a principal list":     strings.Replace(good, Principal, Principal+",other@example.org", 1),
		"another principal":    strings.Replace(good, Principal, "other@balistid.dev", 1),
		"cert-authority":       strings.Replace(good, ns, "cert-authority,"+ns, 1),
		"cert-authority alone": strings.Replace(good, ns+" ", "cert-authority ", 1),
		"valid-before":         strings.Replace(good, ns, ns+`,valid-before="20990101"`, 1),
		"other namespaces":     strings.Replace(good, Namespace, "file", 1),
		"all namespaces":       strings.Replace(good, Namespace, "*", 1),
		"no option":            strings.Replace(good, ns+" ", "", 1),
		"a comment":            strings.Replace(good, "\n", " maintainer\n", 1),
		"two spaces":           strings.Replace(good, " ssh-ed25519", "  ssh-ed25519", 1),
		"the sk type named":    asSK,
		"another key's type":   relabelled,
		"not base64":           strings.Replace(good, strings.Fields(good)[3], "!!!!", 1),
		"no key":               strings.Replace(good, " "+strings.Fields(good)[3], "", 1),
		"nothing":              "",
		"over the cap":         strings.Replace(good, "\n", strings.Repeat(" ", maxSignersBytes)+"\n", 1),
	} {
		if s, err := ParseSigners([]byte(line), "ssh-ed25519"); err == nil {
			t.Errorf("%s: read %q", name, s.Line)
		}
	}
	for _, line := range []string{good, asSK} {
		if _, err := ParseSigners([]byte(line), SKKeyType); err == nil {
			t.Errorf("a software key passed where the token's key type is required: %q", line)
		}
	}
}

// Whatever ParseSigners accepts is the exact line and its key is of the type asked for.
func FuzzParseSigners(f *testing.F) {
	f.Add([]byte(Principal + ` namespaces="` + Namespace + `" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID+xUOO49fSjHBxMTJSdnpxe5V597l/RM+9uoPWU826q` + "\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := ParseSigners(b, "ssh-ed25519")
		if err != nil {
			return
		}
		if !bytes.Equal(s.Line, b) || !bytes.HasPrefix(s.blob, []byte("\x00\x00\x00\x0bssh-ed25519")) {
			t.Fatalf("%q read as %q", b, s.blob)
		}
	})
}
