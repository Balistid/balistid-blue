package main

import (
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

func TestReadVerifierRefusesASymlinkAndAnOversizeFile(t *testing.T) {
	_, vkey, err := note.GenerateKey(rand.Reader, "balistid.test/log")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	good, link, big := filepath.Join(dir, "key.pub"), filepath.Join(dir, "link.pub"), filepath.Join(dir, "big.pub")
	if err := os.WriteFile(good, []byte(vkey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(big, []byte(strings.Repeat("a", maxKeyBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := readVerifier(good, note.NewVerifier); err != nil || v.Name() != "balistid.test/log" {
		t.Fatalf("good key: %v", err)
	}
	for _, p := range []string{link, big, filepath.Join(dir, "absent")} {
		if _, err := readVerifier(p, note.NewVerifier); err == nil {
			t.Errorf("%s: accepted", filepath.Base(p))
		}
	}
}

// HTTPS_PROXY and the like never route the checkpoint through another host.
func TestTheClientIgnoresProxyVariables(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	c := newClient()
	if p := c.Transport.(*http.Transport).Proxy; p != nil { //nolint:forcetypeassert // newClient sets it
		t.Fatal("the transport takes a proxy from the environment")
	}
	if c.CheckRedirect == nil || c.Timeout != httpTimeout {
		t.Fatal("redirects or the timeout changed")
	}
}

// A witness that redirects gets its redirect back as the answer: the checkpoint goes to no other host.
func TestTheClientDoesNotFollowARedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("the redirect was followed")
	}))
	defer other.Close()
	srv := httptest.NewServer(http.RedirectHandler(other.URL+"/add-checkpoint", http.StatusTemporaryRedirect))
	defer srv.Close()
	c := &http.Client{CheckRedirect: noRedirect}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/add-checkpoint", strings.NewReader("old 0\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
