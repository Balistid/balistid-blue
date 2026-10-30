package main

import (
	"io"
	"net"
	"strings"
	"testing"
)

// The relay's headers are the host's: the client refuses more than maxHeader of them.
func TestClientCapsResponseHeaders(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close() //nolint:errcheck // test listener
	header := "HTTP/1.1 200 OK\r\nX-Pad: " + strings.Repeat("a", 2*maxHeader) + "\r\nContent-Length: 0\r\n\r\n"
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(c, 1))
		_, _ = c.Write([]byte(header))
		_ = c.Close()
	}()
	resp, err := newClient().Get("http://" + ln.Addr().String() + "/") //nolint:noctx // a test request
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a response with headers over the cap was taken")
	}
}
