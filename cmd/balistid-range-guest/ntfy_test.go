package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newSink(max int) (*sink, *bytes.Buffer) {
	var buf bytes.Buffer
	return &sink{w: &buf, max: max, now: func() (time.Duration, error) { return 1234567 * time.Millisecond, nil }}, &buf
}

func post(t *testing.T, s *sink, method, path, auth, tag, body string) int {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	if tag != "" {
		r.Header.Set("Tags", tag)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w.Code
}

func TestSinkRecordsTagAndUptime(t *testing.T) {
	s, buf := newSink(sinkMaxLines)
	for _, c := range []struct {
		method, path, auth, tag string
		code                    int
	}{
		{http.MethodPost, ntfySinkTopic, "Bearer " + ntfyToken, "silence", http.StatusOK},
		{http.MethodPost, ntfySinkTopic, "Bearer other", "loss", http.StatusUnauthorized},
		{http.MethodPost, ntfySinkTopic, "", "Silence", http.StatusUnauthorized},
		{http.MethodPost, ntfySinkTopic, "Bearer " + ntfyToken + "x", "silence", http.StatusUnauthorized},
		{http.MethodPost, ntfySinkTopic, "Bearer " + ntfyToken, "abcdefghijklmnopq", http.StatusOK},
		{http.MethodPost, ntfySinkTopic, "Bearer " + ntfyToken, "si lence", http.StatusOK},
		{http.MethodGet, ntfySinkTopic, "Bearer " + ntfyToken, "silence", http.StatusNotFound},
		{http.MethodPost, "/other", "Bearer " + ntfyToken, "silence", http.StatusNotFound},
	} {
		if code := post(t, s, c.method, c.path, c.auth, c.tag, "text"); code != c.code {
			t.Errorf("%s %s %q: status %d, want %d", c.method, c.path, c.tag, code, c.code)
		}
	}
	want := "1234567 silence ok\n1234567 loss bad\n1234567 - bad\n1234567 silence bad\n1234567 - ok\n1234567 - ok\n"
	if buf.String() != want {
		t.Errorf("posts:\n%s\nwant:\n%s", buf.String(), want)
	}
}

func TestSinkCapsLinesAndBody(t *testing.T) {
	s, buf := newSink(2)
	if code := post(t, s, http.MethodPost, ntfySinkTopic, "Bearer "+ntfyToken, "loss", strings.Repeat("x", sinkMaxBody+1)); code != http.StatusRequestEntityTooLarge {
		t.Errorf("an oversize body: status %d", code)
	}
	for range 3 {
		post(t, s, http.MethodPost, ntfySinkTopic, "Bearer "+ntfyToken, "loss", strings.Repeat("x", sinkMaxBody))
	}
	if code := post(t, s, http.MethodPost, ntfySinkTopic, "Bearer "+ntfyToken, "loss", ""); code != http.StatusInsufficientStorage {
		t.Errorf("past the line cap: status %d", code)
	}
	if got := strings.Count(buf.String(), "\n"); got != 2 {
		t.Errorf("%d lines kept, want 2:\n%s", got, buf.String())
	}
}
