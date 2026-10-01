package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// hostPort returns the HOST:PORT of a test server's listener.
func hostPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return srv.Listener.Addr().String()
}

func TestHealthcheckOK(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")+r.Header.Get("X-Nospy-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	code, out, errb := runCLI(t, "", "healthcheck", "--listen", hostPort(t, srv))
	if code != 0 || out != "" || errb != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out, errb)
	}
	if gotPath != "/healthz" || gotAuth != "" {
		t.Errorf("path=%q credentials=%q, want /healthz and none", gotPath, gotAuth)
	}
}

func TestHealthcheckStatusNot200(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusNoContent, http.StatusFound} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// A redirect to a healthy page must not be followed.
			w.Header().Set("Location", "/ok")
			w.WriteHeader(status)
		}))
		code, _, errb := runCLI(t, "", "healthcheck", "--listen", hostPort(t, srv))
		srv.Close()
		if code != 1 || !strings.Contains(errb, "status") || strings.Count(errb, "\n") != 1 {
			t.Errorf("status %d: code=%d stderr=%q, want 1 and one line naming the status", status, code, errb)
		}
	}
}

func TestHealthcheckClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	code, _, errb := runCLI(t, "", "healthcheck", "--listen", addr)
	if code != 1 || !strings.Contains(errb, "healthcheck") || strings.Count(errb, "\n") != 1 {
		t.Errorf("code=%d stderr=%q, want 1 with one line", code, errb)
	}
}

func TestHealthcheckTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	code, _, errb := runCLI(t, "", "healthcheck", "--listen", hostPort(t, srv), "--timeout", "150ms")
	if code != 1 || errb == "" {
		t.Errorf("code=%d stderr=%q, want 1 with a reason", code, errb)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %v with --timeout 150ms", d)
	}
}

func TestHealthcheckWildcardListen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(hostPort(t, srv))
	for _, listen := range []string{"0.0.0.0:" + port, "[::]:" + port, ":" + port} {
		if code, _, errb := runCLI(t, "", "healthcheck", "--listen", listen); code != 0 {
			t.Errorf("--listen %s: code=%d stderr=%q, want 0", listen, code, errb)
		}
	}
}

func TestProbeAddr(t *testing.T) {
	for listen, want := range map[string]string{
		"127.0.0.1:8788": "127.0.0.1:8788",
		"0.0.0.0:8788":   "127.0.0.1:8788",
		"[::]:8788":      "127.0.0.1:8788",
		":8788":          "127.0.0.1:8788",
		"[::1]:9":        "[::1]:9",
		"localhost:8788": "localhost:8788",
		"10.1.2.3:8443":  "10.1.2.3:8443",
	} {
		if got, err := probeAddr(listen); err != nil || got != want {
			t.Errorf("probeAddr(%q) = %q, %v; want %q", listen, got, err, want)
		}
	}
	for _, bad := range []string{"", "8788", "host", "h:0", "h:99999", "h:x"} {
		if _, err := probeAddr(bad); err == nil {
			t.Errorf("probeAddr(%q) accepted", bad)
		}
	}
}

func TestHealthcheckHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	// The test certificate is not trusted: a pass shows verification is skipped.
	if code, _, errb := runCLI(t, "", "healthcheck", "--listen", hostPort(t, srv), "--scheme", "https"); code != 0 {
		t.Errorf("https: code=%d stderr=%q", code, errb)
	}
	// Plain http against a TLS listener is a failure, not a pass.
	if code, _, _ := runCLI(t, "", "healthcheck", "--listen", hostPort(t, srv)); code != 1 {
		t.Errorf("http to a TLS listener: code=%d, want 1", code)
	}
}

func TestHealthcheckUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"healthcheck", "--scheme", "ftp"},
		{"healthcheck", "--listen", "nonsense"},
		{"healthcheck", "--timeout", "0s"},
		{"healthcheck", "--timeout", "soon"},
		{"healthcheck", "extra"},
		{"healthcheck", "--bogus"},
	} {
		code, out, errb := runCLI(t, "", args...)
		if code != 2 || out != "" || !strings.Contains(errb, "usage: nospy healthcheck") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q, want 2 with usage", args, code, out, errb)
		}
	}
}

func TestHealthcheckHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "healthcheck"}, {"healthcheck", "-h"}} {
		code, out, errb := runCLI(t, "", args...)
		if code != 0 || !strings.Contains(out, "usage: nospy healthcheck") || !strings.Contains(out, "-scheme") || errb != "" {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, out, errb)
		}
	}
	if _, out, _ := runCLI(t, "", "help"); !strings.Contains(out, "healthcheck ") {
		t.Errorf("help does not list healthcheck: %q", out)
	}
}
