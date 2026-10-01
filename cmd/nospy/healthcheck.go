package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

type healthcheckOpts struct {
	listen  string
	scheme  string
	timeout time.Duration
}

func defineHealthcheckFlags(fs *flag.FlagSet) *healthcheckOpts {
	o := &healthcheckOpts{}
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8788", "the `HOST:PORT` nospy serve listens on; a wildcard address (0.0.0.0, [::] or no host) probes 127.0.0.1")
	fs.StringVar(&o.scheme, "scheme", "http", "`SCHEME` to probe with, http or https (https skips certificate verification: the probe sends no credentials)")
	fs.DurationVar(&o.timeout, "timeout", 2*time.Second, "give up after this long")
	return o
}

// probeAddr maps a serve --listen value to the address to dial: a wildcard host (empty, 0.0.0.0, ::)
// means "every interface", so the probe uses loopback. It returns an error for anything that is not HOST:PORT.
func probeAddr(listen string) (string, error) {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "", fmt.Errorf("--listen %q is not HOST:PORT", listen)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("--listen %q has an invalid port", listen)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// runHealthcheck probes GET /healthz of a running `nospy serve`: exit 0 on 200, 1 otherwise with one
// line on stderr saying why. It exists because the container image has no shell or curl. It sends
// no token, body or key, follows no redirects, uses no proxy and reads nothing from env or files.
func runHealthcheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet(io.Discard)
	o := defineHealthcheckFlags(fs)
	if code, ok := parseFlags("healthcheck", fs, args, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() > 0 {
		return usageError("healthcheck", stderr, "unexpected argument %q", fs.Arg(0))
	}
	if o.scheme != "http" && o.scheme != "https" {
		return usageError("healthcheck", stderr, "--scheme must be http or https, not %q", o.scheme)
	}
	if o.timeout <= 0 {
		return usageError("healthcheck", stderr, "--timeout must be positive")
	}
	addr, err := probeAddr(o.listen)
	if err != nil {
		return usageError("healthcheck", stderr, "%v", err)
	}

	client := &http.Client{
		Timeout: o.timeout,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			// The probe talks to the local listener and reads only the status; like kubelet, it does
			// not verify the certificate (which is usually for the service's name, not 127.0.0.1).
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, //nolint:gosec // see above
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.scheme+"://"+addr+"/healthz", nil)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nospy: healthcheck: %v\n", err)
		return exitFail
	}
	resp, err := client.Do(req)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nospy: healthcheck: GET %s://%s/healthz: %v\n", o.scheme, addr, err)
		return exitFail
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = fmt.Fprintf(stderr, "nospy: healthcheck: GET %s://%s/healthz: status %d\n", o.scheme, addr, resp.StatusCode)
		return exitFail
	}
	return 0
}
