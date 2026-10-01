package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"nospyai/internal/proxy"
	"nospyai/internal/redact"
)

const shutdownTimeout = 2 * time.Second

// noTrafficAfter is how long the child must run without sending a request through the proxy
// before nospy warns. A package var so tests can shorten it.
var noTrafficAfter = 3 * time.Second

const noTrafficWarning = "nospy: warning: agent sent zero requests through nospy. The agent may be using its own base URL, so its traffic was not redacted."

// wrapMetricsAddr is where a wrapped session serves /metrics. It is a variable so tests can
// swap in a free port. With --metrics=false, or when this port is taken, the wrapper listens
// on a random loopback port.
var wrapMetricsAddr = "127.0.0.1:9464"

type wrapOpts struct {
	routes        multiFlag
	providers     multiFlag
	metrics       bool
	noAgentConfig bool
	logFile       string
	terms         string
}

func defineWrapFlags(fs *flag.FlagSet) *wrapOpts {
	o := &wrapOpts{}
	fs.Var(&o.routes, "route", routeFlagUsage())
	fs.Var(&o.providers, "provider", "add the built-in route of provider `NAME` and point its API family's base-URL variable at it, replacing the default route; repeatable. `nospy providers` lists the names")
	fs.BoolVar(&o.metrics, "metrics", true, "serve aggregate Prometheus metrics at GET /metrics on loopback port 9464 for the session, without authentication. Only one session can hold the port; others run without metrics. --metrics=false turns it off")
	fs.BoolVar(&o.noAgentConfig, "no-agent-config", false, "overrides base URL settings to known agents' command lines")
	fs.StringVar(&o.logFile, "log", "", "append JSON logs to `file`; logging disabled by default")
	fs.StringVar(&o.terms, "terms", "", termsFlagUsage)
	return o
}

// runWrap runs a command behind a local redacting proxy and returns the command's exit code.
func runWrap(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet(io.Discard)
	o := defineWrapFlags(fs)
	if code, ok := parseFlags("nospy", fs, args, stdout, stderr); !ok {
		return code
	}
	// Require the explicit "--", so `nospy scan`-style typos aren't run as commands.
	if i := len(args) - fs.NArg() - 1; fs.NArg() == 0 || i < 0 || args[i] != "--" {
		return usageError("nospy", stderr, "expected -- followed by the command to run")
	}
	cmdArgs := fs.Args()

	specs, err := parseRoutes(o.routes)
	if err != nil {
		return usageError("nospy", stderr, "%v", err)
	}
	wroutes, err := buildWrapRoutes(specs, o.providers, getenv)
	if err != nil {
		return usageError("nospy", stderr, "%v", err)
	}
	terms, tcode := loadTermsFlag("nospy", o.terms, stderr)
	if tcode != 0 {
		return tcode
	}
	routes := make([]proxy.Route, len(wroutes))
	for i, wr := range wroutes {
		routes[i] = wr.Route
	}

	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if o.logFile != "" {
		f, err := os.OpenFile(o.logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "nospy: opening log file: %v\n", err)
			return exitFail
		}
		defer func() { _ = f.Close() }()
		log = slog.New(slog.NewJSONHandler(f, nil))
	}

	if nt, ns := terms.Count(); o.terms != "" {
		// Counts only: the terms file is never logged (invariant 8).
		log.Info(fmt.Sprintf("loaded %d terms in %d sections", nt, ns))
	}

	token, err := newToken()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nospy: generating token: %v\n", err)
		return exitFail
	}
	// Every route's upstream host is allowlisted, so redaction never rewrites the host we forward to.
	opts := []proxy.Option{proxy.WithUserAgent("nospy/" + version)}
	if o.metrics {
		opts = append(opts, proxy.WithMetrics(proxy.NewMetrics()))
	}
	h, err := proxy.New(routes, token, redact.NewDetector(redact.Config{AllowHosts: upstreamHosts(wroutes), Terms: terms}), log, opts...)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nospy: %v\n", err)
		return exitFail
	}
	lc := &net.ListenConfig{}
	var ln net.Listener
	if o.metrics {
		// The metrics port is fixed, so a second session can't have it. It runs on a random port instead.
		if ln, err = lc.Listen(context.Background(), "tcp", wrapMetricsAddr); err != nil {
			log.Warn("metrics port unavailable; this session's metrics are not scrapeable at the fixed address", "addr", wrapMetricsAddr, "err", err)
			_, _ = fmt.Fprintf(stderr, "nospy: warning: metrics port %s is in use, so this session's metrics are not available there. Pass --metrics=false to silence this.\n", wrapMetricsAddr)
			ln = nil
		}
	}
	if ln == nil {
		// Loopback only, never 0.0.0.0.
		if ln, err = lc.Listen(context.Background(), "tcp", "127.0.0.1:0"); err != nil {
			_, _ = fmt.Fprintf(stderr, "nospy: listen: %v\n", err)
			return exitFail
		}
	}
	tw := &tripwire{token: token, next: h}
	srv := &http.Server{
		Handler:           tw,
		ReadHeaderTimeout: 10 * time.Second,
		// The default ErrorLog writes to stderr, which would corrupt the child's TUI.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("proxy server stopped", "err", err)
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if srv.Shutdown(ctx) != nil {
			_ = srv.Close()
		}
	}()

	// Base URLs for the child: one env var per API family, each carrying the session token.
	baseURLs := map[string]string{}
	var assigns []string
	for _, wr := range wroutes {
		if wr.envVar == "" {
			continue
		}
		u := "http://" + ln.Addr().String() + "/" + token + wr.Prefix + wr.baseSuffix
		baseURLs[wr.envVar] = u
		assigns = append(assigns, wr.envVar+"="+u)
	}

	// Catch signals from here on, so a SIGTERM during setup can't skip the cleanup below.
	sigs, stopSigs := catchSignals()
	defer stopSigs()
	cmdArgs, cleanup, err := injectAgentConfig(cmdArgs, baseURLs, o.noAgentConfig, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "nospy: writing agent config: %v\n", err)
		return exitFail
	}
	defer cleanup()

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...) //nolint:gosec,noctx // user-supplied command is the agent's purpose; runChild forwards signals itself
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	cmd.Env = childEnv(os.Environ(), assigns...)
	start := time.Now()
	code := runChild(cmd, sigs, stderr)
	// The agent's UI is gone by now, so this line is readable. It is a tripwire, not protection:
	// whatever the agent sent has already left.
	if tw.count() == 0 && time.Since(start) >= noTrafficAfter {
		_, _ = fmt.Fprintln(stderr, noTrafficWarning)
	}
	return code
}

// tripwire counts requests that carry the session token in their path, then passes them on.
type tripwire struct {
	token string
	next  http.Handler
	n     atomic.Int64
}

func (t *tripwire) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	first, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if subtle.ConstantTimeCompare([]byte(first), []byte(t.token)) == 1 {
		t.n.Add(1)
	}
	t.next.ServeHTTP(w, r)
}

func (t *tripwire) count() int64 { return t.n.Load() }

// catchSignals starts delivering SIGINT/SIGQUIT/SIGTERM/SIGHUP on the returned channel.
// Notify, not Ignore: an ignored disposition would be inherited by the child across exec.
func catchSignals() (chan os.Signal, func()) {
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGHUP)
	return sigs, func() { signal.Stop(sigs) }
}

// runChild starts cmd and waits for it, returning its exit code. The terminal sends
// SIGINT/SIGQUIT to the whole foreground process group, so the child already gets them; the
// parent just must not die first. SIGTERM/SIGHUP are forwarded, since they're sent to nospy alone.
// sigs comes from catchSignals.
func runChild(cmd *exec.Cmd, sigs <-chan os.Signal, stderr io.Writer) int {
	if err := cmd.Start(); err != nil {
		_, _ = fmt.Fprintf(stderr, "nospy: cannot run %s: %v\n", cmd.Args[0], err)
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return 127
		}
		return 126
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case sig := <-sigs:
				if sig == syscall.SIGTERM || sig == syscall.SIGHUP {
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()
	return exitCode(cmd.Wait())
}

// exitCode maps Wait's error to a shell-style exit code: 128+n if the child died from signal n.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return exitFail
}

// selectUpstream picks the route's --route value, else the parent's env value, else the
// default, and refuses a selection that already points at a nospy wrapper (proxy chaining).
// Error text never includes the URL, which may carry credentials.
func selectUpstream(rt routeDef, flagVal, envVal string) (*url.URL, error) {
	raw, src := rt.defaultUpstream, "default upstream"
	switch {
	case flagVal != "":
		raw, src = flagVal, "--route "+rt.prefix
	case envVal != "":
		raw, src = envVal, rt.envVar
	}
	return parseUpstream(raw, src, rt.prefix)
}

// parseUpstream checks that raw is an absolute http(s) URL that is not a nospy address. src
// names where it came from, for the error text; the URL itself is never echoed.
func parseUpstream(raw, src, prefix string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%s is not an absolute http(s) URL", src)
	}
	if isNospyAddr(u) {
		return nil, fmt.Errorf("%s already points at a nospy proxy; refusing to chain proxies (unset it or pass --route %s=URL)", src, prefix)
	}
	return u, nil
}

var tokenSegRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// isNospyAddr reports whether u looks like a wrapper's own address: a loopback host and a
// path that starts with a 32-hex token. A plain local gateway (http://127.0.0.1:4000) doesn't match.
func isNospyAddr(u *url.URL) bool {
	host := u.Hostname()
	if a, err := netip.ParseAddr(host); host != "localhost" && (err != nil || !a.IsLoopback()) {
		return false
	}
	first, _, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
	return tokenSegRe.MatchString(first)
}

// upstreamHost is the hostname of a URL known to be valid (used for the detector allowlist).
func upstreamHost(raw string) string {
	u, _ := url.Parse(raw)
	return u.Hostname()
}

// newToken returns 16 random bytes, hex-encoded: the per-run path token.
func newToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// childEnv returns base with each KEY=value assignment replacing any existing KEY.
func childEnv(base []string, assigns ...string) []string {
	drop := map[string]bool{}
	for _, a := range assigns {
		k, _, _ := strings.Cut(a, "=")
		drop[k] = true
	}
	out := make([]string, 0, len(base)+len(assigns))
	for _, kv := range base {
		if k, _, _ := strings.Cut(kv, "="); !drop[k] {
			out = append(out, kv)
		}
	}
	return append(out, assigns...)
}
