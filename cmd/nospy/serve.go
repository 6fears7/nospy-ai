package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"nospyai/internal/proxy"
	"nospyai/internal/redact"
)

// certWarnWithin is how close to expiry a TLS certificate warns.
const certWarnWithin = 14 * 24 * time.Hour

type serveOpts struct {
	listen          string
	auth            string
	tokensFile      string
	tlsCert, tlsKey string
	insecure        bool
	metrics         bool
	routes          multiFlag
	providers       multiFlag
	terms           string
	chainTTL        time.Duration
	chainMax        int
	shutdownTimeout time.Duration
	peers, peerSelf string
}

var serveRouteUsage = "add a route, as `PREFIX=URL[,api=" + apiNames() + "][,key-mode=passthrough|inject][,key-file=FILE]`; repeatable. " 
#
func defineServeFlags(fs *flag.FlagSet) *serveOpts {
	o := &serveOpts{}
	fs.StringVar(&o.listen, "listen", "127.0.0.1:8788", "address to listen on, as `HOST:PORT`. A non-loopback address needs --auth static-tokens and TLS")
	fs.StringVar(&o.auth, "auth", "", "how clients authenticate (required): `none` (loopback only; every client is \"local\") or `static-tokens` (needs --tokens-file)")
	fs.StringVar(&o.tokensFile, "tokens-file", "", "with --auth static-tokens: a file of `name:sha256hex` lines, reloaded when it changes (see `nospy hash-token`)")
	fs.StringVar(&o.tlsCert, "tls-cert", "", "TLS certificate `file` (PEM), reloaded when it changes; needs --tls-key")
	fs.StringVar(&o.tlsKey, "tls-key", "", "TLS private key `file` (PEM), reloaded when it changes; needs --tls-cert")
	fs.BoolVar(&o.insecure, "insecure-plaintext", false, "allow plaintext HTTP on a non-loopback address (traffic, tokens and keys cross the network unencrypted)")
	fs.BoolVar(&o.metrics, "metrics", true, "expose aggregate Prometheus metrics at GET /metrics on the same listener, without client authentication. --metrics=false turns it off")
	fs.Var(&o.routes, "route", serveRouteUsage)
	fs.Var(&o.providers, "provider", "add the built-in route of provider `NAME` as a passthrough route /NAME; repeatable. `nospy providers` lists the names")
	fs.StringVar(&o.terms, "terms", "", termsFlagUsage)
	fs.DurationVar(&o.chainTTL, "chain-ttl", proxy.DefaultChainTTL, "how long a conversation's redaction state is kept for follow-up requests")
	fs.IntVar(&o.chainMax, "chain-max", proxy.DefaultChainMax, "most conversations whose redaction state is kept in memory")
	fs.DurationVar(&o.shutdownTimeout, "shutdown-timeout", 30*time.Second, "on SIGTERM, how long to let in-flight requests and streams finish before closing them")
	fs.StringVar(&o.peers, "peers", "", "run multiple replicas: a DNS name that resolves to every ready replica (a headless Service), as `HOST:PORT`. Each client's requests are forwarded to one replica, "+
		"so its remembered values and conversation state stay in one process. Needs --peer-self, a non-loopback --listen and TLS (or --insecure-plaintext)")
	fs.StringVar(&o.peerSelf, "peer-self", "", "with --peers: this replica's own `IP` (in Kubernetes, the pod IP from the downward API); a replica not listed under --peers serves every request itself")
	return o
}

// serveConfig is everything serve runs from, built once by buildServeConfig. `check` builds the
// same thing and stops, so it cannot drift from what serve enforces.
type serveConfig struct {
	listen          string
	handler         http.Handler
	certs           *proxy.CertFiles // nil without TLS
	shutdownTimeout time.Duration
	peers           *proxy.Peers // nil without --peers; serveUntil keeps its set current
	summary         string       // the `check` success line: no secrets, tokens, keys or terms
	warnings        []string     // non-fatal findings
	startAttrs      []any        // the serve startup log line, same rules as summary
}

// flatten splits a joined error into its parts.
func flatten(err error) []error {
	if err == nil {
		return nil
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, e := range j.Unwrap() {
			out = append(out, flatten(e)...)
		}
		return out
	}
	return []error{err}
}

// buildServeConfig validates every flag combination and file and returns the config, or every
// problem found (not just the first). Messages never contain a token, key, term or URL. now is
// for certificate validity.
func buildServeConfig(o *serveOpts, log *slog.Logger, now func() time.Time) (*serveConfig, []error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }
	var warns []string

	// Listen address and the loopback rule (invariant 9).
	loopback, listenOK := false, false
	if _, port, err := net.SplitHostPort(o.listen); err != nil {
		fail("--listen %q is not HOST:PORT", o.listen)
	} else if n, err := strconv.Atoi(port); err != nil || n < 0 || n > 65535 {
		fail("--listen %q has an invalid port", o.listen)
	} else {
		loopback, listenOK = proxy.IsLoopbackListen(o.listen), true
	}

	// TLS.
	tlsOn := o.tlsCert != "" || o.tlsKey != ""
	switch {
	case (o.tlsCert == "") != (o.tlsKey == ""):
		fail("--tls-cert and --tls-key must be given together")
	case tlsOn && o.insecure:
		fail("--insecure-plaintext conflicts with --tls-cert/--tls-key")
	}
	if listenOK && !loopback && !tlsOn && !o.insecure {
		fail("--listen %s is not a loopback address: serving plaintext there needs TLS (--tls-cert and --tls-key) or an explicit --insecure-plaintext", o.listen)
	}
	if listenOK && !loopback && o.insecure && !tlsOn {
		warns = append(warns, "serving plaintext on a non-loopback address: tokens, keys and prompts cross the network unencrypted")
	}
	var certs *proxy.CertFiles
	var certExpiry time.Time
	if o.tlsCert != "" && o.tlsKey != "" {
		c, err := proxy.LoadCertFiles(o.tlsCert, o.tlsKey, log, now)
		if err != nil {
			errs = append(errs, err)
		} else {
			certs, certExpiry = c, c.NotAfter()
			if left := certExpiry.Sub(now()); left < certWarnWithin {
				warns = append(warns, fmt.Sprintf("the TLS certificate expires on %s (in %d days)", certExpiry.UTC().Format(time.DateOnly), int(left.Hours()/24)))
			}
		}
	}

	// Authentication.
	var auth proxy.Authenticator
	authDesc := ""
	switch o.auth {
	case "none":
		authDesc = "none"
		if o.tokensFile != "" {
			fail("--tokens-file is only valid with --auth static-tokens")
		}
		if a, err := proxy.NewNoneAuth(o.listen); err != nil {
			if listenOK {
				fail("--auth none is only allowed on a loopback --listen address (127.0.0.1, [::1] or localhost); use --auth static-tokens")
			}
		} else {
			auth = a
		}
	case "static-tokens":
		if o.tokensFile == "" {
			fail("--auth static-tokens needs --tokens-file")
			break
		}
		st, err := proxy.LoadStaticTokens(o.tokensFile, log)
		if err != nil {
			for _, e := range flatten(err) {
				fail("--tokens-file %s: %v", o.tokensFile, e)
			}
			break
		}
		auth = st
		authDesc = fmt.Sprintf("static-tokens (%d tokens)", st.Len())
	case "":
		fail("--auth is required: none or static-tokens")
	default:
		fail("--auth must be none or static-tokens")
	}

	// Routes and key modes.
	specs, err := parseRoutes(o.routes)
	errs = append(errs, flatten(err)...)
	sroutes, rerrs := buildServeRoutes(specs, o.providers)
	errs = append(errs, rerrs...)
	if len(specs) == 0 && len(o.providers) == 0 && err == nil {
		fail("no routes: pass --route PREFIX=URL and/or --provider NAME")
	}
	var routes []proxy.Route
	var routeDescs, startRoutes []string
	for _, rt := range sroutes {
		if rt.KeyMode == proxy.KeyInject {
			if o.auth == "none" && listenOK && !loopback {
				fail("route %s: key-mode=inject with --auth none needs a loopback --listen address: anyone who can reach the listener could use the key", rt.Prefix)
			}
			kf, err := proxy.LoadKeyFile(rt.keyFile, log)
			if err != nil {
				fail("route %s: --route key-file %s: %v", rt.Prefix, rt.keyFile, err)
				continue
			}
			rt.Key = kf.Get
			if u := rt.Upstream; u.Scheme == "http" && !proxy.IsLoopbackHost(u.Hostname()) {
				warns = append(warns, fmt.Sprintf("route %s injects its key into plaintext http to a non-loopback upstream", rt.Prefix))
			}
		}
		routes = append(routes, rt.Route)
		d := strings.TrimPrefix(rt.Prefix, "/") + "(" + rt.KeyMode.String() + ")"
		routeDescs = append(routeDescs, d)
		startRoutes = append(startRoutes, d+" -> "+rt.Upstream.Scheme+"://"+rt.Upstream.Host)
	}

	// Terms.
	var terms *redact.Terms
	if o.terms != "" {
		t, err := redact.LoadTermsFile(o.terms)
		if err != nil {
			for _, e := range flatten(err) {
				fail("--terms %s: %v", o.terms, e)
			}
		} else {
			terms = t
		}
	}

	// Replicas.
	var peers *proxy.Peers
	switch {
	case o.peers == "" && o.peerSelf != "":
		fail("--peer-self needs --peers")
	case o.peers != "" && o.peerSelf == "":
		fail("--peers needs --peer-self (this replica's own IP)")
	case o.peers != "" && listenOK && loopback:
		fail("--peers needs a non-loopback --listen address: replicas reach each other by IP")
	case o.peers != "":
		var err error
		if peers, err = proxy.NewPeers(o.peers, o.peerSelf, certs, log); err != nil {
			fail("--peers/--peer-self: %v", err)
		}
	}

	// Chain store and shutdown.
	if o.chainTTL <= 0 {
		fail("--chain-ttl must be positive")
	}
	if o.chainMax <= 0 {
		fail("--chain-max must be positive")
	}
	if o.shutdownTimeout <= 0 {
		fail("--shutdown-timeout must be positive")
	}

	if len(errs) > 0 {
		return nil, errs
	}

	opts := []proxy.Option{proxy.WithChainStore(proxy.NewChainStore(o.chainMax, o.chainTTL)),
		proxy.WithKnownStore(proxy.NewKnownStore(0, o.chainTTL)), proxy.WithUserAgent("nospy/" + version)}
	if o.metrics {
		opts = append(opts, proxy.WithMetrics(proxy.NewMetrics()))
	}
	if peers != nil {
		opts = append(opts, proxy.WithPeers(peers))
	}
	h, err := proxy.NewServer(routes, auth,
		redact.NewDetector(redact.Config{AllowHosts: routeHosts(routes), Terms: terms}), log, opts...)
	if err != nil {
		return nil, []error{err}
	}

	parts := []string{"routes " + strings.Join(routeDescs, " "), "auth " + authDesc}
	attrs := []any{"routes", startRoutes, "auth", o.auth}
	if o.metrics {
		parts = append(parts, "metrics /metrics")
		attrs = append(attrs, "metrics", true)
	}
	if st, ok := auth.(*proxy.StaticTokens); ok {
		attrs = append(attrs, "tokens", st.Len())
	}
	if o.terms != "" {
		nt, ns := terms.Count() // counts only, never the terms (invariant 8)
		parts = append(parts, fmt.Sprintf("terms %d in %d sections", nt, ns))
		attrs = append(attrs, "terms", nt, "term_sections", ns)
	}
	if certs != nil {
		parts = append(parts, "tls expires "+certExpiry.UTC().Format(time.DateOnly))
		attrs = append(attrs, "tls", true)
	} else {
		parts = append(parts, "plaintext")
		attrs = append(attrs, "tls", false)
	}
	attrs = append(attrs, "chain_ttl", o.chainTTL.String(), "chain_max", o.chainMax)
	if peers != nil {
		parts = append(parts, "peers "+o.peers)
		attrs = append(attrs, "peers", o.peers)
	}
	return &serveConfig{
		listen: o.listen, handler: h, certs: certs, peers: peers, shutdownTimeout: o.shutdownTimeout,
		summary: "ok: " + strings.Join(parts, "; "), warnings: warns, startAttrs: attrs,
	}, nil
}

// prepareServe parses serve's flags and builds the config; `serve` and `check` both start here.
// On failure it has printed the problems and returns the exit code: exitUsage for bad arguments,
// exitFail for an invalid configuration.
func prepareServe(cmd string, args []string, stdout, stderr io.Writer, log *slog.Logger, now func() time.Time) (*serveConfig, int) {
	fs := newFlagSet(io.Discard)
	o := defineServeFlags(fs)
	if code, ok := parseFlags(cmd, fs, args, stdout, stderr); !ok {
		return nil, code
	}
	if fs.NArg() > 0 {
		return nil, usageError(cmd, stderr, "unexpected argument %q", fs.Arg(0))
	}
	cfg, errs := buildServeConfig(o, log, now)
	if len(errs) > 0 {
		s := "s"
		if len(errs) == 1 {
			s = ""
		}
		_, _ = fmt.Fprintf(stderr, "nospy: invalid configuration (%d problem%s):\n", len(errs), s)
		for _, e := range errs {
			_, _ = fmt.Fprintf(stderr, "  - %s\n", strings.ReplaceAll(e.Error(), "\n", "\n    "))
		}
		return nil, exitFail
	}
	return cfg, 0
}

// runCheck validates a serve configuration and exits without listening.
func runCheck(args []string, stdout, stderr io.Writer) int {
	cfg, code := prepareServe("check", args, stdout, stderr, slog.New(slog.DiscardHandler), time.Now)
	if cfg == nil {
		return code
	}
	if _, err := fmt.Fprintln(stdout, cfg.summary); err != nil {
		return exitFail
	}
	for _, w := range cfg.warnings {
		_, _ = fmt.Fprintf(stderr, "nospy: warning: %s\n", w)
	}
	return 0
}

// runServe runs the redacting proxy as a long-lived server until SIGTERM or SIGINT.
func runServe(args []string, stdout, stderr io.Writer) int {
	log := slog.New(slog.NewJSONHandler(stdout, nil))
	cfg, code := prepareServe("serve", args, stdout, stderr, log, time.Now)
	if cfg == nil {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return serveUntil(ctx, cfg, nil, log, stderr)
}

// serveUntil serves cfg on ln (or a new listener on cfg.listen) until ctx is done, then drains:
// /readyz turns 503, no new connections are accepted, and in-flight requests and streams get
// cfg.shutdownTimeout to finish before they are closed.
func serveUntil(ctx context.Context, cfg *serveConfig, ln net.Listener, log *slog.Logger, stderr io.Writer) int {
	if ln == nil {
		var err error
		if ln, err = (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.listen); err != nil {
			_, _ = fmt.Fprintf(stderr, "nospy: listen: %v\n", err)
			return exitFail
		}
	}
	health := proxy.NewHealth(cfg.handler)
	srv := &http.Server{
		Handler:           health,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: SSE streams run for minutes.
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	for _, w := range cfg.warnings {
		log.Warn(w)
	}
	log.Info("serve", append([]any{"listen", ln.Addr().String()}, cfg.startAttrs...)...)

	if cfg.peers != nil {
		go cfg.peers.Run(ctx)
	}
	errc := make(chan error, 1)
	go func() {
		if cfg.certs != nil {
			srv.TLSConfig = &tls.Config{GetCertificate: cfg.certs.GetCertificate, MinVersion: tls.VersionTLS12}
			errc <- srv.ServeTLS(ln, "", "")
		} else {
			// Without TLS, peers forward over h2c so their connections get HTTP/2 pings
			// (plan/24-peer-liveness.md); HTTP/1.1 clients are unaffected.
			srv.Protocols = new(http.Protocols)
			srv.Protocols.SetHTTP1(true)
			srv.Protocols.SetUnencryptedHTTP2(true)
			errc <- srv.Serve(ln)
		}
	}()

	select {
	case err := <-errc:
		_, _ = fmt.Fprintf(stderr, "nospy: serve: %v\n", err)
		return exitFail
	case <-ctx.Done():
	}
	log.Info("shutting down", "timeout", cfg.shutdownTimeout.String())
	health.SetReady(false)
	sctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Warn("shutdown timeout reached; closing remaining connections")
		}
		_ = srv.Close()
		return exitFail
	}
	log.Info("stopped")
	return 0
}
