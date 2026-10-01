package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"nospyai/internal/payload"
	"nospyai/internal/proxy"
)

// Fake credentials, assembled so no scanner sees a token-looking literal.
var (
	testTokA   = "nspy" + "_serve-test-token-a"
	testTokB   = "nspy" + "_serve-test-token-b"
	testRealK  = "sk-" + "ant-serve-test-real-key-0123456789"
	testClient = "sk-" + "ant-serve-test-client-key-0123456789"
)

func wfile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// selfSigned writes a throwaway certificate and key pair valid until notAfter.
func selfSigned(t *testing.T, dir, name string, notAfter time.Time) (cert, key string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(k)
	cert = wfile(t, dir, name+".crt", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	key = wfile(t, dir, name+".key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})))
	return
}

type fixtures struct{ dir, tokens, key, terms, cert, tlsKey string }

func TestServeMetricsWithClientAuthentication(t *testing.T) {
	up := httptest.NewServer(&echoUpstream{})
	defer up.Close()
	tokens := wfile(t, t.TempDir(), "tokens", "private-metrics-client:"+proxy.HashToken(testTokA)+"\n")
	addr, cancel, done, _ := startServe(t, "--metrics", "--auth", "static-tokens", "--tokens-file", tokens,
		"--route", "/anthropic="+up.URL)
	defer cancel()
	base := "http://" + addr
	code, _ := doReq(t, http.DefaultClient, "POST", base+"/anthropic/v1/messages", msgBody(false), nil)
	if code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated proxy request: %d", code)
	}
	code, _ = doReq(t, http.DefaultClient, "POST", base+"/anthropic/v1/messages", msgBody(false),
		map[string]string{proxy.TokenHeader: testTokA})
	if code != http.StatusOK {
		t.Fatalf("authenticated proxy request: %d", code)
	}
	code, body := doReq(t, http.DefaultClient, "GET", base+"/metrics", "", nil)
	if code != http.StatusOK || !strings.Contains(body, `status="401"`) || !strings.Contains(body, `status="200"`) ||
		!strings.Contains(body, `nospy_redactions_total{route="/anthropic",kind="EMAIL"}`) {
		t.Fatalf("metrics not available without a client token: %d %s", code, body)
	}
	for _, secret := range []string{testTokA, secretEmail, "private-metrics-client", "[REDACTED_"} {
		if strings.Contains(body, secret) {
			t.Fatalf("request data %q appeared in scrape", secret)
		}
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("serve exit: %d", code)
	}
}

func newFixtures(t *testing.T) fixtures {
	t.Helper()
	dir := t.TempDir()
	f := fixtures{dir: dir}
	f.tokens = wfile(t, dir, "tokens", "# clients\nalice:"+proxy.HashToken(testTokA)+"\nbob:"+proxy.HashToken(testTokB)+"\nci:"+proxy.HashToken("nspy"+"_ci")+"\n")
	f.key = wfile(t, dir, "key", testRealK+"\n")
	f.terms = wfile(t, dir, "terms", "[CODENAME]\nbluebird\nOrion Next\n[CUSTOMER]\nAcme Corp\nre:ACME-\\d{4}\n[ALLOW]\ndocs.example.com\n")
	f.cert, f.tlsKey = selfSigned(t, dir, "srv", time.Now().Add(90*24*time.Hour))
	return f
}

// --- startup errors: serve and check print the same problems ---

func TestServeConfigErrors(t *testing.T) {
	f := newFixtures(t)
	badTokens := wfile(t, f.dir, "badtokens", "not-a-valid-line\nZ:abc\n")
	badTerms := wfile(t, f.dir, "badterms", "ab\nre:(\n")
	emptyKey := wfile(t, f.dir, "emptykey", "\n")
	const route = "/anthropic=https://api.example.com"
	inj := "/anthropic=https://api.example.com,key-mode=inject,key-file=" + f.key
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"no auth", []string{"--route", route}, []string{"--auth is required"}},
		{"unknown auth", []string{"--auth", "mtls", "--route", route}, []string{"--auth must be none or static-tokens"}},
		{"none on a non-loopback listen", []string{"--auth", "none", "--listen", "0.0.0.0:8788", "--insecure-plaintext", "--route", route}, []string{"--auth none is only allowed on a loopback"}},
		{"none on an empty host", []string{"--auth", "none", "--listen", ":8788", "--insecure-plaintext", "--route", route}, []string{"--auth none is only allowed on a loopback"}},
		{"non-loopback without TLS", []string{"--auth", "static-tokens", "--tokens-file", f.tokens, "--listen", "0.0.0.0:8788", "--route", route}, []string{"not a loopback address", "--insecure-plaintext"}},
		{"static without a file", []string{"--auth", "static-tokens", "--route", route}, []string{"--auth static-tokens needs --tokens-file"}},
		{"file with none", []string{"--auth", "none", "--tokens-file", f.tokens, "--route", route}, []string{"--tokens-file is only valid with --auth static-tokens"}},
		{"cert without key", []string{"--auth", "none", "--tls-cert", f.cert, "--route", route}, []string{"--tls-cert and --tls-key must be given together"}},
		{"tls and insecure", []string{"--auth", "none", "--tls-cert", f.cert, "--tls-key", f.tlsKey, "--insecure-plaintext", "--route", route}, []string{"--insecure-plaintext conflicts"}},
		{"inject without a key file", []string{"--auth", "none", "--route", "/anthropic=https://api.example.com,key-mode=inject"}, []string{"key-mode=inject needs key-file"}},
		{"key file without inject", []string{"--auth", "none", "--route", route + ",key-file=" + f.key}, []string{"key-file is only valid with key-mode=inject"}},
		{"bad key mode", []string{"--auth", "none", "--route", route + ",key-mode=forward"}, []string{"key-mode must be passthrough or inject"}},
		{"inject, none, non-loopback", []string{"--auth", "none", "--listen", "0.0.0.0:8788", "--insecure-plaintext", "--route", inj},
			[]string{"key-mode=inject with --auth none needs a loopback", "--auth none is only allowed"}},
		{"missing key file", []string{"--auth", "none", "--route", route + ",key-mode=inject,key-file=" + filepath.Join(f.dir, "absent")}, []string{"key-file"}},
		{"empty key file", []string{"--auth", "none", "--route", route + ",key-mode=inject,key-file=" + emptyKey}, []string{"key file is empty"}},
		{"bad tokens file", []string{"--auth", "static-tokens", "--tokens-file", badTokens, "--route", route}, []string{"tokens line 1:", "tokens line 2:"}},
		{"missing tokens file", []string{"--auth", "static-tokens", "--tokens-file", filepath.Join(f.dir, "absent"), "--route", route}, []string{"--tokens-file"}},
		{"bad terms", []string{"--auth", "none", "--terms", badTerms, "--route", route}, []string{"terms line 1:", "terms line 2:"}},
		{"no routes", []string{"--auth", "none"}, []string{"no routes"}},
		{"reserved prefix", []string{"--auth", "none", "--route", "/t=https://x.example,api=openai"}, []string{"reserved"}},
		{"bad upstream", []string{"--auth", "none", "--route", "/anthropic=ftp://x.example"}, []string{"not an absolute http(s) URL"}},
		{"unknown provider", []string{"--auth", "none", "--provider", "nosuch"}, []string{"not a known provider"}},
		{"bad listen", []string{"--auth", "none", "--listen", "nonsense", "--route", route}, []string{"--listen"}},
		{"bad port", []string{"--auth", "none", "--listen", "127.0.0.1:99999", "--route", route}, []string{"invalid port"}},
		{"chain ttl", []string{"--auth", "none", "--chain-ttl", "0s", "--route", route}, []string{"--chain-ttl must be positive"}},
		{"chain max", []string{"--auth", "none", "--chain-max", "0", "--route", route}, []string{"--chain-max must be positive"}},
		{"shutdown timeout", []string{"--auth", "none", "--shutdown-timeout", "-1s", "--route", route}, []string{"--shutdown-timeout must be positive"}},
		{"peers without peer-self", []string{"--auth", "static-tokens", "--tokens-file", f.tokens, "--listen", "0.0.0.0:8788", "--tls-cert", f.cert, "--tls-key", f.tlsKey, "--peers", "peers.svc:8788", "--route", route}, []string{"--peers needs --peer-self"}},
		{"peer-self without peers", []string{"--auth", "none", "--peer-self", "10.0.0.1", "--route", route}, []string{"--peer-self needs --peers"}},
		{"peers on a loopback listen", []string{"--auth", "none", "--peers", "peers.svc:8788", "--peer-self", "10.0.0.1", "--route", route}, []string{"--peers needs a non-loopback --listen"}},
		{"peers without TLS", []string{"--auth", "static-tokens", "--tokens-file", f.tokens, "--listen", "0.0.0.0:8788", "--peers", "peers.svc:8788", "--peer-self", "10.0.0.1", "--route", route}, []string{"not a loopback address", "--insecure-plaintext"}},
		{"peers without a port", []string{"--auth", "static-tokens", "--tokens-file", f.tokens, "--listen", "0.0.0.0:8788", "--insecure-plaintext", "--peers", "peers.svc", "--peer-self", "10.0.0.1", "--route", route}, []string{"--peers/--peer-self:", "is not HOST:PORT"}},
		{"peer-self not an IP", []string{"--auth", "static-tokens", "--tokens-file", f.tokens, "--listen", "0.0.0.0:8788", "--insecure-plaintext", "--peers", "peers.svc:8788", "--peer-self", "pod-1", "--route", route}, []string{"--peers/--peer-self:", "is not an IP address"}},
		{"expired cert", []string{"--auth", "none", "--tls-cert", func() string { c, _ := selfSigned(t, f.dir, "old", time.Now().Add(-time.Hour)); return c }(), "--tls-key", filepath.Join(f.dir, "old.key"), "--route", route}, []string{"expired"}},
		{"mismatched key", []string{"--auth", "none", "--tls-cert", f.cert, "--tls-key", func() string { _, k := selfSigned(t, f.dir, "other", time.Now().Add(time.Hour)); return k }(), "--route", route}, []string{"tls pair"}},
	}
	for _, c := range cases {
		codeC, outC, errC := runCLI(t, "", append([]string{"check"}, c.args...)...)
		codeS, outS, errS := runCLI(t, "", append([]string{"serve"}, c.args...)...)
		if codeC != 1 || codeS != 1 || outC != "" {
			t.Errorf("%s: check=%d serve=%d stdout=%q", c.name, codeC, codeS, outC)
			continue
		}
		if errC != errS || outS != "" {
			t.Errorf("%s: serve and check disagree:\ncheck: %q\nserve: %q", c.name, errC, errS)
		}
		for _, w := range c.want {
			if !strings.Contains(errC, w) {
				t.Errorf("%s: message lacks %q:\n%s", c.name, w, errC)
			}
		}
		for _, secret := range []string{testRealK, testTokA, proxy.HashToken(testTokA), "bluebird", "Acme"} {
			if strings.Contains(errC, secret) {
				t.Errorf("%s: message leaks %q", c.name, secret)
			}
		}
	}
}

func TestServeConfigListsEveryProblem(t *testing.T) {
	_, _, errb := runCLI(t, "", "check", "--listen", "0.0.0.0:8788", "--auth", "none", "--chain-max", "0", "--route", "/nosuch=http://x", "--provider", "nosuch")
	if !strings.Contains(errb, "(5 problems):") && !strings.Contains(errb, "(4 problems):") {
		t.Errorf("not every problem listed:\n%s", errb)
	}
	for _, w := range []string{"not a loopback", "--auth none is only allowed", "--chain-max", "--route /nosuch", "not a known provider"} {
		if !strings.Contains(errb, w) {
			t.Errorf("missing %q:\n%s", w, errb)
		}
	}
}

func TestServeUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"serve", "--bogus"},
		{"serve", "--auth", "none", "extra"},
		{"check", "--anthropic-key-mode", "inject"}, // vendor-named flags do not exist
		{"serve", "--openai-upstream", "http://x"},
		{"serve", "--chain-ttl", "soon"},
	} {
		code, out, errb := runCLI(t, "", args...)
		if code != 2 || out != "" || !strings.Contains(errb, "usage:") {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out, errb)
		}
	}
}

// --- check ---

func TestCheckOK(t *testing.T) {
	f := newFixtures(t)
	code, out, errb := runCLI(t, "", "check", "--auth", "static-tokens", "--tokens-file", f.tokens, "--listen", "0.0.0.0:8443",
		"--tls-cert", f.cert, "--tls-key", f.tlsKey, "--terms", f.terms,
		"--route", "/anthropic=https://api.example.com,key-mode=inject,key-file="+f.key,
		"--route", "/openai=https://api.example.org/v1", "--provider", "ollama")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	want := regexp.MustCompile(`^ok: routes anthropic\(inject\) openai\(passthrough\) ollama\(passthrough\); auth static-tokens \(3 tokens\); metrics /metrics; terms 4 in 2 sections; tls expires \d{4}-\d{2}-\d{2}\n$`)
	if !want.MatchString(out) {
		t.Errorf("summary = %q", out)
	}
	for _, leak := range []string{testRealK, testTokA, testTokB, proxy.HashToken(testTokA), "bluebird", "Orion", "Acme", f.key, f.terms, "api.example.com"} {
		if strings.Contains(out, leak) {
			t.Errorf("summary leaks %q: %s", leak, out)
		}
	}
}

func TestCheckOKWithPeers(t *testing.T) {
	f := newFixtures(t)
	for _, tlsArgs := range [][]string{{"--tls-cert", f.cert, "--tls-key", f.tlsKey}, {"--insecure-plaintext"}} {
		args := append([]string{"check", "--auth", "static-tokens", "--tokens-file", f.tokens, "--listen", "0.0.0.0:8443",
			"--route", "/anthropic=https://api.example.com", "--peers", "nospy-peers.apps.svc:8443", "--peer-self", "10.0.3.7"}, tlsArgs...)
		code, out, _ := runCLI(t, "", args...)
		if code != 0 || !strings.Contains(out, "; peers nospy-peers.apps.svc:8443\n") {
			t.Errorf("%v: code=%d out=%q", tlsArgs, code, out)
		}
	}
}

func TestCheckOKPlaintextLoopback(t *testing.T) {
	code, out, _ := runCLI(t, "", "check", "--auth", "none", "--route", "/anthropic=https://api.example.com")
	if code != 0 || out != "ok: routes anthropic(passthrough); auth none; metrics /metrics; plaintext\n" {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestCheckWarnsWhenCertExpiresSoon(t *testing.T) {
	f := newFixtures(t)
	soon, soonKey := selfSigned(t, f.dir, "soon", time.Now().Add(10*24*time.Hour))
	code, out, errb := runCLI(t, "", "check", "--auth", "none", "--tls-cert", soon, "--tls-key", soonKey, "--route", "/anthropic=https://api.example.com")
	if code != 0 || !strings.HasPrefix(out, "ok:") || !strings.Contains(errb, "warning: the TLS certificate expires on") {
		t.Errorf("code=%d out=%q err=%q", code, out, errb)
	}
	// A healthy certificate doesn't warn.
	_, _, errb = runCLI(t, "", "check", "--auth", "none", "--tls-cert", f.cert, "--tls-key", f.tlsKey, "--route", "/anthropic=https://api.example.com")
	if errb != "" {
		t.Errorf("warned on a healthy certificate: %q", errb)
	}
}

func TestCheckWarnsOnPlaintextUpstreamKeyInjection(t *testing.T) {
	f := newFixtures(t)
	code, _, errb := runCLI(t, "", "check", "--auth", "none", "--route", "/myllm=http://llm.internal.example/v1,api=openai,key-mode=inject,key-file="+f.key)
	if code != 0 || !strings.Contains(errb, "injects its key into plaintext http") {
		t.Errorf("code=%d err=%q", code, errb)
	}
	_, _, errb = runCLI(t, "", "check", "--auth", "none", "--route", "/myllm=http://127.0.0.1:4000/v1,api=openai,key-mode=inject,key-file="+f.key)
	if errb != "" {
		t.Errorf("warned for a loopback upstream: %q", errb)
	}
}

// Vendor names appear only as values: no vendor-named flags, and the serve help text says "LLM".
func TestServeHelpIsProviderAgnostic(t *testing.T) {
	for _, cmd := range []string{"serve", "check", "hash-token"} {
		code, out, _ := runCLI(t, "", "help", cmd)
		if code != 0 || !strings.Contains(out, "usage: nospy "+cmd) {
			t.Fatalf("%s: code=%d", cmd, code)
		}
		flags, _, _ := strings.Cut(out, "\nExamples:")
		flags = strings.ReplaceAll(flags, "api="+apiNames(), "")
		for _, vendor := range []string{"anthropic", "openai", "ollama", "claude", "gpt"} {
			if strings.Contains(strings.ToLower(flags), vendor) {
				t.Errorf("%s help names a vendor (%s):\n%s", cmd, vendor, flags)
			}
		}
		for _, bad := range []string{"-anthropic-", "-openai-"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s help has a vendor-named flag %s", cmd, bad)
			}
		}
	}
	_, out, _ := runCLI(t, "", "help", "serve")
	for _, flag := range []string{"-listen", "-auth", "-tokens-file", "-tls-cert", "-tls-key", "-insecure-plaintext", "-route", "-provider", "-terms", "-chain-ttl", "-chain-max", "-shutdown-timeout", "-peers", "-peer-self"} {
		if !strings.Contains(out, flag) {
			t.Errorf("serve help lacks %s", flag)
		}
	}
}

// --- hash-token ---

func TestHashToken(t *testing.T) {
	code, out, errb := runCLI(t, "", "hash-token", "--name", "ci-runner")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	tokRe := regexp.MustCompile(`(?m)^  (nspy_[A-Za-z0-9_-]{43})$`)
	lineRe := regexp.MustCompile(`(?m)^  (ci-runner:[0-9a-f]{64})$`)
	tm, lm := tokRe.FindStringSubmatch(out), lineRe.FindStringSubmatch(out)
	if tm == nil || lm == nil || !strings.Contains(out, "Token (shown once") || !strings.Contains(out, "Tokens-file line") {
		t.Fatalf("unexpected output:\n%s", out)
	}
	// The printed line must verify the printed token through the real loader.
	path := wfile(t, t.TempDir(), "tokens", lm[1]+"\n")
	st, err := proxy.LoadStaticTokens(path, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := st.Authenticate(nil, tm[1]); c != "ci-runner" || err != nil {
		t.Errorf("printed line does not verify the printed token: %q %v", c, err)
	}
	// And each run makes a different token.
	_, out2, _ := runCLI(t, "", "hash-token", "--name", "ci-runner")
	if tokRe.FindStringSubmatch(out2)[1] == tm[1] {
		t.Error("two runs produced the same token")
	}
	// A proxy token pasted into a prompt is redacted like any key.
	_, red, _ := runCLI(t, "run with "+tm[1], "scan")
	if strings.Contains(red, tm[1]) || !strings.Contains(red, "[REDACTED_TOKEN_1]") {
		t.Errorf("scan left the proxy token: %q", red)
	}
}

func TestHashTokenStdin(t *testing.T) {
	code, out, errb := runCLI(t, "  "+testTokA+"\n", "hash-token", "--name", "alice", "--stdin")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	if strings.Contains(out, testTokA) || !strings.Contains(out, "  alice:"+proxy.HashToken(testTokA)+"\n") {
		t.Errorf("output:\n%s", out)
	}
	for _, in := range []string{"", "\n", "two words", "a\nb"} {
		code, out, errb := runCLI(t, in, "hash-token", "--name", "alice", "--stdin")
		if code != 2 || out != "" || !strings.Contains(errb, "stdin must hold one token") {
			t.Errorf("stdin %q: code=%d out=%q err=%q", in, code, out, errb)
		}
	}
}

func TestHashTokenBadName(t *testing.T) {
	for _, args := range [][]string{
		{"hash-token"}, {"hash-token", "--name", ""}, {"hash-token", "--name", "Alice"}, {"hash-token", "--name", "-a"},
		{"hash-token", "--name", "a_b"}, {"hash-token", "--name", "a:b"}, {"hash-token", "--name", "a b"}, {"hash-token", "--name", "ok", "extra"},
	} {
		code, out, errb := runCLI(t, "", args...)
		if code != 2 || out != "" || !strings.Contains(errb, "usage:") {
			t.Errorf("%v: code=%d out=%q err=%q", args, code, out, errb)
		}
	}
}

// --- the wrapper refuses serve-only route options ---

func TestWrapperRejectsKeyModeOptions(t *testing.T) {
	for _, v := range []string{"/anthropic=http://x,key-mode=passthrough", "/anthropic=http://x,key-mode=inject,key-file=/k"} {
		code, _, errb := runCLI(t, "", "--route", v, "--", "true")
		if code != 2 || !strings.Contains(errb, "only valid for `nospy serve`") {
			t.Errorf("%s: code=%d err=%q", v, code, errb)
		}
	}
}

// --- running servers ---

// startServe builds a config from args exactly as `nospy serve` does and serves it on a loopback
// listener until the returned cancel is called. done receives serve's exit code.
func startServe(t *testing.T, args ...string) (addr string, cancel func(), done chan int, logs *syncBuffer) {
	t.Helper()
	logs = &syncBuffer{}
	log := slog.New(slog.NewJSONHandler(logs, nil))
	var out, errb bytes.Buffer
	cfg, code := prepareServe("serve", args, &out, &errb, log, time.Now)
	if cfg == nil {
		t.Fatalf("config rejected (%d): %s", code, errb.String())
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancelCtx := context.WithCancel(context.Background())
	done = make(chan int, 1)
	fin := make(chan struct{})
	go func() { done <- serveUntil(ctx, cfg, ln, log, io.Discard); close(fin) }()
	t.Cleanup(func() {
		cancelCtx()
		select {
		case <-fin:
		case <-time.After(5 * time.Second):
		}
	})
	return ln.Addr().String(), cancelCtx, done, logs
}

var phRe = regexp.MustCompile(`\[REDACTED_[A-Z][A-Z0-9_]*_\d+\]`)

const secretEmail = "alice@corp.io"

func msgBody(stream bool) string {
	b, _ := json.Marshal(map[string]any{"model": "m", "stream": stream,
		"messages": []any{map[string]any{"role": "user", "content": "mail " + secretEmail + " and ssh 10.20.30.40 please"}}})
	return string(b)
}

// echoUpstream answers every Messages request with the placeholders it saw, and records what
// reached it.
type echoUpstream struct {
	mu     sync.Mutex
	bodies []string
	hdrs   []http.Header
}

func (u *echoUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.bodies, u.hdrs = append(u.bodies, string(b)), append(u.hdrs, r.Header.Clone())
	u.mu.Unlock()
	echo := strings.Join(phRe.FindAllString(noNote(b), -1), " ")
	out, _ := json.Marshal(map[string]any{"type": "message", "content": []any{map[string]any{"type": "text", "text": "saw " + echo}}})
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(out)
}

func (u *echoUpstream) seen() ([]string, []http.Header) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string(nil), u.bodies...), append([]http.Header(nil), u.hdrs...)
}

func doReq(t *testing.T, c *http.Client, method, url, body string, hdr map[string]string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// Without TLS the listener speaks h2c next to HTTP/1.1, so peers forward over HTTP/2 and their
// connections get pings (plan/24-peer-liveness.md); an HTTP/1.1 client is unaffected.
func TestServePlaintextSpeaksH2CAndHTTP1(t *testing.T) {
	f := newFixtures(t)
	us := httptest.NewServer(&echoUpstream{})
	defer us.Close()
	addr, _, _, _ := startServe(t, "--auth", "static-tokens", "--tokens-file", f.tokens, "--insecure-plaintext",
		"--route", "/anthropic="+us.URL+",key-mode=inject,key-file="+f.key)
	for _, h2 := range []bool{false, true} {
		tr := &http.Transport{}
		if h2 {
			tr.Protocols = new(http.Protocols)
			tr.Protocols.SetUnencryptedHTTP2(true)
		}
		c := &http.Client{Transport: tr}
		resp, err := c.Get("http://" + addr + "/healthz")
		if err != nil {
			t.Fatalf("h2c=%v: %v", h2, err)
		}
		_ = resp.Body.Close()
		if want := map[bool]int{false: 1, true: 2}[h2]; resp.StatusCode != 200 || resp.ProtoMajor != want {
			t.Errorf("h2c=%v: status %d over HTTP/%d, want 200 over HTTP/%d", h2, resp.StatusCode, resp.ProtoMajor, want)
		}
		tr.CloseIdleConnections()
	}
}

func TestServeEndToEndStaticTokensAndInject(t *testing.T) {
	f := newFixtures(t)
	up := &echoUpstream{}
	us := httptest.NewServer(up)
	defer us.Close()
	addr, cancel, done, logs := startServe(t, "--auth", "static-tokens", "--tokens-file", f.tokens,
		"--route", "/anthropic="+us.URL+",key-mode=inject,key-file="+f.key,
		"--route", "/pass="+us.URL+",api=anthropic")
	base := "http://" + addr
	c := http.DefaultClient

	if code, body := doReq(t, c, "GET", base+"/healthz", "", nil); code != 200 || !strings.HasPrefix(body, "ok") {
		t.Errorf("healthz: %d %q", code, body)
	}
	if code, _ := doReq(t, c, "GET", base+"/readyz", "", nil); code != 200 {
		t.Errorf("readyz: %d", code)
	}
	// Without a token, or with a wrong one, nothing is forwarded.
	if code, _ := doReq(t, c, "POST", base+"/anthropic/v1/messages", msgBody(false), nil); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _ := doReq(t, c, "POST", base+"/anthropic/v1/messages", msgBody(false), map[string]string{"x-api-key": testClient}); code != 401 {
		t.Errorf("a real-looking key that is not a proxy token: %d", code)
	}
	if code, _ := doReq(t, c, "POST", base+"/pass/v1/messages", msgBody(false), map[string]string{"x-api-key": testClient}); code != 401 {
		t.Errorf("passthrough without a proxy token: %d", code)
	}
	if bodies, _ := up.seen(); len(bodies) != 0 {
		t.Fatalf("upstream reached by unauthenticated requests: %d", len(bodies))
	}

	// Inject: the proxy token in x-api-key; the secret never arrives; the client gets it back.
	code, body := doReq(t, c, "POST", base+"/anthropic/v1/messages", msgBody(false), map[string]string{"x-api-key": testTokA, "Authorization": "Bearer " + testClient})
	if code != 200 || !strings.Contains(body, secretEmail) || phRe.MatchString(body) {
		t.Errorf("inject: %d %s", code, body)
	}
	// Passthrough: the client's own key goes up; the path token is stripped.
	code, body = doReq(t, c, "POST", base+"/t/"+testTokB+"/pass/v1/messages", msgBody(false), map[string]string{"x-api-key": testClient})
	if code != 200 || !strings.Contains(body, secretEmail) {
		t.Errorf("passthrough: %d %s", code, body)
	}
	bodies, hdrs := up.seen()
	if len(bodies) != 2 {
		t.Fatalf("upstream calls = %d", len(bodies))
	}
	for _, b := range bodies {
		if strings.Contains(b, secretEmail) || strings.Contains(b, "10.20.30.40") {
			t.Errorf("a secret reached the upstream: %s", b)
		}
	}
	if hdrs[0].Get("X-Api-Key") != testRealK || hdrs[0].Get("Authorization") != "" {
		t.Errorf("inject headers upstream: %v", hdrs[0])
	}
	if hdrs[1].Get("X-Api-Key") != testClient || hdrs[1].Get("X-Nospy-Token") != "" {
		t.Errorf("passthrough headers upstream: %v", hdrs[1])
	}

	cancel()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code %d", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not stop")
	}
	// Logs: one JSON line per request with the client; no credentials or values.
	var sawAlice, sawBob, saw401 bool
	for _, line := range strings.Split(strings.TrimSpace(logs.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line is not JSON: %q", line)
		}
		if m["msg"] == "request" {
			sawAlice = sawAlice || m["client"] == "alice"
			sawBob = sawBob || m["client"] == "bob" && m["path"] == "/pass/v1/messages"
			saw401 = saw401 || m["status"] == float64(401)
		}
	}
	if !sawAlice || !sawBob || !saw401 {
		t.Errorf("request log lines missing (alice=%v bob=%v 401=%v):\n%s", sawAlice, sawBob, saw401, logs.String())
	}
	for _, leak := range []string{testTokA, testTokB, testRealK, testClient, secretEmail, "/t/", "bluebird"} {
		if strings.Contains(logs.String(), leak) {
			t.Errorf("logs contain %q", leak)
		}
	}
	if !strings.Contains(logs.String(), `"msg":"serve"`) || !strings.Contains(logs.String(), `"tokens":3`) {
		t.Errorf("no startup line:\n%s", logs.String())
	}
}

func TestServeNoneAuthInjectOnLoopback(t *testing.T) {
	f := newFixtures(t)
	up := &echoUpstream{}
	us := httptest.NewServer(up)
	defer us.Close()
	addr, _, _, _ := startServe(t, "--auth", "none", "--route", "/anthropic="+us.URL+",key-mode=inject,key-file="+f.key)
	code, body := doReq(t, http.DefaultClient, "POST", "http://"+addr+"/anthropic/v1/messages", msgBody(false), map[string]string{"x-api-key": "anything"})
	if code != 200 || !strings.Contains(body, secretEmail) {
		t.Fatalf("%d %s", code, body)
	}
	_, hdrs := up.seen()
	if hdrs[0].Get("X-Api-Key") != testRealK {
		t.Errorf("upstream key = %q", hdrs[0].Get("X-Api-Key"))
	}
}

func TestServeTLSAndTerms(t *testing.T) {
	f := newFixtures(t)
	up := &echoUpstream{}
	us := httptest.NewServer(up)
	defer us.Close()
	addr, _, _, _ := startServe(t, "--auth", "none", "--tls-cert", f.cert, "--tls-key", f.tlsKey, "--terms", f.terms, "--route", "/anthropic="+us.URL)
	pem, _ := os.ReadFile(f.cert)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	body := `{"messages":[{"role":"user","content":"the bluebird project for Acme Corp"}]}`
	code, _ := doReq(t, c, "POST", "https://"+addr+"/anthropic/v1/messages", body, nil)
	if code != 200 {
		t.Fatalf("status %d", code)
	}
	bodies, _ := up.seen()
	if len(bodies) != 1 || strings.Contains(bodies[0], "bluebird") || strings.Contains(bodies[0], "Acme") {
		t.Errorf("terms reached upstream: %v", bodies)
	}
	if _, err := http.Get("http://" + addr + "/healthz"); err == nil {
		// Plain HTTP to a TLS port is answered with an error page, never the health body.
		t.Log("plain http to the TLS port got a response (expected a 400 from the TLS layer)")
	}
}

// sseUpstream streams a placeholder split across chunks and holds the stream open until released.
type sseUpstream struct {
	release chan struct{}
	started chan struct{}
}

func (u *sseUpstream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	ph := phRe.FindString(noNote(b))
	w.Header().Set("Content-Type", "text/event-stream")
	ev := func(text string) {
		j, _ := json.Marshal(text)
		_, _ = fmt.Fprintf(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":%s}}\n\n", j)
		w.(http.Flusher).Flush()
	}
	ev("mail ")
	ev(ph[:5])
	close(u.started)
	<-u.release
	ev(ph[5:])
	ev(" done")
}

func sseText(t *testing.T, body string) string {
	t.Helper()
	var out strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if d, ok := strings.CutPrefix(line, "data: "); ok {
			var m struct{ Delta struct{ Text string } }
			if err := json.Unmarshal([]byte(d), &m); err != nil {
				t.Fatal(err)
			}
			out.WriteString(m.Delta.Text)
		}
	}
	return out.String()
}

func TestServeSIGTERMDrainsOpenStream(t *testing.T) {
	up := &sseUpstream{release: make(chan struct{}), started: make(chan struct{})}
	us := httptest.NewServer(up)
	defer us.Close()
	addr, cancel, done, logs := startServe(t, "--auth", "none", "--shutdown-timeout", "10s", "--route", "/anthropic="+us.URL)

	result := make(chan string, 1)
	go func() {
		req, _ := http.NewRequest("POST", "http://"+addr+"/anthropic/v1/messages", strings.NewReader(msgBody(true)))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			result <- "error: " + err.Error()
			return
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			result <- "error: " + err.Error()
			return
		}
		result <- string(b)
	}()
	select {
	case <-up.started:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not start")
	}
	cancel() // SIGTERM arrives with the stream open

	// Draining: readiness fails or the listener is gone, and no new work is accepted.
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := http.Get("http://" + addr + "/readyz")
		if err != nil {
			break
		}
		_ = resp.Body.Close()
		if resp.StatusCode == 503 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server kept reporting ready after SIGTERM")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case code := <-done:
		t.Fatalf("serve exited (%d) while a stream was open", code)
	case <-time.After(100 * time.Millisecond):
	}

	close(up.release)
	select {
	case got := <-result:
		if text := sseText(t, got); text != "mail "+secretEmail+" done" && !strings.Contains(text, secretEmail) {
			t.Errorf("stream was cut or not restored: %q (%s)", text, got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream did not complete")
	}
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("exit code %d after a clean drain", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not exit after the drain")
	}
	if !strings.Contains(logs.String(), `"msg":"stopped"`) {
		t.Errorf("logs: %s", logs.String())
	}
}

func TestServeShutdownTimeoutClosesStuckStream(t *testing.T) {
	up := &sseUpstream{release: make(chan struct{}), started: make(chan struct{})}
	us := httptest.NewServer(up)
	defer us.Close()
	defer close(up.release)
	addr, cancel, done, _ := startServe(t, "--auth", "none", "--shutdown-timeout", "200ms", "--route", "/anthropic="+us.URL)
	go func() {
		req, _ := http.NewRequest("POST", "http://"+addr+"/anthropic/v1/messages", strings.NewReader(msgBody(true)))
		req.Header.Set("Content-Type", "application/json")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-up.started:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not start")
	}
	cancel()
	select {
	case code := <-done:
		if code != exitFail {
			t.Errorf("forced close should exit %d, got %d", exitFail, code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not give up after --shutdown-timeout")
	}
}

// noNote drops the placeholder note from a request body: its example placeholder is not a value
// the vault issued, so echoing upstreams must not see it.
func noNote(b []byte) string { return strings.ReplaceAll(string(b), payload.PlaceholderNote, "") }
