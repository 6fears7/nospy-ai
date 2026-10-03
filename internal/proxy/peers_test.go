package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nospyai/internal/redact"
)

func TestRendezvousOwner(t *testing.T) {
	nodes := []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"}
	owners := map[string]string{}
	counts := map[string]int{}
	for i := range 1000 {
		key := fmt.Sprintf("client-%d\x00/anthropic", i)
		o := rendezvousOwner(nodes, key)
		if o != rendezvousOwner(nodes, key) {
			t.Fatal("not deterministic")
		}
		owners[key] = o
		counts[o]++
	}
	for _, n := range nodes {
		if counts[n] < 250 || counts[n] > 420 {
			t.Errorf("node %s owns %d of 1000 clients: %v", n, counts[n], counts)
		}
	}
	// The route is part of the key: clients don't all move together from one route to another.
	moved := 0
	for i := range 1000 {
		if rendezvousOwner(nodes, fmt.Sprintf("client-%d\x00/openai", i)) != owners[fmt.Sprintf("client-%d\x00/anthropic", i)] {
			moved++
		}
	}
	if moved == 0 {
		t.Error("route prefix does not affect the owner")
	}

	// Removing a node moves only that node's clients.
	rest := []string{"10.1.0.1", "10.1.0.3"}
	for key, was := range owners {
		now := rendezvousOwner(rest, key)
		if was != "10.1.0.2" && now != was {
			t.Fatalf("%q moved from %s to %s though its owner stayed", key, was, now)
		}
		if now == "10.1.0.2" {
			t.Fatalf("%q still owned by the removed node", key)
		}
	}
	// Adding one takes clients only for itself.
	more := append(slices.Clone(nodes), "10.1.0.4")
	for key, was := range owners {
		if now := rendezvousOwner(more, key); now != was && now != "10.1.0.4" {
			t.Fatalf("%q moved between old nodes: %s -> %s", key, was, now)
		}
	}
	if rendezvousOwner(nil, "k") != "" {
		t.Error("empty set has an owner")
	}
}

func TestNewPeersValidation(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	for _, c := range []struct{ addr, self string }{
		{"", "10.0.0.1"}, {"peers.svc", "10.0.0.1"}, {":8788", "10.0.0.1"}, {"peers.svc:0", "10.0.0.1"},
		{"peers.svc:http", "10.0.0.1"}, {"peers.svc:70000", "10.0.0.1"}, {"peers.svc:8788", ""}, {"peers.svc:8788", "pod-1"},
	} {
		if _, err := NewPeers(c.addr, c.self, nil, log); err == nil {
			t.Errorf("NewPeers(%q, %q) accepted", c.addr, c.self)
		}
	}
	if _, err := NewPeers("peers.svc:8788", "10.0.0.1", nil, log); err != nil {
		t.Error(err)
	}
	if _, err := NewPeers("peers.svc:8788", "fd00::1", nil, log); err != nil {
		t.Error(err)
	}
}

// TestNewPeersLiveness pins the liveness settings of the transport NewPeers builds, so the
// tests that tune p.tr afterwards can't mask a missing HTTP2 config or handshake timeout.
func TestNewPeersLiveness(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certPath, keyPath := writeCert(t, dir, "shared", now.Add(-time.Hour), now.Add(24*time.Hour))
	log := slog.New(slog.DiscardHandler)
	tlsCerts, err := LoadCertFiles(certPath, keyPath, log, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		certs *CertFiles
	}{{"tls", tlsCerts}, {"plain", nil}} {
		t.Run(c.name, func(t *testing.T) {
			p, err := NewPeers("peers.svc:8788", "10.0.0.1", c.certs, log)
			if err != nil {
				t.Fatal(err)
			}
			if p.tr.HTTP2 == nil {
				t.Fatal("transport has no HTTP2 config, so peer connections get no pings")
			}
			if got := p.tr.HTTP2.SendPingTimeout; got != peerPingAfter {
				t.Errorf("SendPingTimeout = %v, want %v", got, peerPingAfter)
			}
			if got := p.tr.HTTP2.PingTimeout; got != peerPingTimeout {
				t.Errorf("PingTimeout = %v, want %v", got, peerPingTimeout)
			}
			if got := p.tr.TLSHandshakeTimeout; got != peerHandshakeTimeout {
				t.Errorf("TLSHandshakeTimeout = %v, want %v", got, peerHandshakeTimeout)
			}
		})
	}
}

func TestPeersRefresh(t *testing.T) {
	var logs syncBuf
	p, err := NewPeers("peers.svc:8788", "10.0.0.2", nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	var lerr error
	p.lookup = func(_ context.Context, host string) ([]string, error) {
		if host != "peers.svc" {
			t.Errorf("looked up %q", host)
		}
		return addrs, lerr
	}
	forwarded := func() (n int) {
		for i := range 200 {
			if ip, ok := p.Owner(fmt.Sprintf("c%d", i), "/x"); ok {
				if ip == "10.0.0.2" {
					t.Fatal("forwarded to itself")
				}
				n++
			}
		}
		return
	}
	ctx := context.Background()

	if forwarded() != 0 { // no set yet
		t.Error("forwarded before the first lookup")
	}
	addrs = []string{"10.0.0.1", "10.0.0.3"} // this pod is not listed (not ready yet)
	p.refresh(ctx)
	if forwarded() != 0 {
		t.Error("forwarded while this pod is not in the set")
	}
	addrs = []string{"10.0.0.3", "::ffff:10.0.0.2", "10.0.0.1", "junk", "10.0.0.1"} // mapped, unsorted, duplicate, unparsable
	p.refresh(ctx)
	if n := forwarded(); n < 100 || n > 160 { // two thirds
		t.Errorf("forwarded %d of 200 with 3 peers", n)
	}
	if got := p.set.Load().ips; !slices.Equal(got, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}) {
		t.Errorf("set = %v", got)
	}

	// An error keeps the last good set and warns once, not on every lookup.
	lerr = errors.New("no such host")
	p.refresh(ctx)
	p.refresh(ctx)
	if n := forwarded(); n == 0 {
		t.Error("the set was dropped on a lookup error")
	}
	if c := strings.Count(logs.String(), "peer lookup failed"); c != 1 {
		t.Errorf("lookup failure logged %d times:\n%s", c, logs.String())
	}
	lerr = nil
	addrs = []string{"10.0.0.2"}
	p.refresh(ctx)
	if !strings.Contains(logs.String(), "works again") {
		t.Errorf("recovery not logged:\n%s", logs.String())
	}
	if forwarded() != 0 {
		t.Error("a pod alone forwarded")
	}
	assertNoSecretInLogs(t, logs.String(), "client")
}

// --- two or three replicas in one process ---

type peerPod struct {
	ip     string
	srv    *httptest.Server
	chains *ChainStore
	known  *KnownStore
	peers  *Peers
	logs   *syncBuf
}

type peerCluster struct {
	pods   []*peerPod
	ips    []string
	anth   *fakeUpstream
	oai    *fakeOpenAI
	client *http.Client

	mu     sync.Mutex
	addr   map[string]string // fake pod IP -> the test server's real address
	down   map[string]bool
	dials  map[string]int // fake pod IP -> connection attempts made to it
	frozen map[string]bool
	closed map[string]int   // fake pod IP -> connections to it that were closed
	protos map[string][]int // fake pod IP -> ProtoMajor of each forwarded request it received
}

// freezeConn is a connection to a pod whose process was stopped (SIGSTOP, a hung node): once the
// pod is frozen, Read blocks until Close, and Write reports success and discards. That holds for
// connections opened before the freeze and after it, so a TLS handshake stalls too.
type freezeConn struct {
	net.Conn
	c      *peerCluster
	ip     string
	done   chan struct{}
	closer sync.Once
}

func (f *freezeConn) isFrozen() bool {
	f.c.mu.Lock()
	defer f.c.mu.Unlock()
	return f.c.frozen[f.ip]
}

func (f *freezeConn) Read(b []byte) (int, error) {
	if f.isFrozen() {
		<-f.done
		return 0, net.ErrClosed
	}
	n, err := f.Conn.Read(b)
	if f.isFrozen() { // data that arrived after the freeze is never seen
		<-f.done
		return 0, net.ErrClosed
	}
	return n, err
}

func (f *freezeConn) Write(b []byte) (int, error) {
	if f.isFrozen() {
		return len(b), nil
	}
	return f.Conn.Write(b)
}

func (f *freezeConn) Close() error {
	f.closer.Do(func() {
		close(f.done)
		f.c.mu.Lock()
		f.c.closed[f.ip]++
		f.c.mu.Unlock()
	})
	return f.Conn.Close()
}

type clusterOpts struct {
	plain    bool         // peers and listeners use plain HTTP
	ownCert  int          // 1-based pod that gets a certificate of its own; 0: all share one
	anthHdlr http.Handler // replaces the fake Anthropic upstream

	// Per-test liveness timings, in place of the production ones (plan/24-peer-liveness.md); zero
	// keeps the default. Set before any request, because the transport reads them on first use.
	pingAfter, pingTimeout, handshake time.Duration
	anthDelay                         time.Duration // the fake Anthropic upstream answers this late
}

func newPeerCluster(t *testing.T, n int, o clusterOpts) *peerCluster {
	t.Helper()
	c := &peerCluster{anth: &fakeUpstream{}, oai: &fakeOpenAI{}, addr: map[string]string{}, down: map[string]bool{}, dials: map[string]int{},
		frozen: map[string]bool{}, closed: map[string]int{}, protos: map[string][]int{},
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}}
	t.Cleanup(c.client.CloseIdleConnections)
	var anthH http.Handler = c.anth
	if o.anthHdlr != nil {
		anthH = o.anthHdlr
	}
	if o.anthDelay > 0 {
		inner := anthH
		anthH = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(o.anthDelay)
			inner.ServeHTTP(w, r)
		})
	}
	aUp, oUp := httptest.NewServer(anthH), httptest.NewServer(c.oai)
	t.Cleanup(aUp.Close)
	t.Cleanup(oUp.Close)
	au, _ := url.Parse(aUp.URL)
	ou, _ := url.Parse(oUp.URL + "/v1")

	dir := t.TempDir()
	now := time.Now()
	sharedCert, sharedKey := writeCert(t, dir, "shared", now.Add(-time.Hour), now.Add(24*time.Hour))
	ownCert, ownKey := writeCert(t, dir, "own", now.Add(-time.Hour), now.Add(24*time.Hour))
	tokens := tokensFile(t, "a:"+HashToken(tokA), "b:"+HashToken(tokB))

	for i := range n {
		c.ips = append(c.ips, fmt.Sprintf("10.1.0.%d", i+1))
	}
	for i := range n {
		pod := &peerPod{ip: c.ips[i], chains: NewChainStore(0, 0), known: NewKnownStore(0, 0), logs: &syncBuf{}}
		log := slog.New(slog.NewJSONHandler(pod.logs, nil))
		certPath, keyPath := sharedCert, sharedKey
		if o.ownCert == i+1 {
			certPath, keyPath = ownCert, ownKey
		}
		var certs *CertFiles
		if !o.plain {
			var err error
			if certs, err = LoadCertFiles(certPath, keyPath, log, nil); err != nil {
				t.Fatal(err)
			}
		}
		var err error
		if pod.peers, err = NewPeers("peers.svc:8788", pod.ip, certs, log); err != nil {
			t.Fatal(err)
		}
		pod.peers.lookup = func(context.Context, string) ([]string, error) { return c.ips, nil }
		pod.peers.tr.DialContext = c.dial
		if o.pingAfter > 0 {
			pod.peers.tr.HTTP2.SendPingTimeout = o.pingAfter
		}
		if o.pingTimeout > 0 {
			pod.peers.tr.HTTP2.PingTimeout = o.pingTimeout
		}
		if o.handshake > 0 {
			pod.peers.tr.TLSHandshakeTimeout = o.handshake
		}
		pod.peers.refresh(context.Background())

		st, err := LoadStaticTokens(tokens, log)
		if err != nil {
			t.Fatal(err)
		}
		h, err := NewServer([]Route{
			{Prefix: "/anthropic", Upstream: au, Dialect: AnthropicDialect},
			{Prefix: "/openai", Upstream: ou, Dialect: OpenAIDialect},
		}, st, redact.NewDetector(redact.Config{}), log,
			WithChainStore(pod.chains), WithKnownStore(pod.known), WithPeers(pod.peers))
		if err != nil {
			t.Fatal(err)
		}
		pod.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get(PeerHeader) != "" {
				c.mu.Lock()
				c.protos[pod.ip] = append(c.protos[pod.ip], r.ProtoMajor)
				c.mu.Unlock()
			}
			h.ServeHTTP(w, r)
		}))
		if o.plain {
			// As serveUntil does without TLS: HTTP/1.1 for clients, h2c for peers.
			pod.srv.Config.Protocols = new(http.Protocols)
			pod.srv.Config.Protocols.SetHTTP1(true)
			pod.srv.Config.Protocols.SetUnencryptedHTTP2(true)
			pod.srv.Start()
		} else {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatal(err)
			}
			pod.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			pod.srv.EnableHTTP2 = true
			pod.srv.StartTLS()
		}
		t.Cleanup(pod.srv.Close)
		c.addr[pod.ip] = pod.srv.Listener.Addr().String()
		c.pods = append(c.pods, pod)
	}
	return c
}

// dial reaches a fake pod IP at its test server, unless the test took that pod down.
func (c *peerCluster) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, _ := net.SplitHostPort(addr)
	c.mu.Lock()
	c.dials[host]++
	real, ok, down := c.addr[host], c.addr[host] != "", c.down[host]
	c.mu.Unlock()
	if !ok || down {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("connection refused")}
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, network, real)
	if err != nil {
		return nil, err
	}
	return &freezeConn{Conn: conn, c: c, ip: host, done: make(chan struct{})}, nil
}

func (c *peerCluster) setDown(ip string) { c.mu.Lock(); c.down[ip] = true; c.mu.Unlock() }

// freeze stops the pod at ip: its connections, existing and new, stop answering but stay open.
func (c *peerCluster) freeze(ip string) { c.mu.Lock(); c.frozen[ip] = true; c.mu.Unlock() }

func (c *peerCluster) closedTo(ip string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed[ip]
}

// waitClosed waits until n connections to the pod have been closed by the transport.
func (c *peerCluster) waitClosed(t *testing.T, ip string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.closedTo(ip) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d connections to %s closed, want %d: the dead connection was never noticed", c.closedTo(ip), ip, n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *peerCluster) protoMajors(ip string) []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.protos[ip])
}

func (c *peerCluster) dialsTo(ip string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dials[ip]
}

// nextRanked is the index of the pod that owns the client on the route once pod skip is gone.
func (c *peerCluster) nextRanked(client, prefix string, skip int) int {
	rest := slices.DeleteFunc(slices.Clone(c.ips), func(ip string) bool { return ip == c.ips[skip] })
	return slices.Index(c.ips, rendezvousOwner(rest, client+"\x00"+prefix))
}

// testClock is a clock the test moves by hand.
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// ownerOf is the index of the pod that owns the client on the route.
func (c *peerCluster) ownerOf(client, prefix string) int {
	return slices.Index(c.ips, rendezvousOwner(c.ips, client+"\x00"+prefix))
}

// others returns the indexes of the pods that don't own the client on the route.
func (c *peerCluster) others(client, prefix string) []int {
	var out []int
	for i := range c.pods {
		if i != c.ownerOf(client, prefix) {
			out = append(out, i)
		}
	}
	return out
}

func (c *peerCluster) post(t *testing.T, pod int, path, body string, hdr map[string]string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", c.pods[pod].srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Nospy-Token", tokA)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// sendKnown sends a Messages request whose only content is the given text; it returns the
// client's reply.
func (c *peerCluster) sendKnown(t *testing.T, pod int, content string) string {
	t.Helper()
	body := `{"model":"claude-opus-5-5","system":"x","messages":[{"role":"user","content":` + jsonString(content) + `}]}`
	resp := c.post(t, pod, "/anthropic/v1/messages", body, nil)
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, out)
	}
	return string(out)
}

func (c *peerCluster) lastUpstream(t *testing.T) string {
	t.Helper()
	calls := c.anth.recorded()
	return noNote([]byte(calls[len(calls)-1].body))
}

func TestPeerForwardsToOwner(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprintf("plain=%v", plain), func(t *testing.T) {
			c := newPeerCluster(t, 3, clusterOpts{plain: plain})
			owner := c.ownerOf("a", "/anthropic")
			entry := c.others("a", "/anthropic")[0]
			resp := c.post(t, entry, "/anthropic/v1/messages?beta=true", messagesBody(false), map[string]string{"X-Api-Key": "client-key"})
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			assertRedactedAndRestored(t, c.anth, string(body))
			up := c.anth.recorded()[0]
			if up.path != "/v1/messages?beta=true" || up.hdr.Get("X-Api-Key") != "client-key" {
				t.Errorf("upstream saw %q, key %q", up.path, up.hdr.Get("X-Api-Key"))
			}
			for _, h := range []string{PeerHeader, TokenHeader} {
				if up.hdr.Get(h) != "" {
					t.Errorf("%s reached the upstream", h)
				}
			}

			// The owner served it (and logs counts); the entry pod only forwarded (and logs the peer).
			ol := requestLogs(t, c.pods[owner].logs, 1)
			el := requestLogs(t, c.pods[entry].logs, 1)
			if !strings.Contains(ol, `"redacted"`) || strings.Contains(ol, `"peer"`) {
				t.Errorf("owner log:\n%s", ol)
			}
			if !strings.Contains(el, `"peer":"`+c.ips[owner]+`"`) || strings.Contains(el, `"redacted"`) || !strings.Contains(el, `"client":"a"`) {
				t.Errorf("forwarding pod log:\n%s", el)
			}
			assertNoSecretInLogs(t, el+ol, tokA, "alice@corp.io", "hunter22")

			// Entering at the owner is not forwarded.
			_ = c.post(t, owner, "/anthropic/v1/messages", messagesBody(false), nil).Body.Close()
			if strings.Count(c.pods[owner].logs.String(), `"peer"`) != 0 {
				t.Error("the owner forwarded")
			}
		})
	}
}

// Step 19's two-request scenario, with each request entering a different pod.
func TestPeerKnownValuesAcrossPods(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	owner := c.ownerOf("a", "/anthropic")
	in := c.others("a", "/anthropic")
	const pw = "hunter2hunter2"
	c.sendKnown(t, in[0], "DB_PASSWORD="+pw+"\nHOST=h")
	if strings.Contains(c.lastUpstream(t), pw) {
		t.Fatal("request 1 leaked")
	}
	back := c.sendKnown(t, in[1], "the value is "+pw+" and mail a@corp.io")
	if up := c.lastUpstream(t); strings.Contains(up, pw) || !strings.Contains(up, "the value is [REDACTED_SECRET_1] and mail [REDACTED_EMAIL_1]") {
		t.Errorf("request 2 not redacted:\n%s", up)
	}
	if !strings.Contains(back, pw) || strings.Contains(back, "[REDACTED_") {
		t.Errorf("response not restored: %s", back)
	}
	for i, p := range c.pods {
		if got := p.known.Len("a", "/anthropic"); (i == owner) != (got > 0) {
			t.Errorf("pod %d (owner=%v) holds %d known values", i, i == owner, got)
		}
	}
}

func TestPeerResponsesChainAcrossPods(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			c := newPeerCluster(t, 3, clusterOpts{})
			in := c.others("a", "/openai")
			first := c.post(t, in[0], "/openai/v1/responses", responsesBody(stream, "", ""), nil)
			clientText(t, first)
			second := c.post(t, in[1], "/openai/v1/responses", responsesBody(stream, "resp_1", ", also bob@corp.io"), nil)
			text, _ := clientText(t, second)
			calls := c.oai.recorded()
			if len(calls) != 2 {
				t.Fatalf("upstream calls = %d", len(calls))
			}
			if !strings.Contains(calls[1].body, "[REDACTED_EMAIL_2]") || strings.Contains(calls[1].body, "bob@corp.io") {
				t.Errorf("second request did not continue the numbering: %s", calls[1].body)
			}
			if !strings.Contains(text, "alice@corp.io") || !strings.Contains(text, "bob@corp.io") {
				t.Errorf("reply not restored: %q", text)
			}
		})
	}
}

// A request that carries the peer header is served where it lands, and the header never goes upstream.
func TestPeerHeaderServedLocally(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	owner := c.ownerOf("a", "/anthropic")
	entry := c.others("a", "/anthropic")[0]
	body := `{"model":"claude-opus-5-5","system":"x","messages":[{"role":"user","content":"DB_PASSWORD=hunter2hunter2"}]}`
	_ = c.post(t, entry, "/anthropic/v1/messages", body, map[string]string{PeerHeader: "1"}).Body.Close()
	if c.pods[entry].known.Len("a", "/anthropic") == 0 || c.pods[owner].known.Len("a", "/anthropic") != 0 {
		t.Error("the request was not served by the pod it entered")
	}
	if l := requestLogs(t, c.pods[entry].logs, 1); strings.Contains(l, `"peer"`) {
		t.Errorf("a peer request was forwarded again:\n%s", l)
	}
	if got := c.anth.recorded(); len(got) != 1 || got[0].hdr.Get(PeerHeader) != "" {
		t.Errorf("upstream calls %d, header %q", len(got), got[0].hdr.Get(PeerHeader))
	}
}

func TestPeerOwnerDownServesLocally(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	owner := c.ownerOf("a", "/anthropic")
	entry := c.others("a", "/anthropic")[0]
	c.setDown(c.ips[owner])
	resp := c.post(t, entry, "/anthropic/v1/messages", messagesBody(false), nil)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	assertRedactedAndRestored(t, c.anth, string(body))
	logs := requestLogs(t, c.pods[entry].logs, 1)
	if !strings.Contains(logs, `"msg":"peer unreachable; serving locally"`) || !strings.Contains(logs, `"peer":"`+c.ips[owner]+`"`) {
		t.Errorf("no warning naming the peer:\n%s", logs)
	}
	if !strings.Contains(logs, `"level":"WARN"`) || !strings.Contains(logs, `"redacted"`) {
		t.Errorf("the local request should log its counts:\n%s", logs)
	}
	// The request line names a peer only when it was forwarded; the warnings name it themselves.
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, `"msg":"request"`) && strings.Contains(line, `"peer"`) {
			t.Errorf("the request line names a peer it did not use:\n%s", line)
		}
	}
	if !strings.Contains(logs, `"msg":"peer marked down"`) {
		t.Errorf("the failed peer was not marked down:\n%s", logs)
	}
	assertNoSecretInLogs(t, logs, tokA, "alice@corp.io")
}

// After a failed forward the owner is skipped: the next request pays no dial to it and goes to the
// next-ranked pod, the owner the client will have once DNS drops the dead one.
func TestPeerDownSkipsFailedOwner(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	owner := c.ownerOf("a", "/anthropic")
	next := c.nextRanked("a", "/anthropic", owner)
	entry := 3 - owner - next // the third pod
	c.setDown(c.ips[owner])

	c.sendKnown(t, entry, "DB_PASSWORD=hunter2hunter2") // pays the failed dial, served locally
	if n := c.dialsTo(c.ips[owner]); n != 1 {
		t.Fatalf("%d dials to the dead owner for the first request", n)
	}
	if c.pods[entry].known.Len("a", "/anthropic") == 0 {
		t.Error("the first request was not served locally")
	}
	c.sendKnown(t, entry, "DB_PASSWORD=walrus7walrus7")
	c.sendKnown(t, entry, "the value is walrus7walrus7")
	if n := c.dialsTo(c.ips[owner]); n != 1 {
		t.Errorf("%d dials to the dead owner after it was marked down", n)
	}
	// Both later requests were handed to the next-ranked pod, which served them itself.
	logs := requestLogs(t, c.pods[entry].logs, 3)
	if n := strings.Count(logs, `"peer":"`+c.ips[next]+`"`); n != 2 {
		t.Errorf("forwarded to the next-ranked pod %d times, want 2:\n%s", n, logs)
	}
	if n := strings.Count(logs, `"peer marked down"`); n != 1 {
		t.Errorf("warned %d times that the peer is down, want 1:\n%s", n, logs)
	}
	nextLogs := requestLogs(t, c.pods[next].logs, 2)
	if n := strings.Count(nextLogs, `"msg":"request"`); n != 2 || strings.Contains(nextLogs, `"peer":`) {
		t.Errorf("the next-ranked pod should serve both itself:\n%s", nextLogs)
	}
	if c.pods[next].known.Len("a", "/anthropic") == 0 {
		t.Error("the next-ranked pod holds no state for the client")
	}
	// The next-ranked pod itself learns the owner is down on its own first request, and then agrees.
	c.sendKnown(t, next, "DB_PASSWORD=hunter2hunter2")
	if _, ok := c.pods[next].peers.down[c.ips[owner]]; !ok {
		t.Errorf("the next-ranked pod did not mark the owner down")
	}
	assertNoSecretInLogs(t, logs+nextLogs, tokA, "hunter2hunter2", "walrus7walrus7")
}

// When the next-ranked pod is the one that received the request, it serves it with no dial at all.
func TestPeerDownNextRankedIsSelf(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	owner := c.ownerOf("a", "/anthropic")
	next := c.nextRanked("a", "/anthropic", owner)
	c.setDown(c.ips[owner])
	c.sendKnown(t, next, "DB_PASSWORD=hunter2hunter2")
	c.sendKnown(t, next, "the value is hunter2hunter2")
	if n := c.dialsTo(c.ips[owner]); n != 1 {
		t.Errorf("%d dials to the dead owner, want 1", n)
	}
	if n := c.dialsTo(c.ips[3-owner-next]); n != 0 {
		t.Errorf("%d dials to the third pod: the request should stay here", n)
	}
	if c.pods[next].known.Len("a", "/anthropic") == 0 {
		t.Error("not served locally")
	}
	for _, line := range strings.Split(requestLogs(t, c.pods[next].logs, 2), "\n") {
		if strings.Contains(line, `"msg":"request"`) && strings.Contains(line, `"peer"`) {
			t.Errorf("a request was forwarded:\n%s", line)
		}
	}
}

// Once peerDownFor has passed, the peer is dialled again.
func TestPeerDownExpires(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	owner := c.ownerOf("a", "/anthropic")
	entry := c.others("a", "/anthropic")[0]
	clock := &testClock{t: time.Now()}
	c.pods[entry].peers.now = clock.now
	c.setDown(c.ips[owner])
	c.sendKnown(t, entry, "DB_PASSWORD=hunter2hunter2")
	clock.advance(peerDownFor - time.Second)
	c.sendKnown(t, entry, "the value is hunter2hunter2")
	if n := c.dialsTo(c.ips[owner]); n != 1 {
		t.Fatalf("%d dials inside the window, want 1", n)
	}
	clock.advance(2 * time.Second)
	c.sendKnown(t, entry, "the value is hunter2hunter2")
	if n := c.dialsTo(c.ips[owner]); n != 2 {
		t.Errorf("%d dials after the window, want 2", n)
	}
	logs := c.pods[entry].logs.String()
	if n := strings.Count(logs, `"msg":"peer used again"`); n != 1 {
		t.Errorf("logged %d times that the peer is used again, want 1:\n%s", n, logs)
	}
	if n := strings.Count(logs, `"peer marked down"`); n != 2 { // the retry failed again, so a new window starts
		t.Errorf("marked down %d times, want 2:\n%s", n, logs)
	}
}

// With the peer back, the first request after the window uses it and logs it once.
func TestPeerDownRecovers(t *testing.T) {
	var logs syncBuf
	p, err := NewPeers("peers.svc:8788", "10.0.0.2", nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	p.lookup = func(context.Context, string) ([]string, error) {
		return []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil
	}
	clock := &testClock{t: time.Now()}
	p.now = clock.now
	p.refresh(context.Background())
	var victim string // a peer that owns some client
	for i := range 50 {
		if ip, ok := p.Owner(fmt.Sprintf("c%d", i), "/x"); ok {
			victim = ip
			break
		}
	}
	p.markDown(victim, errors.New("connection refused"))
	p.markDown(victim, errors.New("connection refused")) // a request already in flight: no second warning
	if c := strings.Count(logs.String(), "peer marked down"); c != 1 {
		t.Errorf("warned %d times", c)
	}
	clock.advance(peerDownFor)
	for i := range 200 { // every client, several times over: the info is logged once
		p.Owner(fmt.Sprintf("c%d", i), "/x")
	}
	if c := strings.Count(logs.String(), "peer used again"); c != 1 {
		t.Errorf("logged %d times that the peer is used again:\n%s", c, logs.String())
	}
	if !strings.Contains(logs.String(), `"peer":"`+victim+`"`) || len(p.down) != 0 {
		t.Errorf("down = %v\n%s", p.down, logs.String())
	}
	assertNoSecretInLogs(t, logs.String(), "c1")
}

// While a peer is down, every client's owner is the rendezvous winner over the set without it.
func TestPeerDownOwnerMatchesSetWithoutIt(t *testing.T) {
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	p, err := NewPeers("peers.svc:8788", "10.0.0.2", nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p.lookup = func(context.Context, string) ([]string, error) { return ips, nil }
	p.refresh(context.Background())
	for _, victim := range []string{"10.0.0.1", "10.0.0.4"} {
		p.downMu.Lock()
		clear(p.down)
		p.downMu.Unlock()
		p.markDown(victim, errors.New("x"))
		without := slices.DeleteFunc(slices.Clone(ips), func(ip string) bool { return ip == victim })
		for i := range 1000 {
			client := fmt.Sprintf("client-%d", i)
			want := rendezvousOwner(without, client+"\x00/anthropic")
			got, fwd := p.Owner(client, "/anthropic")
			if want == "10.0.0.2" {
				if fwd {
					t.Fatalf("%s: forwarded to %s, want local", client, got)
				}
			} else if !fwd || got != want {
				t.Fatalf("%s: owner %q (forward %v), want %s", client, got, fwd, want)
			}
		}
	}
	// This pod is never skipped, so with every other peer down everything is served locally.
	for _, ip := range ips {
		if ip != "10.0.0.2" {
			p.markDown(ip, errors.New("x"))
		}
	}
	for i := range 100 {
		if ip, fwd := p.Owner(fmt.Sprintf("client-%d", i), "/anthropic"); fwd {
			t.Fatalf("forwarded to %s with every other peer down", ip)
		}
	}
}

// A DNS refresh that no longer lists a peer forgets its failure, so the map can't grow.
func TestPeerDownPrunedByRefresh(t *testing.T) {
	p, err := NewPeers("peers.svc:8788", "10.0.0.1", nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	addrs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	var lerr error
	p.lookup = func(context.Context, string) ([]string, error) { return addrs, lerr }
	p.refresh(context.Background())
	p.markDown("10.0.0.2", errors.New("x"))
	p.markDown("10.0.0.3", errors.New("x"))
	p.refresh(context.Background()) // both still listed: kept
	if len(p.down) != 2 {
		t.Fatalf("down = %v", p.down)
	}
	lerr = errors.New("no such host") // a failed lookup changes nothing
	addrs = []string{"10.0.0.1"}
	p.refresh(context.Background())
	if len(p.down) != 2 {
		t.Fatalf("a failed lookup pruned: %v", p.down)
	}
	lerr = nil
	addrs = []string{"10.0.0.1", "10.0.0.3"}
	p.refresh(context.Background())
	if _, ok := p.down["10.0.0.2"]; ok || len(p.down) != 1 {
		t.Errorf("down = %v, want only 10.0.0.3", p.down)
	}
}

// A peer with a different certificate is marked down too: it is not dialled again.
func TestPeerDownAfterCertMismatch(t *testing.T) {
	ips := []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"}
	owner := slices.Index(ips, rendezvousOwner(ips, "a\x00/anthropic"))
	c := newPeerCluster(t, 3, clusterOpts{ownCert: owner + 1})
	entry := c.others("a", "/anthropic")[0]
	c.sendKnown(t, entry, "DB_PASSWORD=hunter2hunter2")
	first := c.dialsTo(c.ips[owner])
	if first == 0 {
		t.Fatal("the owner was never dialled")
	}
	c.sendKnown(t, entry, "the value is hunter2hunter2")
	if n := c.dialsTo(c.ips[owner]); n != first {
		t.Errorf("%d dials after the first request, want %d: the mismatching peer was dialled again", n, first)
	}
	if !strings.Contains(c.pods[entry].logs.String(), `"msg":"peer marked down"`) {
		t.Errorf("no warning:\n%s", c.pods[entry].logs.String())
	}
}

// Requests arriving while a peer is being marked down are all served, and the peer is reported once.
func TestPeerDownConcurrent(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	owner := c.ownerOf("a", "/anthropic")
	entry := c.others("a", "/anthropic")[0]
	c.setDown(c.ips[owner])
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			req, _ := http.NewRequest("POST", c.pods[entry].srv.URL+"/anthropic/v1/messages", strings.NewReader(messagesBody(false)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Nospy-Token", tokA)
			resp, err := c.client.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("status %d", resp.StatusCode)
			}
		})
	}
	wg.Wait()
	requestLogs(t, c.pods[entry].logs, 16)
	if n := strings.Count(c.pods[entry].logs.String(), `"msg":"peer marked down"`); n != 1 {
		t.Errorf("warned %d times, want 1", n)
	}
}

// A peer that is still connected but stopped answering (a frozen process, a lost node) is noticed
// by the HTTP/2 health-check pings, even in the middle of a request (plan/24-peer-liveness.md).
func TestPeerFreezeMidRequest(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprintf("plain=%v", plain), func(t *testing.T) {
			ping := 100 * time.Millisecond
			c := newPeerCluster(t, 3, clusterOpts{plain: plain, pingAfter: ping, pingTimeout: ping, handshake: ping})
			owner := c.ownerOf("a", "/anthropic")
			next := c.nextRanked("a", "/anthropic", owner)
			entry := 3 - owner - next
			c.sendKnown(t, entry, "DB_PASSWORD=hunter2hunter2") // warms the connection to the owner
			if !strings.Contains(requestLogs(t, c.pods[entry].logs, 1), `"msg":"request"`) {
				t.Fatal("warm-up never finished")
			}
			if n := c.dialsTo(c.ips[owner]); n != 1 {
				t.Fatalf("%d dials to the owner while warming", n)
			}
			c.freeze(c.ips[owner])

			start := time.Now()
			resp := c.post(t, entry, "/anthropic/v1/messages", messagesBody(false), nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status %d, want 502: the body had already been sent", resp.StatusCode)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("took %v to notice the frozen owner; the ping budget is %v", d, 2*ping)
			}
			if n := len(c.anth.recorded()); n != 1 {
				t.Errorf("upstream called %d times, want 1 (the warm-up): a failed forward is never replayed", n)
			}
			logs := c.pods[entry].logs.String()
			if n := strings.Count(logs, `"msg":"peer marked down"`); n != 1 || !strings.Contains(logs, `"peer":"`+c.ips[owner]+`"`) {
				t.Errorf("the frozen owner was not marked down once:\n%s", logs)
			}

			// The next request goes to the next-ranked pod, with no dial to the frozen one.
			c.sendKnown(t, entry, "DB_PASSWORD=walrus7walrus7")
			if n := c.dialsTo(c.ips[owner]); n != 1 {
				t.Errorf("%d dials to the frozen owner, want 1", n)
			}
			if got := requestLogs(t, c.pods[next].logs, 1); !strings.Contains(got, `"msg":"request"`) {
				t.Errorf("the next-ranked pod did not serve the request:\n%s", got)
			}
			if c.pods[next].known.Len("a", "/anthropic") == 0 {
				t.Error("the next-ranked pod holds no state for the client")
			}
			assertNoSecretInLogs(t, logs, tokA, "hunter2hunter2")
		})
	}
}

// A peer that froze between requests: the pings close the idle connection, and the next request
// pays only the handshake timeout before it is served.
func TestPeerFreezeIdle(t *testing.T) {
	ping, hs := 100*time.Millisecond, 150*time.Millisecond
	c := newPeerCluster(t, 3, clusterOpts{pingAfter: ping, pingTimeout: ping, handshake: hs})
	owner := c.ownerOf("a", "/anthropic")
	entry := c.others("a", "/anthropic")[0]
	c.sendKnown(t, entry, "DB_PASSWORD=hunter2hunter2")
	if !strings.Contains(requestLogs(t, c.pods[entry].logs, 1), `"msg":"request"`) {
		t.Fatal("warm-up never finished")
	}
	c.freeze(c.ips[owner])
	c.waitClosed(t, c.ips[owner], 1) // no request in flight: only the pings can notice
	if strings.Contains(c.pods[entry].logs.String(), "peer marked down") {
		t.Error("an idle connection's death marked the peer down")
	}

	start := time.Now()
	resp := c.post(t, entry, "/anthropic/v1/messages", messagesBody(false), nil)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	if d := time.Since(start); d < hs || d > hs+3*time.Second {
		t.Errorf("took %v, want about the handshake timeout %v", d, hs)
	}
	if n := c.dialsTo(c.ips[owner]); n != 2 {
		t.Errorf("%d dials to the owner, want 2 (warm-up and the stalled handshake)", n)
	}
	logs := c.pods[entry].logs.String()
	if !strings.Contains(logs, `"msg":"peer unreachable; serving locally"`) || strings.Count(logs, `"msg":"peer marked down"`) != 1 {
		t.Errorf("the stalled handshake was not a local fallback that marks the peer down:\n%s", logs)
	}
	c.sendKnown(t, entry, "the value is hunter2hunter2")
	if n := c.dialsTo(c.ips[owner]); n != 2 {
		t.Errorf("%d dials to the owner after it was marked down, want 2", n)
	}
}

// An owner that is slow but alive is not cut off: its HTTP/2 read loop answers the pings while
// the handler waits on the upstream.
func TestPeerSlowOwnerNotCutOff(t *testing.T) {
	for _, plain := range []bool{false, true} {
		t.Run(fmt.Sprintf("plain=%v", plain), func(t *testing.T) {
			ping := 100 * time.Millisecond
			delay := 10 * ping // several times the whole ping budget
			c := newPeerCluster(t, 3, clusterOpts{plain: plain, pingAfter: ping, pingTimeout: 2 * ping, handshake: ping, anthDelay: delay})
			owner := c.ownerOf("a", "/anthropic")
			entry := c.others("a", "/anthropic")[0]
			start := time.Now()
			resp := c.post(t, entry, "/anthropic/v1/messages", messagesBody(false), nil)
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d: %s", resp.StatusCode, body)
			}
			if time.Since(start) < delay {
				t.Error("the upstream was not slow")
			}
			assertRedactedAndRestored(t, c.anth, string(body))
			if n := c.dialsTo(c.ips[owner]); n != 1 {
				t.Errorf("%d dials to the owner, want 1", n)
			}
			if l := c.pods[entry].logs.String(); strings.Contains(l, "peer marked down") || strings.Contains(l, "peer request failed") {
				t.Errorf("a healthy owner was cut off:\n%s", l)
			}
		})
	}
}

// Without TLS the forward is HTTP/2 (h2c), so the pings apply to it as well.
func TestPeerPlaintextIsHTTP2(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{plain: true})
	owner := c.ownerOf("a", "/anthropic")
	entry := c.others("a", "/anthropic")[0]
	c.sendKnown(t, entry, "DB_PASSWORD=hunter2hunter2")
	if got := c.protoMajors(c.ips[owner]); !slices.Equal(got, []int{2}) {
		t.Errorf("the owner saw forwarded requests with ProtoMajor %v, want [2]", got)
	}
	// A client talking to a pod over HTTP/1.1 is unaffected: that pod's own server speaks both.
	if resp := c.post(t, owner, "/anthropic/v1/messages", messagesBody(false), nil); resp.ProtoMajor != 1 || resp.StatusCode != 200 {
		t.Errorf("client got HTTP/%d, status %d", resp.ProtoMajor, resp.StatusCode)
	}
}

// With TLS the forward is HTTP/2 as before.
func TestPeerTLSIsHTTP2(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	owner := c.ownerOf("a", "/anthropic")
	entry := c.others("a", "/anthropic")[0]
	c.sendKnown(t, entry, "DB_PASSWORD=hunter2hunter2")
	if got := c.protoMajors(c.ips[owner]); !slices.Equal(got, []int{2}) {
		t.Errorf("the owner saw forwarded requests with ProtoMajor %v, want [2]", got)
	}
}

// A plaintext peer that only speaks HTTP/1.1 (an old pod during a rolling upgrade) is a transport
// error: the old pod is marked down, and nothing it sends is ever relayed as a response. The
// request that finds out is a 502, not a local fallback: the h2c transport writes the body right
// after the preface, before the old pod's reply shows it can't speak HTTP/2, so the body has been
// read (as with any mid-request failure, one attempt per request). Later requests skip the old pod.
func TestPeerPlaintextHTTP1OnlyPeer(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{plain: true})
	owner := c.ownerOf("a", "/anthropic")
	entry := c.others("a", "/anthropic")[0]
	var hits atomic.Int32
	old := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "answered by the old pod", http.StatusTeapot)
	}))
	t.Cleanup(old.Close)
	c.mu.Lock()
	c.addr[c.ips[owner]] = old.Listener.Addr().String()
	c.mu.Unlock()

	resp := c.post(t, entry, "/anthropic/v1/messages", messagesBody(false), nil)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusTeapot || strings.Contains(string(body), "old pod") {
		t.Fatalf("the old pod's answer was relayed: status %d %q", resp.StatusCode, body)
	}
	logs := c.pods[entry].logs.String()
	if resp.StatusCode != 200 && resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d: %s", resp.StatusCode, body)
	}
	if strings.Count(logs, `"msg":"peer marked down"`) != 1 || !strings.Contains(logs, `"peer":"`+c.ips[owner]+`"`) {
		t.Errorf("the old pod was not marked down:\n%s", logs)
	}
	// Later requests skip it and are served.
	if got := c.sendKnown(t, entry, "the value is hunter2hunter2"); got == "" {
		t.Error("empty reply")
	}
	if n := c.dialsTo(c.ips[owner]); n != 1 {
		t.Errorf("%d dials to the old pod, want 1", n)
	}
}

func TestPeerDifferentCertServesLocally(t *testing.T) {
	// The pod that owns client a presents a certificate of its own (the pod IPs are fixed, so
	// the owner is known before the cluster exists).
	ips := []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"}
	owner := slices.Index(ips, rendezvousOwner(ips, "a\x00/anthropic"))
	c := newPeerCluster(t, 3, clusterOpts{ownCert: owner + 1})
	entry := c.others("a", "/anthropic")[0]
	resp := c.post(t, entry, "/anthropic/v1/messages", messagesBody(false), nil)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	assertRedactedAndRestored(t, c.anth, string(body))
	logs := requestLogs(t, c.pods[entry].logs, 1)
	if !strings.Contains(logs, "peer unreachable; serving locally") || !strings.Contains(logs, errPeerCert.Error()) {
		t.Errorf("no warning about the certificate:\n%s", logs)
	}
	if strings.Contains(c.pods[owner].logs.String(), `"msg":"request"`) {
		t.Error("the peer with the other certificate was sent the request")
	}
}

func TestPeerSelfNotListedServesLocally(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{})
	entry := c.others("a", "/anthropic")[0]
	c.pods[entry].peers.lookup = func(context.Context, string) ([]string, error) {
		return slices.DeleteFunc(slices.Clone(c.ips), func(ip string) bool { return ip == c.ips[entry] }), nil
	}
	c.pods[entry].peers.refresh(context.Background())
	c.sendKnown(t, entry, "DB_PASSWORD=hunter2hunter2")
	if c.pods[entry].known.Len("a", "/anthropic") == 0 {
		t.Error("a pod outside the peer set did not serve its own request")
	}
	if l := requestLogs(t, c.pods[entry].logs, 1); strings.Contains(l, `"peer":`) {
		t.Errorf("forwarded without being in the set:\n%s", l)
	}
}

// The forward relays an SSE stream as it arrives: the first event reaches the client while the
// upstream is still holding the rest back.
func TestPeerForwardStreams(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	up := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		_, _ = fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello \"}}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		_, _ = fmt.Fprint(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	})
	c := newPeerCluster(t, 3, clusterOpts{anthHdlr: up})
	entry := c.others("a", "/anthropic")[0]
	resp := c.post(t, entry, "/anthropic/v1/messages", messagesBody(true), nil)
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("content type %q", ct)
	}
	br := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		var sb strings.Builder
		for {
			line, err := br.ReadString('\n')
			sb.WriteString(line)
			if strings.Contains(line, "hello") || err != nil {
				first <- sb.String()
				return
			}
		}
	}()
	select {
	case s := <-first:
		if !strings.Contains(s, "hello") {
			t.Fatalf("stream ended before the first delta: %q", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the forward buffered the stream: no event arrived while the upstream was still open")
	}
	close(release)
	rest, _ := io.ReadAll(br)
	if !strings.Contains(string(rest), "content_block_stop") {
		t.Errorf("stream did not finish: %q", rest)
	}
}

// A body the pod already started sending to the owner is never replayed locally: a failure after
// that is a 502, not a second upstream call.
func TestPeerFailureAfterBodyReadIs502(t *testing.T) {
	c := newPeerCluster(t, 3, clusterOpts{plain: true})
	entry := c.others("a", "/anthropic")[0]
	// A peer that accepts the connection and hangs up.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			// Read until the request body has arrived (the peers speak h2c, so the preface and
			// headers come first), then hang up without answering.
			var got []byte
			buf := make([]byte, 4096)
			for !bytes.Contains(got, []byte("claude-opus")) {
				n, err := conn.Read(buf)
				got = append(got, buf[:n]...)
				if err != nil {
					break
				}
			}
			_ = conn.Close()
		}
	}()
	owner := c.ownerOf("a", "/anthropic")
	c.mu.Lock()
	c.addr[c.ips[owner]] = ln.Addr().String()
	c.mu.Unlock()
	resp := c.post(t, entry, "/anthropic/v1/messages", messagesBody(false), nil)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status %d, want 502", resp.StatusCode)
	}
	if n := len(c.anth.recorded()); n != 0 {
		t.Errorf("upstream called %d times", n)
	}
}

func TestPeersRunRefreshesUntilCancelled(t *testing.T) {
	p, err := NewPeers("peers.svc:8788", "10.0.0.1", nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p.interval = 5 * time.Millisecond
	var mu sync.Mutex
	calls := 0
	p.lookup = func(context.Context, string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return []string{"10.0.0.1", "10.0.0.2"}, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := calls
		mu.Unlock()
		if n >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d lookups", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// A pod that starts before DNS lists it retries at the settle interval until it is listed, then
// goes back to the steady one (plan/23-peer-startup.md).
func TestPeersRunSettlesFast(t *testing.T) {
	p, err := NewPeers("peers.svc:8788", "10.0.0.2", nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p.interval = 100 * time.Millisecond
	p.settle = 2 * time.Millisecond
	var mu sync.Mutex
	calls := 0
	p.lookup = func(context.Context, string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		switch {
		case calls <= 2:
			return nil, errors.New("no such host")
		case calls == 3:
			return []string{"10.0.0.1"}, nil // listed, but not this pod
		}
		return []string{"10.0.0.1", "10.0.0.2"}, nil
	}
	count := func() int { mu.Lock(); defer mu.Unlock(); return calls }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("Run did not stop")
		}
	}()

	deadline := time.Now().Add(3 * time.Second)
	for s := p.set.Load(); s == nil || !s.hasSelf; s = p.set.Load() {
		if time.Now().After(deadline) {
			t.Fatalf("never listed this pod after %d lookups", count())
		}
		time.Sleep(time.Millisecond)
	}
	if n := count(); n < 4 || n > 5 { // two failures, a set without this pod, then one with it
		t.Errorf("%d lookups to settle, want 4", n)
	}
	// Settled: lookups follow the steady interval (about 3 in this window), not the settle one (over a hundred).
	before := count()
	time.Sleep(350 * time.Millisecond)
	if n := count() - before; n < 1 || n > 5 {
		t.Errorf("%d lookups in 350ms after settling, want about 3", n)
	}
}

// The peers line follows the set, not just its size: one pod replaced by another is logged.
func TestPeersLogsEverySetChange(t *testing.T) {
	var logs syncBuf
	p, err := NewPeers("peers.svc:8788", "10.0.0.2", nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	var addrs []string
	p.lookup = func(context.Context, string) ([]string, error) { return addrs, nil }
	count := func() int { return strings.Count(logs.String(), `"msg":"peers"`) }
	ctx := context.Background()

	p.refresh(ctx) // an empty first set is logged too
	if count() != 1 {
		t.Fatalf("first lookup logged %d peers lines:\n%s", count(), logs.String())
	}
	addrs = []string{"10.0.0.3", "10.0.0.2", "10.0.0.1"}
	p.refresh(ctx)
	p.refresh(ctx) // unchanged: nothing new
	if count() != 2 {
		t.Fatalf("%d peers lines after one change:\n%s", count(), logs.String())
	}
	addrs = []string{"10.0.0.4", "10.0.0.2", "10.0.0.1"} // same size, one pod replaced
	p.refresh(ctx)
	if count() != 3 {
		t.Fatalf("a replaced pod was not logged:\n%s", logs.String())
	}
	if last := logs.String()[strings.LastIndex(logs.String(), `{"time"`):]; !strings.Contains(last, `"n":3`) ||
		!strings.Contains(last, `"self_listed":true`) || !strings.Contains(last, `"ips":["10.0.0.1","10.0.0.2","10.0.0.4"]`) {
		t.Errorf("last peers line: %s", last)
	}
}
