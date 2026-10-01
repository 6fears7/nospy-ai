package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// PeerHeader marks a request that another replica forwarded (plan/21-client-affinity.md): a
// request carrying it is always served locally, so a forward can't loop. A client can set it
// too; the only effect is that its own request skips affinity, which weakens only that client's
// own protection. It is never sent upstream (outboundHeader drops it).
const PeerHeader = "X-Nospy-Peer"

const (
	defaultPeerInterval = 10 * time.Second
	// peerSettleInterval is the lookup interval while the last lookup failed or doesn't list this
	// pod: a replica that starts with the rest is not in DNS until it is ready, and serves
	// everything locally until it is (plan/23-peer-startup.md).
	peerSettleInterval = time.Second
	peerLookupTimeout  = 5 * time.Second
	peerDialTimeout    = 500 * time.Millisecond
	// peerDownFor is how long a peer that just failed is skipped: the DNS refresh interval, by
	// when Kubernetes has normally dropped a dead pod (plan/22-peer-down-skip.md).
	peerDownFor = 10 * time.Second
	// A peer connection that has received no frame for peerPingAfter gets an HTTP/2 PING and is
	// closed when peerPingTimeout passes without an answer, so a peer that froze or vanished is
	// noticed within about ten seconds, mid-request or idle (plan/24-peer-liveness.md). The pong
	// comes from the peer's HTTP/2 read loop, not a handler, so a peer busy with a long upstream
	// call still answers at once.
	peerPingAfter   = 5 * time.Second
	peerPingTimeout = 5 * time.Second
	// peerHandshakeTimeout bounds the TLS handshake with a peer. A frozen process's kernel still
	// accepts the TCP connection, so the dial succeeds and only the handshake hangs; a pod-to-pod
	// handshake takes milliseconds (plan/24-peer-liveness.md).
	peerHandshakeTimeout = time.Second
)

var errPeerCert = errors.New("peer presented a different certificate")

// peerSet is one resolved snapshot: the peers' IPs, sorted, and whether this pod is among them.
type peerSet struct {
	ips     []string
	hasSelf bool
}

// Peers routes each client to one owner replica, so the per-process stores (the known-values set
// and the Responses chains) see all of a client's requests. The replicas are found by a periodic
// DNS lookup of a headless Service; the owner of (client, route) is the rendezvous-hash winner
// over their IPs. A pod whose own IP is not in the set (not ready yet) serves everything locally.
// It replicates no state: when the set changes, the clients that move start empty, as after a
// restart. A peer whose forward just failed is skipped for peerDownFor: its clients go to the
// next-ranked peer, which is the owner they will have once DNS drops it.
type Peers struct {
	host, port string
	self       string // this pod's IP, normalized
	scheme     string // "https", or "http" without TLS
	log        *slog.Logger
	lookup     func(ctx context.Context, host string) ([]string, error)
	interval   time.Duration // between lookups once this pod is listed
	settle     time.Duration // between lookups while it is not
	tr         *http.Transport
	set        atomic.Pointer[peerSet] // nil until the first successful lookup
	now        func() time.Time        // the clock, replaced in tests

	downMu sync.Mutex
	down   map[string]time.Time // peer IP -> skipped until; an expired entry stays until the peer is used again or DNS drops it

	mu      sync.Mutex // guards the log state
	failing bool       // the last lookup failed (a warning is logged once per change)
	last    string     // the last set logged: its IPs, joined
	logged  bool       // a set has been logged (the first one may be empty)
}

// NewPeers returns peers resolved from addr (HOST:PORT; HOST usually a headless Service's DNS
// name) for the pod at IP self. With certs set, peers talk TLS and are trusted only when their
// leaf certificate is byte-identical to the one this pod serves: every replica mounts the same
// Secret, and the handshake proves the peer holds the key. Without certs they use plain HTTP.
// Call Run to keep the set current.
func NewPeers(addr, self string, certs *CertFiles, log *slog.Logger) (*Peers, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return nil, fmt.Errorf("peers address %q is not HOST:PORT", addr)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("peers address %q has an invalid port", addr)
	}
	sa, err := netip.ParseAddr(self)
	if err != nil {
		return nil, fmt.Errorf("peer self %q is not an IP address", self)
	}
	p := &Peers{host: host, port: port, self: sa.Unmap().String(), scheme: "http", log: log,
		lookup: net.DefaultResolver.LookupHost, interval: defaultPeerInterval, settle: peerSettleInterval,
		now: time.Now, down: map[string]time.Time{}}
	p.tr = &http.Transport{
		// No Proxy: pod-to-pod traffic never goes through HTTPS_PROXY.
		DialContext:         (&net.Dialer{Timeout: peerDialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: peerHandshakeTimeout,
		ForceAttemptHTTP2:   true,
		HTTP2:               &http.HTTP2Config{SendPingTimeout: peerPingAfter, PingTimeout: peerPingTimeout},
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
	}
	if certs == nil {
		// Plaintext peers speak HTTP/2 too (h2c, prior knowledge), or they would fall back to
		// HTTP/1.1 and get no pings. A peer that doesn't speak h2c (an old pod during a rolling
		// upgrade) fails as a transport error and is never relayed as a response. The first such
		// forward is a 502, because the body goes out right after the preface; the peer is then
		// marked down, so later requests skip it (plan/24-peer-liveness.md).
		p.tr.Protocols = new(http.Protocols)
		p.tr.Protocols.SetUnencryptedHTTP2(true)
	} else {
		p.scheme = "https"
		p.tr.TLSClientConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Peers are addressed by pod IP, which no certificate names, so the usual chain and
			// name check can't apply. VerifyConnection replaces it (and runs on resumed
			// connections too): the peer must present the very leaf this pod serves, and the TLS
			// handshake itself proves it holds that certificate's key.
			InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection below
			VerifyConnection: func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 || !bytes.Equal(cs.PeerCertificates[0].Raw, certs.LeafDER()) {
					return errPeerCert
				}
				return nil
			},
		}
	}
	return p, nil
}

// Run resolves the peers now and then until ctx is done: every interval once this pod is listed,
// every settle until then (the lookup failed, or the set doesn't list this pod yet). A failed
// lookup keeps the last good set.
func (p *Peers) Run(ctx context.Context) {
	defer p.tr.CloseIdleConnections()
	t := time.NewTimer(p.next(p.refresh(ctx)))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(p.next(p.refresh(ctx)))
		}
	}
}

// next is the wait before the next lookup, given whether the last one listed this pod.
func (p *Peers) next(listed bool) time.Duration {
	if listed {
		return p.interval
	}
	return p.settle
}

// refresh looks the peers up once. It reports whether the lookup worked and lists this pod.
func (p *Peers) refresh(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, peerLookupTimeout)
	defer cancel()
	addrs, err := p.lookup(ctx, p.host)
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		if !p.failing {
			p.log.Warn("peer lookup failed; keeping the previous set", "err", err)
		}
		p.failing = true
		return false
	}
	if p.failing {
		p.log.Info("peer lookup works again")
	}
	p.failing = false
	s := &peerSet{}
	for _, a := range addrs {
		if ip, err := netip.ParseAddr(a); err == nil {
			s.ips = append(s.ips, ip.Unmap().String())
		}
	}
	slices.Sort(s.ips)
	s.ips = slices.Compact(s.ips)
	s.hasSelf = slices.Contains(s.ips, p.self)
	p.set.Store(s)
	p.pruneDown(s.ips)
	// Logged on every change of the set, not only of its size: a pod replaced by another keeps n.
	if key := strings.Join(s.ips, ","); !p.logged || key != p.last {
		p.logged, p.last = true, key
		p.log.Info("peers", "n", len(s.ips), "self_listed", s.hasSelf, "ips", s.ips)
	}
	return s.hasSelf
}

// pruneDown forgets the failures of peers that are no longer listed, so the map can't grow.
func (p *Peers) pruneDown(ips []string) {
	p.downMu.Lock()
	defer p.downMu.Unlock()
	for ip := range p.down {
		if !slices.Contains(ips, ip) {
			delete(p.down, ip)
		}
	}
}

// markDown skips peer for peerDownFor after a failed forward. Only the first failure of a window
// warns (a request already in flight when the peer died fails after it was marked).
func (p *Peers) markDown(peer string, err error) {
	now := p.now()
	p.downMu.Lock()
	if until, ok := p.down[peer]; ok && now.Before(until) {
		p.downMu.Unlock()
		return
	}
	p.down[peer] = now.Add(peerDownFor)
	p.downMu.Unlock()
	p.log.Warn("peer marked down", "peer", peer, "err", err, "for", peerDownFor)
}

// Owner returns the IP of the replica that owns the client's state for the route, and false when
// this pod is the owner or must serve locally anyway (no set yet, or this pod is not in it). A peer
// that failed within peerDownFor is passed over: the owner is then the best-ranked peer that isn't
// down, so every replica agrees on it, and it is the owner once DNS drops the failed one. This pod
// is never down, so there is always a candidate.
func (p *Peers) Owner(client, prefix string) (string, bool) {
	s := p.set.Load()
	if s == nil || !s.hasSelf {
		return "", false
	}
	key := client + "\x00" + prefix
	nodes := s.ips
	p.downMu.Lock()
	if len(p.down) > 0 {
		now := p.now()
		nodes = slices.DeleteFunc(slices.Clone(nodes), func(ip string) bool {
			until, ok := p.down[ip]
			return ok && now.Before(until)
		})
	}
	owner := rendezvousOwner(nodes, key)
	_, expired := p.down[owner]
	if expired {
		delete(p.down, owner)
	}
	p.downMu.Unlock()
	if expired {
		p.log.Info("peer used again", "peer", owner)
	}
	return owner, owner != p.self
}

// rendezvousOwner picks the node with the highest hash of node and key (highest-random-weight
// hashing): it needs no ring state, and removing a node moves only the keys that node owned.
// nodes must be sorted, so a tie (2^-64) resolves the same everywhere.
func rendezvousOwner(nodes []string, key string) string {
	var best string
	var bestScore uint64
	for i, n := range nodes {
		sum := sha256.Sum256([]byte(n + "\x00" + key))
		if score := binary.BigEndian.Uint64(sum[:8]); i == 0 || score > bestScore {
			best, bestScore = n, score
		}
	}
	return best
}

// forward hands the request, unchanged, to the owner at peer and relays the response as it
// streams. It reports false, having written nothing, when the peer could not be reached before
// the request body was touched (dial or TLS failure); the caller then serves the request itself.
// Once the body has been read or a response has started, a failure is a 502 and never a retry.
// Either way the peer is marked down (a failure caused by the client going away is not its fault).
// The owner authenticates the request again: forwarding grants nothing.
func (p *Peers) forward(w http.ResponseWriter, r *http.Request, peer string) bool {
	target := &url.URL{Scheme: p.scheme, Host: net.JoinHostPort(peer, p.port)}
	body := &trackedBody{rc: r.Body}
	r.Body = body
	var unreachable error
	rp := &httputil.ReverseProxy{
		Transport: p.tr,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Header.Set(PeerHeader, "1")
		},
		FlushInterval: -1, // SSE streams pass through as they arrive
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			clientGone := r.Context().Err() != nil
			if !clientGone {
				p.markDown(peer, err)
			}
			if !body.read.Load() && !clientGone {
				unreachable = err
				return
			}
			p.log.Warn("peer request failed", "peer", peer, "err", err)
			http.Error(w, "nospy: peer request failed", http.StatusBadGateway)
		},
	}
	rp.ServeHTTP(w, r)
	if unreachable == nil {
		return true
	}
	p.log.Warn("peer unreachable; serving locally", "peer", peer, "err", unreachable)
	return false
}

// trackedBody notes whether anything was read. Until then Close does nothing, because the
// transport closes the body of a request it failed to send, and the request must stay readable
// for the local fallback.
type trackedBody struct {
	rc   io.ReadCloser
	read atomic.Bool
}

func (b *trackedBody) Read(p []byte) (int, error) {
	b.read.Store(true)
	return b.rc.Read(p)
}

func (b *trackedBody) Close() error {
	if !b.read.Load() {
		return nil
	}
	return b.rc.Close()
}
