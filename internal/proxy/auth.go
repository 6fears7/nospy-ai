package proxy

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
)

// Authenticator identifies the client of a serve-mode request. token is the credential the
// route's key mode designates (see KeyMode). The returned client name goes into logs and scopes
// the Responses chain store, so one client can never continue another's chain.
// Implementations return ErrUnauthenticated (or any error) to refuse; the client only ever
// sees a bare 401.
type Authenticator interface {
	Authenticate(r *http.Request, token string) (client string, err error)
}

// ErrUnauthenticated is what an Authenticator returns for a missing or unknown credential.
var ErrUnauthenticated = errors.New("unauthenticated")

// KeyMode says where the client's proxy token travels and what goes upstream as the key.
type KeyMode int

const (
	// KeyPassthrough: the client sends its real upstream key untouched, plus the proxy token in
	// X-Nospy-Token or a /t/<token>/ path prefix. Both are stripped; the real key is forwarded.
	KeyPassthrough KeyMode = iota
	// KeyInject: the client sends the proxy token in the route's key header. No client credential
	// is forwarded; nospy sets the real key from its own key file (see outboundHeader).
	KeyInject
)

func (m KeyMode) String() string {
	if m == KeyInject {
		return "inject"
	}
	return "passthrough"
}

// TokenHeader carries the proxy token of a passthrough route.
const TokenHeader = "X-Nospy-Token" //nolint:gosec // header name, not a credential

// noneAuth trusts every client on a loopback listener.
type noneAuth struct{}

// NewNoneAuth returns the `none` authenticator: every request is client "local". It is
// constructible only for a loopback listen address (invariant 9).
func NewNoneAuth(listen string) (Authenticator, error) {
	if !IsLoopbackListen(listen) {
		return nil, errors.New("auth none is only allowed on a loopback listen address")
	}
	return noneAuth{}, nil
}

func (noneAuth) Authenticate(*http.Request, string) (string, error) { return "local", nil }

// IsLoopbackListen reports whether a host:port listen address binds loopback only. An empty
// host (":8788"), 0.0.0.0, [::] and any name other than localhost are not loopback.
func IsLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	return err == nil && IsLoopbackHost(host)
}

// IsLoopbackHost reports whether host is localhost or a loopback IP address.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// ClientNameRe is the format of a client (token) name; it appears in logs and in the chain key.
var ClientNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

type tokenEntry struct {
	name string
	hash [sha256.Size]byte
}

// StaticTokens authenticates against a file of `name:sha256hex` lines (a mounted Secret). The
// file is re-read when its mtime or size changes, so rotation needs no restart. If a changed
// file no longer parses, the previous tokens stay in force and a warning is logged.
type StaticTokens struct {
	r *reloadable[[]tokenEntry]
}

// parseStaticTokens parses a tokens file: one `name:sha256hex` per line, `#` comments and blank
// lines ignored. All problems are returned together as "tokens line N: <problem>"; the text of a
// line is never echoed, because a mistake there may be a raw token.
func parseStaticTokens(r io.Reader) ([]tokenEntry, error) {
	sc := bufio.NewScanner(r)
	var errs []error
	var out []tokenEntry
	names, hashes := map[string]bool{}, map[[sha256.Size]byte]bool{}
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if n == 1 {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		bad := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("tokens line %d: "+format, append([]any{n}, a...)...))
		}
		name, hexHash, ok := strings.Cut(line, ":")
		if !ok {
			bad("expected name:sha256hex")
			continue
		}
		name, hexHash = strings.TrimSpace(name), strings.TrimSpace(hexHash)
		var e tokenEntry
		e.name = name
		valid := true
		if !ClientNameRe.MatchString(name) {
			bad("name must match [a-z0-9][a-z0-9-]*")
			valid = false
		}
		if raw, err := hex.DecodeString(hexHash); err != nil || len(raw) != sha256.Size {
			bad("hash must be 64 hex characters (a sha256; see `nospy hash-token`)")
			valid = false
		} else {
			copy(e.hash[:], raw)
		}
		if !valid {
			continue
		}
		if names[name] {
			bad("duplicate name")
			continue
		}
		if hashes[e.hash] {
			bad("duplicate token hash")
			continue
		}
		names[name], hashes[e.hash] = true, true
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, fmt.Errorf("tokens file: %w", err))
	}
	return out, errors.Join(errs...)
}

// LoadStaticTokens loads the tokens file and watches it for changes. A file with no tokens is
// an error at startup (nobody could authenticate); a later reload that parses to no tokens is
// applied, so emptying the file locks everyone out.
func LoadStaticTokens(path string, log *slog.Logger) (*StaticTokens, error) {
	load := func() ([]tokenEntry, error) {
		f, err := os.Open(path) //nolint:gosec // operator-configured path
		if err != nil {
			return nil, fmt.Errorf("tokens file: %w", err)
		}
		defer func() { _ = f.Close() }()
		return parseStaticTokens(f)
	}
	r, err := newReloadable([]string{path}, load, func(err error) {
		log.Warn("tokens file changed but did not load; keeping the previous tokens", "err", err)
	})
	if err != nil {
		return nil, err
	}
	if len(r.get()) == 0 {
		return nil, errors.New("tokens file: no tokens (see `nospy hash-token`)")
	}
	return &StaticTokens{r: r}, nil
}

// Len reports how many tokens are currently loaded.
func (s *StaticTokens) Len() int { return len(s.r.get()) }

// HashToken returns the sha256 hex digest of a token: the value stored in a tokens file.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Authenticate hashes the presented token and compares it, in constant time, with every stored
// hash (no early exit). An empty token never authenticates.
func (s *StaticTokens) Authenticate(_ *http.Request, token string) (string, error) {
	if token == "" {
		return "", ErrUnauthenticated
	}
	sum := sha256.Sum256([]byte(token))
	client := ""
	for _, e := range s.r.get() {
		if subtle.ConstantTimeCompare(sum[:], e.hash[:]) == 1 {
			client = e.name
		}
	}
	if client == "" {
		return "", ErrUnauthenticated
	}
	return client, nil
}

// KeyFile holds the real upstream key of an inject route, re-read when the file changes.
type KeyFile struct {
	r *reloadable[string]
}

func parseKey(b []byte) (string, error) {
	k := strings.TrimSpace(string(b))
	switch {
	case k == "":
		return "", errors.New("key file is empty")
	case strings.ContainsAny(k, "\r\n\x00"):
		return "", errors.New("key file must hold a single line")
	}
	return k, nil
}

// LoadKeyFile reads the key file (one line, surrounding whitespace trimmed) and watches it. The
// key never appears in an error or a log.
func LoadKeyFile(path string, log *slog.Logger) (*KeyFile, error) {
	load := func() (string, error) {
		b, err := os.ReadFile(path) //nolint:gosec // operator-configured path
		if err != nil {
			return "", fmt.Errorf("key file: %w", err)
		}
		return parseKey(b)
	}
	r, err := newReloadable([]string{path}, load, func(err error) {
		log.Warn("key file changed but did not load; keeping the previous key", "err", err)
	})
	if err != nil {
		return nil, err
	}
	return &KeyFile{r: r}, nil
}

// Get returns the current key.
func (k *KeyFile) Get() string { return k.r.get() }

// splitPathToken removes a leading /t/<token> from a request path.
func splitPathToken(p string) (rest, token string) {
	after, ok := strings.CutPrefix(p, "/t/")
	if !ok {
		return p, ""
	}
	token, tail, _ := strings.Cut(after, "/")
	return "/" + tail, token
}

// credentialFor extracts the proxy token a request carries for route rt: from its key header
// (inject) or from X-Nospy-Token / the path prefix (passthrough).
func credentialFor(r *http.Request, rt *route, pathToken string) string {
	if rt.KeyMode == KeyInject {
		return headerCredential(r, rt.KeyHeader, rt.KeyScheme)
	}
	if t := r.Header.Get(TokenHeader); t != "" {
		return t
	}
	return pathToken
}

func headerCredential(r *http.Request, header, scheme string) string {
	v := strings.TrimSpace(r.Header.Get(header))
	if scheme == "" {
		return v
	}
	if len(v) > len(scheme) && strings.EqualFold(v[:len(scheme)], scheme) && v[len(scheme)] == ' ' {
		return strings.TrimSpace(v[len(scheme)+1:])
	}
	return ""
}

func (h *handler) authenticate(r *http.Request, rt *route, pathToken string) (string, error) {
	client, err := h.auth.Authenticate(r, credentialFor(r, rt, pathToken))
	if err != nil || client == "" {
		return "", ErrUnauthenticated
	}
	return client, nil
}

// anyCredentialWorks reports whether the request carries a token any route would accept. It
// decides between 404 and 401 for a path that names no route.
func (h *handler) anyCredentialWorks(r *http.Request, pathToken string) bool {
	cands := []string{r.Header.Get(TokenHeader), pathToken,
		headerCredential(r, "X-Api-Key", ""), headerCredential(r, "Authorization", "Bearer")}
	for _, c := range cands {
		if _, err := h.auth.Authenticate(r, c); err == nil {
			return true
		}
	}
	return false
}

// unauthenticated answers 401 with no detail about why.
func unauthenticated(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = io.WriteString(w, `{"error":{"type":"authentication_error","message":"nospy: unauthenticated"}}`)
}
