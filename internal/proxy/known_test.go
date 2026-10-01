package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"nospyai/internal/redact"
)

func kv(vals ...string) []redact.Known {
	var ks []redact.Known
	for _, v := range vals {
		ks = append(ks, redact.Known{Kind: redact.KindSecret, Value: v})
	}
	return ks
}

func values(ks []redact.Known) string {
	var vs []string
	for _, k := range ks {
		vs = append(vs, k.Value)
	}
	return strings.Join(vs, ",")
}

func TestKnownStoreBoundsAndTTL(t *testing.T) {
	now := time.Unix(1000, 0)
	ks := NewKnownStore(3, time.Minute)
	ks.now = func() time.Time { return now }

	ks.Add("a", "/anthropic", kv("one", "two", "three"))
	ks.Add("a", "/anthropic", kv("one")) // seen again: "two" is now the oldest
	ks.Add("a", "/anthropic", kv("four"))
	if got := values(ks.Get("a", "/anthropic")); got != "four,one,three" {
		t.Errorf("after eviction: %s, want four,one,three", got)
	}
	// Scope: client and route are part of the key.
	if ks.Get("b", "/anthropic") != nil || ks.Get("a", "/openai") != nil {
		t.Error("another client or route got the set")
	}
	ks.Add("b", "/anthropic", kv("other"))
	if got := values(ks.Get("a", "/anthropic")); got != "four,one,three" {
		t.Errorf("client b changed a's set: %s", got)
	}
	// Get returns a copy.
	ks.Get("a", "/anthropic")[0].Value = "changed"
	if got := values(ks.Get("a", "/anthropic")); got != "four,one,three" {
		t.Errorf("Get leaked the stored slice: %s", got)
	}
	// Idle TTL: a new sighting extends it, and it drops the client's whole set.
	now = now.Add(40 * time.Second)
	ks.Add("a", "/anthropic", kv("one"))
	now = now.Add(40 * time.Second)
	if got := values(ks.Get("a", "/anthropic")); got != "one,four,three" {
		t.Errorf("set expired despite a sighting: %s", got)
	}
	if ks.Get("b", "/anthropic") != nil {
		t.Error("b's set outlived its ttl")
	}
	now = now.Add(2 * time.Minute)
	if ks.Get("a", "/anthropic") != nil {
		t.Error("expired set returned")
	}
	ks.Add("c", "/anthropic", kv("x")) // sweeps what expired
	if ks.Len("a", "/anthropic") != 0 || ks.Len("c", "/anthropic") != 1 || len(ks.sets) != 1 {
		t.Errorf("sweep left %d sets", len(ks.sets))
	}
}

func TestKnownStoreConcurrent(t *testing.T) {
	ks := NewKnownStore(50, time.Minute)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				ks.Add("a", "/p", kv(fmt.Sprintf("value-%d-%d", g, i)))
				ks.Get("a", "/p")
			}
		}()
	}
	wg.Wait()
	if n := ks.Len("a", "/p"); n != 50 {
		t.Errorf("Len = %d, want 50", n)
	}
}

type knownEnv struct {
	fu     *fakeUpstream
	px     *httptest.Server
	known  *KnownStore
	client string
	mu     sync.Mutex
}

func setupKnown(t *testing.T) *knownEnv {
	t.Helper()
	e := &knownEnv{fu: &fakeUpstream{}, known: NewKnownStore(0, 0), client: "a"}
	up := httptest.NewServer(e.fu)
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	h, err := New([]Route{{Prefix: "/anthropic", Upstream: u, Dialect: AnthropicDialect}}, testToken,
		redact.NewDetector(redact.Config{}), slog.New(slog.DiscardHandler),
		WithKnownStore(e.known), WithClient(func(*http.Request) string { e.mu.Lock(); defer e.mu.Unlock(); return e.client }))
	if err != nil {
		t.Fatal(err)
	}
	e.px = httptest.NewServer(h)
	t.Cleanup(e.px.Close)
	return e
}

func (e *knownEnv) send(t *testing.T, content string) string {
	t.Helper()
	body := `{"model":"claude-opus-5-5","system":"x","messages":[{"role":"user","content":` + jsonString(content) + `}]}`
	resp := post(t, e.px.URL+"/"+testToken+"/anthropic/v1/messages", body, nil)
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, out)
	}
	return string(out)
}

func (e *knownEnv) lastUpstream(t *testing.T) string {
	t.Helper()
	calls := e.fu.recorded()
	return noNote([]byte(calls[len(calls)-1].body))
}

// A value redacted by a context rule in one request is redacted in the client's later request
// that holds it as bare prose, and the response restores it. Another client is not covered.
func TestKnownValuesAcrossRequests(t *testing.T) {
	e := setupKnown(t)
	const pw = "hunter2hunter2"
	e.send(t, "DB_PASSWORD="+pw+"\nHOST=h")
	if strings.Contains(e.lastUpstream(t), pw) {
		t.Fatal("request 1 leaked")
	}

	back := e.send(t, "the value is "+pw+" and mail a@corp.io")
	up := e.lastUpstream(t)
	if strings.Contains(up, pw) || !strings.Contains(up, "the value is [REDACTED_SECRET_1] and mail [REDACTED_EMAIL_1]") {
		t.Errorf("request 2 not redacted with a fresh vault:\n%s", up)
	}
	// The fake upstream echoes the placeholders it saw; the client gets the real values.
	if !strings.Contains(back, pw) || strings.Contains(back, "[REDACTED_") {
		t.Errorf("response not restored: %s", back)
	}

	e.mu.Lock()
	e.client = "b"
	e.mu.Unlock()
	e.send(t, "the value is "+pw)
	if up := e.lastUpstream(t); !strings.Contains(up, pw) {
		t.Errorf("client b was covered by a's set:\n%s", up)
	}
	if e.known.Len("b", "/anthropic") != 0 {
		t.Error("a request with no sighting created a set")
	}
}

// Only kinds a context rule finds are remembered.
func TestKnownValuesSkipContextFreeKinds(t *testing.T) {
	e := setupKnown(t)
	e.send(t, "mail a@corp.io from 10.1.2.3 at build.corp.io")
	if n := e.known.Len("a", "/anthropic"); n != 0 {
		t.Errorf("known set holds %d context-free values", n)
	}
}

// A request's fixed cost with a full set. "rebuild" is what every request paid before step 20's
// cache (Get copies the values, NewKnownSet builds the matcher); "cached" is a request that adds
// no new values (Matcher hands back the built one).
func BenchmarkKnownGetWithKnown(b *testing.B) {
	pem := "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", 94) + "\n-----END PRIVATE KEY-----"
	run := func(b *testing.B, tokens, keys int, cached bool) {
		ks := NewKnownStore(0, time.Hour)
		var vals []redact.Known
		for i := 0; i < tokens; i++ {
			vals = append(vals, redact.Known{Kind: redact.KindToken, Value: fmt.Sprintf("tok_%028x", i*7919+1)})
		}
		for i := 0; i < keys; i++ {
			vals = append(vals, redact.Known{Kind: redact.KindPrivateKey, Value: fmt.Sprintf("%s%04d", pem, i)})
		}
		ks.Add("a", "/anthropic", vals)
		det := redact.NewDetector(redact.Config{})
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			m := ks.Matcher("a", "/anthropic")
			if !cached {
				m = redact.NewKnownSet(ks.Get("a", "/anthropic"))
			}
			redact.NewRedactor(det, redact.NewVault()).WithKnown(m)
		}
	}
	for _, c := range []struct {
		name         string
		tokens, keys int
	}{{"tokens=4096", 4096, 0}, {"tokens=4032+pem=64", 4032, 64}} {
		b.Run(c.name+"/rebuild", func(b *testing.B) { run(b, c.tokens, c.keys, false) })
		b.Run(c.name+"/cached", func(b *testing.B) { run(b, c.tokens, c.keys, true) })
	}
}

// Value bytes count toward a cap next to the count: the oldest go once the total passes it.
func TestKnownStoreByteCap(t *testing.T) {
	ks := NewKnownStore(100, time.Minute)
	ks.maxBytes = 10
	ks.Add("a", "/p", kv("aaaa", "bbbb")) // 8 bytes
	ks.Add("a", "/p", kv("cc"))           // 10: at the cap, nothing goes
	if got := values(ks.Get("a", "/p")); got != "cc,bbbb,aaaa" {
		t.Fatalf("at cap: %s", got)
	}
	ks.Add("a", "/p", kv("dddd")) // 14: the oldest (aaaa) goes, then 10 holds
	if got := values(ks.Get("a", "/p")); got != "dddd,cc,bbbb" {
		t.Fatalf("over cap: %s", got)
	}
	ks.Add("a", "/p", kv("eeeeeeee")) // 18: bbbb, cc and dddd go in turn, then the cap holds
	if got, n := values(ks.Get("a", "/p")), ks.sets[knownKey{"a", "/p"}].bytes; got != "eeeeeeee" || n != 8 {
		t.Fatalf("big add: %s (%d bytes)", got, n)
	}
	// The count cap still evicts as before.
	ks = NewKnownStore(2, time.Minute)
	ks.Add("a", "/p", kv("aaaa", "bbbb", "cccc"))
	if got := values(ks.Get("a", "/p")); got != "cccc,bbbb" {
		t.Fatalf("count cap: %s", got)
	}
	if n := ks.sets[knownKey{"a", "/p"}].bytes; n != 8 {
		t.Errorf("bytes after count eviction = %d", n)
	}
}

// A value over the byte cap is not stored, and what the client already had stays.
func TestKnownStoreOversizedValue(t *testing.T) {
	ks := NewKnownStore(100, time.Minute)
	ks.maxBytes = 10
	ks.Add("a", "/p", kv("aaaa", "bbbb"))
	ks.Add("a", "/p", kv(strings.Repeat("x", 11)))
	if got := values(ks.Get("a", "/p")); got != "bbbb,aaaa" {
		t.Fatalf("got %s", got)
	}
	if n := ks.sets[knownKey{"a", "/p"}].bytes; n != 8 {
		t.Errorf("bytes = %d", n)
	}
	ks.Add("a", "/p", kv(strings.Repeat("y", 10))) // exactly the cap: stored, the rest make room
	if got := values(ks.Get("a", "/p")); got != strings.Repeat("y", 10) {
		t.Errorf("at the cap: %s", got)
	}
}

// Seeing a held value again, even as another kind, neither double-counts its bytes nor evicts.
func TestKnownStoreReplaceKeepsBytes(t *testing.T) {
	ks := NewKnownStore(100, time.Minute)
	ks.maxBytes = 10
	ks.Add("a", "/p", kv("aaaa", "bbbb"))
	ks.Add("a", "/p", []redact.Known{{Kind: redact.KindToken, Value: "aaaa"}})
	got := ks.Get("a", "/p")
	if values(got) != "aaaa,bbbb" || got[0].Kind != redact.KindToken {
		t.Fatalf("got %v", got)
	}
	if n := ks.sets[knownKey{"a", "/p"}].bytes; n != 8 {
		t.Errorf("bytes = %d, want 8", n)
	}
	ks.Add("a", "/p", kv("cc")) // 10: still fits, so nothing was double-counted
	if got := values(ks.Get("a", "/p")); got != "cc,aaaa,bbbb" {
		t.Errorf("got %s", got)
	}
}

// The matcher is rebuilt only when the set's values or their kinds change: not for a request
// that adds nothing new, or a value seen again.
func TestKnownStoreMatcherCache(t *testing.T) {
	ks := NewKnownStore(2, time.Minute)
	if ks.Matcher("a", "/p") != nil {
		t.Fatal("matcher for an unknown client")
	}
	ks.Add("a", "/p", kv("aaaa", "bbbb"))
	m := ks.Matcher("a", "/p")
	if m == nil || ks.Matcher("a", "/p") != m {
		t.Fatal("matcher not reused")
	}
	ks.Add("a", "/p", kv("bbbb"))
	ks.Add("a", "/p", nil)
	if ks.Matcher("a", "/p") != m {
		t.Error("rebuilt after a reorder")
	}
	if ks.Matcher("b", "/p") == m {
		t.Error("clients share a matcher")
	}
	ks.Add("a", "/p", []redact.Known{{Kind: redact.KindToken, Value: "bbbb"}})
	m2 := ks.Matcher("a", "/p")
	if m2 == m {
		t.Error("not rebuilt after a kind change")
	}
	ks.Add("a", "/p", kv("cccc")) // evicts aaaa
	if ks.Matcher("a", "/p") == m2 {
		t.Error("not rebuilt after an insert and an eviction")
	}
	// The old matcher still works for a request that holds it.
	r := redact.NewRedactor(redact.NewDetector(redact.Config{}), redact.NewVault()).WithKnown(m)
	r.Scan("x aaaa y")
	if out, _ := r.Rewrite("x aaaa y"); out != "x [REDACTED_SECRET_1] y" {
		t.Errorf("old matcher: %s", out)
	}
}

// Concurrent requests of one client share a matcher while others add values.
func TestKnownStoreMatcherConcurrent(t *testing.T) {
	ks := NewKnownStore(50, time.Minute)
	det := redact.NewDetector(redact.Config{})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				r := redact.NewRedactor(det, redact.NewVault()).WithKnown(ks.Matcher("a", "/p"))
				r.Scan(fmt.Sprintf("see val%d-%d here", g, i))
				ks.Add("a", "/p", kv(fmt.Sprintf("val%d-%d", g, i)))
			}
		}(g)
	}
	wg.Wait()
	if n := ks.Len("a", "/p"); n != 50 {
		t.Errorf("Len = %d, want 50", n)
	}
}
