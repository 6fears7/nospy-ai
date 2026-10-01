package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"nospyai/internal/redact"
)

// TestMain lets the test binary double as the wrapped child (the re-exec pattern).
func TestMain(m *testing.M) {
	switch os.Getenv("NOSPY_TEST_CHILD") {
	case "post", "badtoken":
		os.Exit(childPost())
	case "scrapemetrics":
		os.Exit(childScrapeMetrics())
	case "postchat":
		os.Exit(childPostChat())
	}
	os.Exit(m.Run())
}

const childEmail = "alice@corp.io"

// childPost plays an agent: it sends a Messages request containing an email to the base URL
// it was given and prints the text of the reply.
func childPost() int {
	body := `{"model":"m","max_tokens":8,"messages":[{"role":"user","content":"mail ` + childEmail + `"}]}`
	base := os.Getenv("ANTHROPIC_BASE_URL")
	if os.Getenv("NOSPY_TEST_CHILD") == "badtoken" { // a request that doesn't carry the session token
		base = regexp.MustCompile(`/[0-9a-f]{32}/`).ReplaceAllString(base, "/"+strings.Repeat("0", 32)+"/")
	}
	resp, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "child:", err)
		return 9
	}
	defer func() { _ = resp.Body.Close() }()
	if os.Getenv("NOSPY_TEST_CHILD") == "badtoken" {
		if resp.StatusCode != http.StatusNotFound {
			return 9
		}
		return 0 // the tripwire test deliberately expects a non-JSON rejection
	}
	var msg struct {
		Content []struct{ Text string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&msg); err != nil {
		return 9
	}
	for _, c := range msg.Content {
		fmt.Println(c.Text)
	}
	return 0
}

// childScrapeMetrics sends one redacted request, then prints what /metrics reports.
func childScrapeMetrics() int {
	if code := childPost(); code != 0 {
		return code
	}
	resp, err := http.Get("http://" + os.Getenv("NOSPY_TEST_METRICS_ADDR") + "/metrics")
	if err != nil {
		fmt.Fprintln(os.Stderr, "child:", err)
		return 9
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 9
	}
	_, _ = io.Copy(os.Stdout, resp.Body)
	return 0
}

// childPostChat plays an OpenAI-SDK agent: a Chat Completions request to $OPENAI_BASE_URL.
func childPostChat() int {
	body := `{"model":"m","messages":[{"role":"user","content":"mail ` + childEmail + `"}]}`
	resp, err := http.Post(os.Getenv("OPENAI_BASE_URL")+"/chat/completions", "application/json", strings.NewReader(body))
	if err != nil {
		fmt.Fprintln(os.Stderr, "child:", err)
		return 9
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		Choices []struct{ Message struct{ Content string } }
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 9
	}
	for _, c := range out.Choices {
		fmt.Println(c.Message.Content)
	}
	return 0
}

func runWrapCLI(t *testing.T, getenv func(string) string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, getenv, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

func TestWrapSetsBaseURL(t *testing.T) {
	t.Setenv("ANTHROPIC_BASE_URL", "") // the parent's value must be replaced, not kept
	code, out, errb := runWrapCLI(t, noEnv, "--", "sh", "-c", "echo $ANTHROPIC_BASE_URL")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	if !regexp.MustCompile(`^http://127\.0\.0\.1:\d+/[0-9a-f]{32}/anthropic\n$`).MatchString(out) {
		t.Errorf("base URL = %q", out)
	}
	// A fresh token per run.
	_, out2, _ := runWrapCLI(t, noEnv, "--", "sh", "-c", "echo $ANTHROPIC_BASE_URL")
	if out == out2 {
		t.Errorf("token reused across runs: %q", out)
	}
}

func TestWrapExitCode(t *testing.T) {
	for _, c := range []struct {
		script string
		want   int
	}{{"exit 0", 0}, {"exit 3", 3}, {"kill -KILL $$", 128 + 9}} {
		code, _, errb := runWrapCLI(t, noEnv, "--", "sh", "-c", c.script)
		if code != c.want {
			t.Errorf("%q: code=%d want %d (stderr %q)", c.script, code, c.want, errb)
		}
	}
}

func TestWrapCommandNotFound(t *testing.T) {
	code, _, errb := runWrapCLI(t, noEnv, "--", "/nonexistent/nospy-test-cmd")
	if code != 127 || !strings.Contains(errb, "cannot run") {
		t.Errorf("code=%d stderr=%q", code, errb)
	}
}

// Child args that look like nospy flags belong to the child.
func TestWrapPassesChildArgs(t *testing.T) {
	code, out, _ := runWrapCLI(t, noEnv, "--", "sh", "-c", `echo "$@"`, "sh", "--help", "--log")
	if code != 0 || out != "--help --log\n" {
		t.Errorf("code=%d out=%q", code, out)
	}
}

func TestWrapRefusesChaining(t *testing.T) {
	nospyURL := "http://127.0.0.1:5555/" + strings.Repeat("ab", 16) + "/anthropic"
	for _, c := range []struct {
		name string
		env  string
		args []string
	}{
		{"parent env", nospyURL, []string{"--", "true"}},
		{"flag", "", []string{"--route", "/anthropic=" + nospyURL, "--", "true"}},
		{"localhost name", "http://localhost:5555/" + strings.Repeat("0f", 16) + "/anthropic", []string{"--", "true"}},
	} {
		getenv := func(k string) string {
			if k == "ANTHROPIC_BASE_URL" {
				return c.env
			}
			return ""
		}
		code, out, errb := runWrapCLI(t, getenv, c.args...)
		if code != 2 || out != "" || !strings.Contains(errb, "chain") {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", c.name, code, out, errb)
		}
		if strings.Contains(errb, "5555") || strings.Contains(errb, "abab") {
			t.Errorf("%s: error echoes the URL: %q", c.name, errb)
		}
	}
}

func TestSelectUpstream(t *testing.T) {
	rt := routeTable[0]
	const def = "https://api.anthropic.com"
	cases := []struct {
		name, flag, env, want string
	}{
		{"default", "", "", def},
		{"env over default", "", "https://gw.corp.example/anthropic", "https://gw.corp.example/anthropic"},
		{"flag over env", "https://flag.example", "https://gw.corp.example", "https://flag.example"},
		{"local gateway is not nospy", "", "http://127.0.0.1:4000", "http://127.0.0.1:4000"},
		{"loopback with a non-token path", "", "http://127.0.0.1:4000/v1", "http://127.0.0.1:4000/v1"},
		{"token-like path on a remote host", "", "https://gw.example/" + strings.Repeat("ab", 16), "https://gw.example/" + strings.Repeat("ab", 16)},
	}
	for _, c := range cases {
		u, err := selectUpstream(rt, c.flag, c.env)
		if err != nil || u.String() != c.want {
			t.Errorf("%s: got %v, %v; want %s", c.name, u, err, c.want)
		}
	}
	for _, bad := range []string{"not a url", "ftp://x", "//x", "http://"} {
		if _, err := selectUpstream(rt, bad, ""); err == nil {
			t.Errorf("flag %q: want error", bad)
		} else if strings.Contains(err.Error(), bad) {
			t.Errorf("error echoes the value: %v", err)
		}
	}
}

func TestChildEnv(t *testing.T) {
	got := childEnv([]string{"A=1", "ANTHROPIC_BASE_URL=old", "B=2=3", "ANTHROPIC_BASE_URL_X=keep"}, "ANTHROPIC_BASE_URL=new")
	want := []string{"A=1", "B=2=3", "ANTHROPIC_BASE_URL_X=keep", "ANTHROPIC_BASE_URL=new"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v", got)
	}
}

// fakeAnthropic records request bodies and answers with the placeholders it saw.
type fakeAnthropic struct {
	mu     sync.Mutex
	bodies []string
}

func (f *fakeAnthropic) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.bodies = append(f.bodies, string(b))
	f.mu.Unlock()
	echo := strings.Join(regexp.MustCompile(`\[REDACTED_[A-Z]+_\d+\]`).FindAllString(noNote(b), -1), " ")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "message", "content": []any{map[string]any{"type": "text", "text": "saw " + echo}}})
}

// The whole path: wrapper -> child agent -> proxy -> upstream, and back.
func TestWrapEndToEnd(t *testing.T) {
	up := &fakeAnthropic{}
	srv := httptest.NewServer(up)
	defer srv.Close()
	t.Setenv("NOSPY_TEST_CHILD", "post")

	logPath := t.TempDir() + "/nospy.log"
	code, out, errb := runWrapCLI(t, noEnv, "--route", "/anthropic="+srv.URL, "--log", logPath, "--", os.Args[0])
	if code != 0 {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, errb, out)
	}
	if errb != "" {
		t.Errorf("wrapper wrote to stderr: %q", errb)
	}
	if strings.TrimSpace(out) != "saw "+childEmail {
		t.Errorf("child saw %q, want the restored email", out)
	}
	if len(up.bodies) != 1 || strings.Contains(up.bodies[0], childEmail) || !strings.Contains(up.bodies[0], "[REDACTED_EMAIL_1]") {
		t.Errorf("upstream bodies = %q", up.bodies)
	}
	log, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(log), `"EMAIL":1`) || strings.Contains(string(log), childEmail) {
		t.Errorf("log = %q, err = %v", log, err)
	}
}

func TestWrapMetricsOnByDefault(t *testing.T) {
	up := &fakeAnthropic{}
	srv := httptest.NewServer(up)
	defer srv.Close()
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()
	_ = probe.Close()
	old := wrapMetricsAddr
	wrapMetricsAddr = addr
	defer func() { wrapMetricsAddr = old }()
	t.Setenv("NOSPY_TEST_CHILD", "scrapemetrics")
	t.Setenv("NOSPY_TEST_METRICS_ADDR", addr)

	code, out, errb := runWrapCLI(t, noEnv, "--route", "/anthropic="+srv.URL, "--", os.Args[0])
	if code != 0 {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, errb, out)
	}
	for _, want := range []string{
		`nospy_redactions_total{route="/anthropic",kind="EMAIL"} 1`,
		`nospy_http_requests_total{route="/anthropic",method="POST",status="200",handling="local"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics missing %q:\n%s", want, out)
		}
	}
	_, metrics, _ := strings.Cut(out, "\n") // the first line is the child's own "saw <email>"
	if strings.Contains(metrics, childEmail) {
		t.Errorf("metrics leaked the email:\n%s", metrics)
	}
}

// A second session, or --metrics=false, leaves the fixed port alone and still works.
func TestWrapMetricsPortTakenOrDisabled(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	old := wrapMetricsAddr
	wrapMetricsAddr = busy.Addr().String()
	defer func() { wrapMetricsAddr = old }()

	for _, c := range []struct {
		args []string
		warn bool
	}{{nil, true}, {[]string{"--metrics=false"}, false}} {
		args := append(c.args, "--", "sh", "-c", "echo $ANTHROPIC_BASE_URL")
		code, out, errb := runWrapCLI(t, noEnv, args...)
		if code != 0 || !strings.HasPrefix(out, "http://127.0.0.1:") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", args, code, out, errb)
		}
		if got := strings.Contains(errb, "metrics port "+busy.Addr().String()+" is in use"); got != c.warn {
			t.Errorf("%v: warning on stderr = %v, want %v (stderr %q)", args, got, c.warn, errb)
		}
		if strings.Contains(out, busy.Addr().String()) {
			t.Errorf("%v: session used the busy metrics port: %q", args, out)
		}
	}
}

// syncBuffer lets a test poll output that exec's copier goroutine is still writing.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// SIGTERM sent to nospy reaches the child, and nospy returns the child's exit code.
func TestWrapForwardsSIGTERM(t *testing.T) {
	var out syncBuffer
	var errb bytes.Buffer
	done := make(chan int, 1)
	go func() {
		script := `trap 'echo got-term; exit 7' TERM; echo ready; while :; do sleep 0.05; done`
		done <- run([]string{"--", "sh", "-c", script}, noEnv, strings.NewReader(""), &out, &errb)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "ready") {
		if time.Now().After(deadline) {
			t.Fatal("child never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 7 || !strings.Contains(out.String(), "got-term") {
			t.Errorf("code=%d out=%q stderr=%q", code, out.String(), errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("wrapper did not exit after SIGTERM")
	}
}

func setNoTrafficAfter(t *testing.T, d time.Duration) {
	t.Helper()
	old := noTrafficAfter
	noTrafficAfter = d
	t.Cleanup(func() { noTrafficAfter = old })
}

func TestTripwireCountsOnlyTokenRequests(t *testing.T) {
	const tok = "0123456789abcdef0123456789abcdef"
	tw := &tripwire{token: tok, next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})}
	for path, want := range map[string]int64{
		"/" + strings.Repeat("0", 32) + "/anthropic/v1/messages": 0, // wrong token
		"/anthropic/v1/messages":                                 0, // no token
		"/" + tok[:31] + "/anthropic":                            0,
		"/" + tok + "x/anthropic":                                0,
		"/" + tok + "/anthropic/v1/messages":                     1,
	} {
		before := tw.count()
		tw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", path, nil))
		if got := tw.count() - before; got != want {
			t.Errorf("%s: counted %d, want %d", path, got, want)
		}
	}
}

func TestTripwireFiresWithoutTraffic(t *testing.T) {
	setNoTrafficAfter(t, 100*time.Millisecond)
	for _, c := range []struct {
		script string
		code   int
	}{{"sleep 0.3", 0}, {"sleep 0.3; exit 5", 5}} {
		code, out, errb := runWrapCLI(t, noEnv, "--", "sh", "-c", c.script)
		if code != c.code || out != "" {
			t.Errorf("%q: code=%d stdout=%q", c.script, code, out)
		}
		if errb != noTrafficWarning+"\n" {
			t.Errorf("%q: stderr = %q", c.script, errb)
		}
	}
	const want = "nospy: warning: agent sent zero requests through nospy. The agent may be using its own base URL, so its traffic was not redacted."
	if noTrafficWarning != want {
		t.Errorf("warning text changed: %q", noTrafficWarning)
	}
}

func TestTripwireSilentForShortRun(t *testing.T) {
	setNoTrafficAfter(t, 10*time.Second)
	code, _, errb := runWrapCLI(t, noEnv, "--", "sh", "-c", "true")
	if code != 0 || errb != "" {
		t.Errorf("code=%d stderr=%q", code, errb)
	}
}

func TestTripwireSilentWhenRequestArrives(t *testing.T) {
	setNoTrafficAfter(t, 0) // any run would warn if nothing were counted
	srv := httptest.NewServer(&fakeAnthropic{})
	defer srv.Close()
	t.Setenv("NOSPY_TEST_CHILD", "post")
	code, _, errb := runWrapCLI(t, noEnv, "--route", "/anthropic="+srv.URL, "--", os.Args[0])
	if code != 0 || errb != "" {
		t.Errorf("code=%d stderr=%q", code, errb)
	}
}

func TestTripwireIgnoresWrongToken(t *testing.T) {
	setNoTrafficAfter(t, 0)
	srv := httptest.NewServer(&fakeAnthropic{})
	defer srv.Close()
	t.Setenv("NOSPY_TEST_CHILD", "badtoken")
	code, _, errb := runWrapCLI(t, noEnv, "--route", "/anthropic="+srv.URL, "--", os.Args[0])
	if code != 0 || errb != noTrafficWarning+"\n" {
		t.Errorf("code=%d stderr=%q", code, errb)
	}
}

func TestWrapSetsOpenAIBaseURL(t *testing.T) {
	t.Setenv("OPENAI_BASE_URL", "") // the parent's value must be replaced, not kept
	code, out, errb := runWrapCLI(t, noEnv, "--", "sh", "-c", "echo $ANTHROPIC_BASE_URL $OPENAI_BASE_URL")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	re := regexp.MustCompile(`^http://127\.0\.0\.1:(\d+)/([0-9a-f]{32})/anthropic http://127\.0\.0\.1:(\d+)/([0-9a-f]{32})/openai/v1\n$`)
	m := re.FindStringSubmatch(out)
	if m == nil || m[1] != m[3] || m[2] != m[4] {
		t.Errorf("base URLs = %q", out)
	}
}

func TestWrapProviderPointsEnvVarAtIt(t *testing.T) {
	code, out, errb := runWrapCLI(t, noEnv, "--provider", "ollama", "--", "sh", "-c", "echo $ANTHROPIC_BASE_URL $OPENAI_BASE_URL")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	if !regexp.MustCompile(`/anthropic http://127\.0\.0\.1:\d+/[0-9a-f]{32}/ollama/v1\n$`).MatchString(out) {
		t.Errorf("base URLs = %q", out)
	}
}

func TestWrapProviderAndRouteUsageErrors(t *testing.T) {
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--provider", "nosuch", "--", "true"}, "nospy providers"},
		{[]string{"--route", "/myllm=http://x", "--", "true"}, "api="},
		{[]string{"--route", "/myllm=http://x,api=gemini", "--", "true"}, "api must be"},
		{[]string{"--route", "/openai=http://a", "--route", "/openai=http://b", "--", "true"}, "more than once"},
		{[]string{"--route", "/ollama=http://a,api=openai", "--provider", "ollama", "--", "true"}, "already defined"},
	} {
		code, out, errb := runWrapCLI(t, noEnv, c.args...)
		if code != 2 || out != "" || !strings.Contains(errb, c.want) {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", c.args, code, out, errb)
		}
	}
}

// The chaining refusal covers the OpenAI route too (env var, flag and new routes), while a plain
// local server such as Ollama's port is accepted.
func TestWrapRefusesChainingOnEveryRoute(t *testing.T) {
	nospyURL := "http://127.0.0.1:5555/" + strings.Repeat("ab", 16) + "/openai/v1"
	getenv := func(k string) string {
		if k == "OPENAI_BASE_URL" {
			return nospyURL
		}
		return ""
	}
	for name, c := range map[string]struct {
		getenv func(string) string
		args   []string
	}{
		"env":      {getenv, []string{"--", "true"}},
		"flag":     {noEnv, []string{"--route", "/openai=" + nospyURL, "--", "true"}},
		"new":      {noEnv, []string{"--route", "/x=" + nospyURL + ",api=openai", "--", "true"}},
		"new (an)": {noEnv, []string{"--route", "/x=" + nospyURL + ",api=anthropic", "--", "true"}},
	} {
		code, out, errb := runWrapCLI(t, c.getenv, c.args...)
		if code != 2 || out != "" || !strings.Contains(errb, "chain") || strings.Contains(errb, "5555") {
			t.Errorf("%s: code=%d stdout=%q stderr=%q", name, code, out, errb)
		}
	}
	code, _, errb := runWrapCLI(t, noEnv, "--route", "/openai=http://127.0.0.1:11434/v1", "--", "true")
	if code != 0 || errb != "" {
		t.Errorf("plain local upstream refused: code=%d stderr=%q", code, errb)
	}
}

// fakeOpenAIChat answers a chat completion echoing the placeholders it saw.
type fakeOpenAIChat struct {
	mu            sync.Mutex
	bodies, paths []string
}

func (f *fakeOpenAIChat) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.bodies = append(f.bodies, string(b))
	f.paths = append(f.paths, r.URL.Path)
	f.mu.Unlock()
	echo := strings.Join(regexp.MustCompile(`\[REDACTED_[A-Z]+_\d+\]`).FindAllString(noNote(b), -1), " ")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"object": "chat.completion", "choices": []any{
		map[string]any{"index": 0, "message": map[string]any{"role": "assistant", "content": "saw " + echo}}}})
}

// The whole OpenAI path: wrapper -> child agent -> proxy -> upstream, and back.
func TestWrapEndToEndOpenAI(t *testing.T) {
	up := &fakeOpenAIChat{}
	srv := httptest.NewServer(up)
	defer srv.Close()
	t.Setenv("NOSPY_TEST_CHILD", "postchat")
	logPath := t.TempDir() + "/nospy.log"
	code, out, errb := runWrapCLI(t, noEnv, "--route", "/openai="+srv.URL+"/v1", "--log", logPath, "--", os.Args[0])
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, errb, out)
	}
	if strings.TrimSpace(out) != "saw "+childEmail {
		t.Errorf("child saw %q, want the restored email", out)
	}
	if len(up.bodies) != 1 || strings.Contains(up.bodies[0], childEmail) || !strings.Contains(up.bodies[0], "[REDACTED_EMAIL_1]") {
		t.Errorf("upstream bodies = %q", up.bodies)
	}
	if up.paths[0] != "/v1/chat/completions" {
		t.Errorf("upstream path = %q, want /v1/chat/completions (no /v1/v1)", up.paths[0])
	}
	log, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(log), `"EMAIL":1`) || strings.Contains(string(log), childEmail) {
		t.Errorf("log = %q, err = %v", log, err)
	}
}

func TestProvidersCommand(t *testing.T) {
	code, out, errb := runCLI(t, "", "providers")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	if !regexp.MustCompile(`(?m)^NAME\s+API\s+UPSTREAM$`).MatchString(out) ||
		!regexp.MustCompile(`(?m)^ollama\s+openai\s+http://127\.0\.0\.1:11434/v1$`).MatchString(out) {
		t.Errorf("listing:\n%s", out)
	}
	if code, out, _ := runCLI(t, "", "help", "providers"); code != 0 || !strings.Contains(out, "usage: nospy providers") {
		t.Errorf("help providers: code=%d out=%q", code, out)
	}
	if code, _, errb := runCLI(t, "", "providers", "extra"); code != 2 || !strings.Contains(errb, "usage:") {
		t.Errorf("extra arg: code=%d stderr=%q", code, errb)
	}
}

// Every route's upstream host stays out of redaction, not only the first route's.
func TestDetectorAllowsEveryRouteHost(t *testing.T) {
	rs, err := buildWrapRoutes(nil, nil, noGetenv)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range upstreamHosts(rs) {
		if !redactKeepsHost(h) {
			t.Errorf("host %s would be redacted", h)
		}
	}
}

func redactKeepsHost(host string) bool {
	det := redact.NewDetector(redact.Config{AllowHosts: upstreamHosts(mustRoutes())})
	out, _ := redact.NewRedactor(det, redact.NewVault()).Redact("see https://" + host + "/v1")
	return !strings.Contains(out, "[REDACTED_")
}

func mustRoutes() []wrapRoute {
	rs, _ := buildWrapRoutes(nil, nil, noGetenv)
	return rs
}

// A bad terms file is a usage error before any child starts.
func TestWrapBadTermsFile(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	p := writeTerms(t, "[lower]\nre:(oops\n")
	code, _, errb := runWrapCLI(t, noEnv, "--terms", p, "--", "sh", "-c", "touch "+marker)
	if code != exitUsage {
		t.Fatalf("code = %d, stderr=%q", code, errb)
	}
	if !strings.Contains(errb, "terms line 1: invalid section name") || !strings.Contains(errb, "terms line 2: invalid regex") || strings.Contains(errb, "oops") {
		t.Errorf("stderr = %q", errb)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("child ran despite a bad terms file")
	}
}

// Terms reach the proxy's detector, and the log carries counts only.
func TestWrapTermsEndToEnd(t *testing.T) {
	up := &fakeAnthropic{}
	srv := httptest.NewServer(up)
	defer srv.Close()
	t.Setenv("NOSPY_TEST_CHILD", "post")

	// [ALLOW] is visible end to end: the email the child sends is no longer redacted.
	p := writeTerms(t, "Project Falcon\n[CODENAME]\nbluebird\n[ALLOW]\n"+childEmail+"\n")
	logPath := filepath.Join(t.TempDir(), "nospy.log")
	code, out, errb := runWrapCLI(t, noEnv, "--terms", p, "--route", "/anthropic="+srv.URL, "--log", logPath, "--", os.Args[0])
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q stdout=%q", code, errb, out)
	}
	if len(up.bodies) != 1 || !strings.Contains(up.bodies[0], childEmail) {
		t.Errorf("upstream bodies = %q", up.bodies)
	}
	log, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(log), "loaded 2 terms in 2 sections") {
		t.Fatalf("log = %q, err = %v", log, err)
	}
	for _, leak := range []string{"Falcon", "bluebird", "CODENAME"} {
		if strings.Contains(string(log), leak) {
			t.Errorf("log leaks %q: %s", leak, log)
		}
	}
}
