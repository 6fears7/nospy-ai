package payload

import (
	"encoding/json"
	"strings"
	"testing"

	"nospyai/internal/redact"
)

var testDet = redact.NewDetector(redact.Config{AllowHosts: []string{"api.anthropic.com"}})

const anthropicReq = `{
  "model": "claude-opus-5-5",
  "max_tokens": 1024,
  "system": [{"type": "text", "text": "Deploy host is build.corp.io", "cache_control": {"type": "ephemeral"}}],
  "tools": [{"name": "Bash", "description": "Run a command on 10.9.9.9",
             "input_schema": {"type": "object", "properties": {"cmd": {"type": "string", "pattern": "^ssh 10\\.0\\.0\\.5$"}}}}],
  "messages": [
    {"role": "user", "content": "my email is alice@corp.io"},
    {"role": "assistant", "content": [
      {"type": "thinking", "thinking": "user said a@b.com", "signature": "c2lnbmVk"},
      {"type": "tool_use", "id": "toolu_01", "name": "Bash",
       "input": {"command": "ssh 10.0.0.5", "name": "bob@corp.io", "type": "carol@corp.io"}}
    ]},
    {"role": "user", "content": [
      {"type": "tool_result", "tool_use_id": "toolu_01", "content": "db_url: x\npassword=hunter22\n"},
      {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"}}
    ]}
  ]
}`

func TestRedactRequestAnthropic(t *testing.T) {
	r := redact.NewRedactor(testDet, redact.NewVault())
	out, counts, err := RedactRequest(Anthropic, []byte(anthropicReq), r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, secret := range []string{"alice@corp.io", "bob@corp.io", "carol@corp.io", "10.0.0.5\"", "hunter22", "build.corp.io", "10.9.9.9"} {
		if strings.Contains(s, secret) {
			t.Errorf("leaked %q", secret)
		}
	}
	for _, keep := range []string{
		`"thinking":"user said a@b.com"`, `"signature":"c2lnbmVk"`, // signed block untouched
		`iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk`, // image untouched
		`"pattern":"^ssh 10\\.0\\.0\\.5$"`,                             // input_schema untouched
		`"model":"claude-opus-5-5"`, `"id":"toolu_01"`, `"tool_use_id":"toolu_01"`, `"max_tokens":1024`,
	} {
		if !strings.Contains(s, keep) {
			t.Errorf("missing %s in %s", keep, s)
		}
	}
	if counts[redact.KindEmail] != 3 || counts[redact.KindIPv4] != 2 {
		t.Errorf("counts = %v", counts)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
}

func TestRedactRequestInvalidJSON(t *testing.T) {
	r := redact.NewRedactor(testDet, redact.NewVault())
	for _, in := range []string{`{"messages": [`, `{"a":1} {"b":2}`, ``} {
		if _, _, err := RedactRequest(Anthropic, []byte(in), r); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}

func TestRedactRequestIdempotent(t *testing.T) {
	r := redact.NewRedactor(testDet, redact.NewVault())
	once, _, err := RedactRequest(Anthropic, []byte(anthropicReq), r)
	if err != nil {
		t.Fatal(err)
	}
	twice, counts, err := RedactRequest(Anthropic, once, r)
	if err != nil {
		t.Fatal(err)
	}
	// The note is added to every request with a non-empty vault, so a second pass adds it again.
	if stripNote(string(once)) != stripNote(string(twice)) || len(counts) != 0 || strings.Count(string(twice), PlaceholderNote) != 2 {
		t.Fatalf("second pass changed output (counts %v)", counts)
	}
}

func TestRedactRequestLargeNumbersPreserved(t *testing.T) {
	r := redact.NewRedactor(testDet, redact.NewVault())
	out, _, err := RedactRequest(Anthropic, []byte(`{"max_tokens":12345678901234567890,"temperature":0.7}`), r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "12345678901234567890") || !strings.Contains(string(out), "0.7") {
		t.Fatalf("got %s", out)
	}
}

// Fresh vault per request (invariant 3) must still give identical placeholders every time,
// and appending a message must not renumber anything earlier (invariant 4).
func TestRedactRequestDeterministicAndPrefixStable(t *testing.T) {
	redactFresh := func(body string) string {
		out, _, err := RedactRequest(Anthropic, []byte(body), redact.NewRedactor(testDet, redact.NewVault()))
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	first := redactFresh(anthropicReq)
	for i := 0; i < 50; i++ {
		if got := redactFresh(anthropicReq); got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, got)
		}
	}
	// Append a turn that introduces new values before the system prompt's value would be
	// visited under sorted-key order ("messages" < "system").
	longer := strings.Replace(anthropicReq, "\n  ]\n}", `,
    {"role": "user", "content": "also dave@corp.io on 10.7.7.7"}
  ]
}`, 1)
	if longer == anthropicReq {
		t.Fatal("fixture edit failed")
	}
	grown := redactFresh(longer)
	for _, want := range []string{"Deploy host is [REDACTED_DOMAIN_1]", "my email is [REDACTED_EMAIL_1]"} {
		if !strings.Contains(first, want) || !strings.Contains(grown, want) {
			t.Errorf("placeholder %q not stable:\n%s\n%s", want, first, grown)
		}
	}
}

// A file an agent read arrives with line numbers in front of every line; the secrets in it are
// still redacted, and restored on the way back.
func TestRedactRequestGutterNumberedFile(t *testing.T) {
	file := "     1\t# app\n     2\tDB_PASSWORD=hunter2hunter2\n     3\tAPI_HOST=build.corp-example.io\n"
	body := `{"model":"claude-opus-5-5","system":"x","messages":[{"role":"user","content":[` +
		`{"type":"tool_result","tool_use_id":"t1","content":` + jsonStr(file) + `}]}]}`
	v := redact.NewVault()
	out, counts, err := RedactRequest(Anthropic, []byte(body), redact.NewRedactor(testDet, v))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2hunter2") || strings.Contains(string(out), "build.corp-example.io") {
		t.Errorf("leaked: %s", out)
	}
	if counts[redact.KindSecret] != 1 || counts[redact.KindDomain] != 1 {
		t.Errorf("counts = %v", counts)
	}
	back, err := RestoreResponse(Anthropic, out, v)
	if err != nil {
		t.Fatal(err)
	}
	if got := stripNote(string(back)); got != body && !jsonEqual(got, body) {
		t.Errorf("round trip differs:\n%s\n%s", got, body)
	}
}
