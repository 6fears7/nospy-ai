package payload

import (
	"encoding/json"
	"strings"
	"testing"

	"nospyai/internal/redact"
)

// Identity metadata is deleted, not redacted (plan/12-identity.md), and dropping it leaves the
// rest of the body, and so the placeholder numbering, exactly as it was.
func TestRedactRequestDropsIdentityKeys(t *testing.T) {
	const tail = `"messages":[{"role":"user","content":"mail alice@corp.io and bob@corp.io from 10.1.2.3"}]`
	cases := []struct {
		name    string
		d       Dialect
		with    string
		without string
		gone    []string
		kept    string
	}{
		{"anthropic", Anthropic,
			`{"model":"claude-opus-5-5","metadata":{"user_id":"user_0a1b2c_account_x_session_y"},` + tail + `}`,
			`{"model":"claude-opus-5-5",` + tail + `}`,
			[]string{"metadata", "user_0a1b2c"}, ""},
		{"chat", OpenAIChat,
			`{"model":"gpt-5","user":"dave@corp.io","safety_identifier":"hash-1","metadata":{"k":"v"},"prompt_cache_key":"sess-1",` + tail + `}`,
			`{"model":"gpt-5","prompt_cache_key":"sess-1",` + tail + `}`,
			[]string{`"user":`, "safety_identifier", "metadata", "dave@corp.io", "hash-1"}, `"prompt_cache_key":"sess-1"`},
		{"responses", OpenAIResponses,
			`{"model":"gpt-5","user":"dave@corp.io","safety_identifier":"hash-1","metadata":{"k":"v"},"prompt_cache_key":"sess-1","input":"mail alice@corp.io and bob@corp.io from 10.1.2.3"}`,
			`{"model":"gpt-5","prompt_cache_key":"sess-1","input":"mail alice@corp.io and bob@corp.io from 10.1.2.3"}`,
			[]string{`"user":`, "safety_identifier", "metadata", "dave@corp.io", "hash-1"}, `"prompt_cache_key":"sess-1"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := redact.NewRedactor(testDet, redact.NewVault())
			out, counts, err := RedactRequest(c.d, []byte(c.with), r)
			if err != nil {
				t.Fatal(err)
			}
			if !json.Valid(out) {
				t.Fatalf("not valid JSON: %s", out)
			}
			for _, g := range c.gone {
				if strings.Contains(string(out), g) {
					t.Errorf("%q still in %s", g, out)
				}
			}
			if c.kept != "" && !strings.Contains(string(out), c.kept) {
				t.Errorf("%s missing from %s", c.kept, out)
			}
			if counts[redact.KindEmail] != 2 {
				t.Errorf("counts = %v: the dropped identity must not be counted or numbered", counts)
			}
			want, _, err := RedactRequest(c.d, []byte(c.without), redact.NewRedactor(testDet, redact.NewVault()))
			if err != nil {
				t.Fatal(err)
			}
			if string(out) != string(want) {
				t.Errorf("numbering changed by the drop:\n got  %s\n want %s", out, want)
			}
		})
	}
}

// Only the root is dropped: a nested key of the same name is user data and is redacted.
func TestRedactRequestDropKeysRootOnly(t *testing.T) {
	body := `{"model":"claude-opus-5-5","messages":[{"role":"user","content":"x"}],"tools":[{"name":"t","description":"d","metadata":"eve@corp.io"}]}`
	out, _ := redactWith(t, Anthropic, body)
	if strings.Contains(out, "eve@corp.io") || !strings.Contains(out, `"metadata":"[REDACTED_EMAIL_1]"`) {
		t.Errorf("got %s", out)
	}
}

// A home directory in tool input or a tool result is redacted and restored like any other value.
func TestRedactRequestHomePathRoundTrip(t *testing.T) {
	body := `{"model":"claude-opus-5-5","system":"Working directory: /Users/alice/src/app","messages":[` +
		`{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Read","input":{"file_path":"/Users/alice/src/app/go.mod"}}]},` +
		`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"C:\\Users\\alice\\x","is_error":false},` +
		`{"type":"image","source":{"type":"base64","media_type":"image/png","data":"AA/home/alice/AA"}},` +
		`{"type":"image","source":{"type":"url","url":"data:image/png;base64,/home/alice/"}}]}]}`
	v := redact.NewVault()
	out, counts, err := RedactRequest(Anthropic, []byte(body), redact.NewRedactor(testDet, v))
	if err != nil {
		t.Fatal(err)
	}
	if counts[redact.KindUser] != 3 {
		t.Errorf("counts = %v", counts)
	}
	s := string(out)
	if !strings.Contains(s, "/Users/[REDACTED_USER_1]/src/app") || !strings.Contains(s, `C:\\Users\\[REDACTED_USER_1]\\x`) {
		t.Errorf("got %s", s)
	}
	if !strings.Contains(s, `"data":"AA/home/alice/AA"`) || !strings.Contains(s, `data:image/png;base64,/home/alice/`) {
		t.Errorf("binary payload was touched: %s", s)
	}
	back, err := RestoreResponse(Anthropic, out, v)
	if err != nil {
		t.Fatal(err)
	}
	back = []byte(stripNote(string(back)))
	if string(back) != body && !jsonEqual(string(back), body) {
		t.Errorf("round trip differs:\n%s\n%s", back, body)
	}
}

func jsonEqual(a, b string) bool {
	var x, y any
	return json.Unmarshal([]byte(a), &x) == nil && json.Unmarshal([]byte(b), &y) == nil && mustJSON(x) == mustJSON(y)
}
