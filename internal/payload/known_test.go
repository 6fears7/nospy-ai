package payload

import (
	"strings"
	"testing"

	"nospyai/internal/redact"
)

const (
	keyedFile = "     1\t# app\n     2\tDB_PASSWORD=hunter2hunter2\n"
	prose     = "the password is hunter2hunter2"
)

// anthropicHistory builds a request whose history holds the keyed original (a tool result)
// and the restored value back as prose in an assistant turn, in the given order.
func anthropicHistory(proseFirst bool) string {
	tr := `{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":` + jsonStr(keyedFile) + `}]}`
	as := `{"role":"assistant","content":[{"type":"text","text":` + jsonStr(prose) + `}]}`
	first, second := tr, as
	if proseFirst {
		first, second = as, tr
	}
	return `{"model":"claude-opus-5-5","system":"x","messages":[{"role":"user","content":"mail alice@corp.io"},` +
		first + `,` + second + `]}`
}

func redactFresh(t *testing.T, body string) (string, map[string]int, *redact.Vault) {
	t.Helper()
	v := redact.NewVault()
	out, counts, err := RedactRequest(Anthropic, []byte(body), redact.NewRedactor(testDet, v))
	if err != nil {
		t.Fatal(err)
	}
	return string(out), counts, v
}

// The value a context rule found is redacted wherever else it sits in the same request, with
// the same placeholder, whichever spot comes first in visiting order.
func TestRedactRequestRestoredValueInProse(t *testing.T) {
	for _, proseFirst := range []bool{false, true} {
		body := anthropicHistory(proseFirst)
		out, counts, v := redactFresh(t, body)
		if strings.Contains(out, "hunter2hunter2") {
			t.Fatalf("proseFirst=%v: leaked: %s", proseFirst, out)
		}
		if n := strings.Count(out, "[REDACTED_SECRET_1]"); n != 2 {
			t.Errorf("proseFirst=%v: %d uses of [REDACTED_SECRET_1], want 2: %s", proseFirst, n, out)
		}
		if !strings.Contains(out, "the password is [REDACTED_SECRET_1]") || !strings.Contains(out, "mail [REDACTED_EMAIL_1]") {
			t.Errorf("proseFirst=%v: placeholders or numbering changed: %s", proseFirst, out)
		}
		// The literal hit counts under its kind, next to the rule's own.
		if counts[redact.KindSecret] != 2 || counts[redact.KindEmail] != 1 {
			t.Errorf("proseFirst=%v: counts = %v", proseFirst, counts)
		}
		back, err := RestoreResponse(Anthropic, []byte(out), v)
		if err != nil {
			t.Fatal(err)
		}
		if got := stripNote(string(back)); !jsonEqual(got, body) {
			t.Errorf("proseFirst=%v: round trip differs:\n%s\n%s", proseFirst, got, body)
		}
	}
}

// Numbering follows the rules' first appearances only: a literal hit never takes a number, and
// two runs over one body agree.
func TestRedactRequestTwoPassStable(t *testing.T) {
	body := anthropicHistory(true)
	first, _, _ := redactFresh(t, body)
	for i := 0; i < 20; i++ {
		if got, _, _ := redactFresh(t, body); got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, got)
		}
	}
	// Appending a turn that adds a second secret later must not renumber the first.
	grown := strings.TrimSuffix(body, "]}") + `,{"role":"user","content":"API_KEY=zxcvbnm98765"}]}`
	out, _, _ := redactFresh(t, grown)
	if !strings.Contains(out, "the password is [REDACTED_SECRET_1]") || !strings.Contains(out, "[REDACTED_SECRET_2]") {
		t.Errorf("numbering changed: %s", out)
	}
}

// Encoded tool arguments are walked in both passes too.
func TestRedactRequestLiteralInToolArguments(t *testing.T) {
	body := `{"model":"gpt-5","messages":[` +
		`{"role":"tool","tool_call_id":"c1","content":` + jsonStr(keyedFile) + `},` +
		`{"role":"assistant","tool_calls":[{"id":"c2","type":"function","function":{"name":"note","arguments":` +
		jsonStr(`{"text":"pw hunter2hunter2"}`) + `}}]}]}`
	v := redact.NewVault()
	out, _, err := RedactRequest(OpenAIChat, []byte(body), redact.NewRedactor(testDet, v))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2hunter2") {
		t.Errorf("leaked: %s", out)
	}
}

// admin is a USER (from a home path). It doesn't hit inside administrator, and a name shorter
// than four characters is left to the rules.
func TestRedactRequestLiteralBoundaries(t *testing.T) {
	body := `{"model":"claude-opus-5-5","system":"x","messages":[{"role":"user","content":` +
		jsonStr("cwd /home/admin/app and /home/bob/app\nadministrator: admin, bob; (admin) admin_x xadmin") + `}]}`
	out, _, _ := redactFresh(t, body)
	for _, want := range []string{"administrator: [REDACTED_USER_1], bob; ([REDACTED_USER_1]) admin_x xadmin"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	if !strings.Contains(out, "/home/[REDACTED_USER_2]/app") { // bob: the rule finds it, the literal doesn't
		t.Errorf("rule hit missing: %s", out)
	}
}

// A known value is found in a request that has no key beside it, and registered in that
// request's fresh vault, so the response restores it.
func TestRedactRequestKnownValues(t *testing.T) {
	known := []redact.Known{{Kind: redact.KindSecret, Value: "hunter2hunter2"}}
	body := `{"model":"claude-opus-5-5","system":"x","messages":[{"role":"user","content":"mail alice@corp.io, ` + prose + `"}]}`
	v := redact.NewVault()
	r := redact.NewRedactor(testDet, v).WithKnown(redact.NewKnownSet(known))
	out, counts, err := RedactRequest(Anthropic, []byte(body), r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2hunter2") || !strings.Contains(string(out), "the password is [REDACTED_SECRET_1]") {
		t.Fatalf("known value not redacted: %s", out)
	}
	if counts[redact.KindSecret] != 1 {
		t.Errorf("counts = %v", counts)
	}
	back, _ := RestoreResponse(Anthropic, out, v)
	if !strings.Contains(string(back), prose) {
		t.Errorf("not restored: %s", back)
	}
	// Both are remembered kinds' sightings: the secret yes, the email no.
	if got := r.Found(); len(got) != 1 || got[0].Value != "hunter2hunter2" || got[0].Kind != redact.KindSecret {
		t.Errorf("Found = %v", got)
	}
	// Without the set the same body leaks the value.
	if plain, _, _ := redactFresh(t, body); !strings.Contains(plain, "hunter2hunter2") {
		t.Fatal("test body is not a leak without the known set")
	}
}

// Numbers still follow first appearance when a known value is found: it takes the next number
// of its kind in visiting order, so appending history keeps earlier numbers.
func TestRedactRequestKnownValuesNumbering(t *testing.T) {
	known := []redact.Known{{Kind: redact.KindSecret, Value: "hunter2hunter2"}}
	body := `{"model":"claude-opus-5-5","system":"x","messages":[{"role":"user","content":"API_KEY=zxcvbnm98765"},{"role":"user","content":"` + prose + `"}]}`
	run := func() string {
		out, _, err := RedactRequest(Anthropic, []byte(body), redact.NewRedactor(testDet, redact.NewVault()).WithKnown(redact.NewKnownSet(known)))
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}
	out := run()
	if !strings.Contains(out, "API_KEY=[REDACTED_SECRET_1]") || !strings.Contains(out, "the password is [REDACTED_SECRET_2]") {
		t.Errorf("numbering: %s", out)
	}
	if run() != out {
		t.Error("two runs differ")
	}
}

// A 1 MB request in 2000 messages with 200 secrets in its vault: the whole two-pass walk, and
// the same body with an empty vault for comparison.
func BenchmarkRedactRequestVaultLiterals(b *testing.B) {
	line := strings.Repeat("The quick brown fox jumps over the lazy dog while reading logs. ", 8)
	var sb strings.Builder
	sb.WriteString(`{"model":"claude-opus-5-5","system":"x","messages":[`)
	for i := 0; i < 2000; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"role":"user","content":` + jsonStr(line) + `}`)
	}
	sb.WriteString(`]}`)
	body := []byte(sb.String())
	run := func(b *testing.B, n int) {
		b.SetBytes(int64(len(body)))
		for i := 0; i < b.N; i++ {
			v := redact.NewVault()
			for j := 0; j < n; j++ {
				v.Placeholder(redact.KindSecret, "secretvalue-"+strings.Repeat("x", j%7)+string(rune('a'+j%26))+string(rune('a'+j/26)))
			}
			if _, _, err := RedactRequest(Anthropic, body, redact.NewRedactor(testDet, v)); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run("vault=0", func(b *testing.B) { run(b, 0) })
	b.Run("vault=200", func(b *testing.B) { run(b, 200) })
}
