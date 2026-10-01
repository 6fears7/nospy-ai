package payload

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"nospyai/internal/redact"
)

// stripNote removes the note from an encoded redacted body, wherever a dialect merged it.
func stripNote(s string) string {
	for _, form := range []string{`\n\n` + PlaceholderNote, `,{"text":"` + PlaceholderNote + `","type":"text"}`} {
		s = strings.ReplaceAll(s, form, "")
	}
	return s
}

// redactDoc redacts body and returns the result as a generic document.
func redactDoc(t *testing.T, d Dialect, body string, v *redact.Vault) map[string]any {
	t.Helper()
	out, _, err := RedactRequest(d, []byte(body), redact.NewRedactor(testDet, v))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	return doc
}

func TestNoteIsConstantAndAgnostic(t *testing.T) {
	for _, vendor := range []string{"anthropic", "claude", "openai", "gpt", "codex"} {
		if strings.Contains(strings.ToLower(PlaceholderNote), vendor) {
			t.Errorf("note names %q", vendor)
		}
	}
	if strings.Contains(PlaceholderNote, "\n") || strings.Contains(PlaceholderNote, `"`) {
		t.Error("note must be one plain line without double quotes")
	}
}

func TestNoteAnthropic(t *testing.T) {
	const user = `{"role":"user","content":"mail alice@corp.io"}`
	block := map[string]any{"type": "text", "text": PlaceholderNote}
	cases := []struct {
		name, body string
		want       any // the "system" value
	}{
		{"string", `{"system":"be brief","messages":[` + user + `]}`, "be brief\n\n" + PlaceholderNote},
		{"empty string", `{"system":"","messages":[` + user + `]}`, PlaceholderNote},
		{"absent", `{"messages":[` + user + `]}`, PlaceholderNote},
		{"null", `{"system":null,"messages":[` + user + `]}`, PlaceholderNote},
		{"array", `{"system":[{"type":"text","text":"be brief","cache_control":{"type":"ephemeral"}}],"messages":[` + user + `]}`,
			[]any{map[string]any{"type": "text", "text": "be brief", "cache_control": map[string]any{"type": "ephemeral"}}, block}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := redactDoc(t, Anthropic, c.body, redact.NewVault())
			if !reflect.DeepEqual(doc["system"], c.want) {
				t.Errorf("system = %#v, want %#v", doc["system"], c.want)
			}
			if !strings.Contains(mustJSON(doc), "[REDACTED_EMAIL_1]") {
				t.Errorf("message not redacted: %s", mustJSON(doc))
			}
		})
	}
}

func TestNoteAnthropicNeedsMessagesAndRedaction(t *testing.T) {
	for name, body := range map[string]string{
		"nothing redacted": `{"system":"be brief","messages":[{"role":"user","content":"hello"}]}`,
		"no messages":      `{"system":"mail alice@corp.io"}`,
	} {
		doc := redactDoc(t, Anthropic, body, redact.NewVault())
		if strings.Contains(mustJSON(doc), "privacy proxy") {
			t.Errorf("%s: note added: %s", name, mustJSON(doc))
		}
	}
}

func TestNoteOpenAIChat(t *testing.T) {
	const user = `{"role":"user","content":"mail alice@corp.io"}`
	sys := func(role string, content any) map[string]any {
		return map[string]any{"role": role, "content": content}
	}
	noteMsg := sys("system", PlaceholderNote)
	block := map[string]any{"type": "text", "text": PlaceholderNote}
	userMsg := sys("user", "mail [REDACTED_EMAIL_1]")
	cases := []struct {
		name, body string
		want       []any
	}{
		{"system string", `{"messages":[{"role":"system","content":"be brief"},` + user + `]}`,
			[]any{sys("system", "be brief\n\n"+PlaceholderNote), userMsg}},
		{"developer string", `{"messages":[{"role":"developer","content":"be brief"},` + user + `]}`,
			[]any{sys("developer", "be brief\n\n"+PlaceholderNote), userMsg}},
		{"system array", `{"messages":[{"role":"system","content":[{"type":"text","text":"be brief"}]},` + user + `]}`,
			[]any{sys("system", []any{map[string]any{"type": "text", "text": "be brief"}, block}), userMsg}},
		{"system null content", `{"messages":[{"role":"system","content":null},` + user + `]}`,
			[]any{noteMsg, sys("system", nil), userMsg}},
		{"no system", `{"messages":[` + user + `]}`, []any{noteMsg, userMsg}},
		{"system not first", `{"messages":[` + user + `,{"role":"system","content":"late"}]}`,
			[]any{noteMsg, userMsg, sys("system", "late")}},
		{"empty messages with tools", `{"messages":[],"tools":[],"input":"x"}`, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := redactDoc(t, OpenAIChat, c.body, redact.NewVault())
			if c.want == nil {
				if strings.Contains(mustJSON(doc), "privacy proxy") {
					t.Errorf("note added: %s", mustJSON(doc))
				}
				return
			}
			if !reflect.DeepEqual(doc["messages"], c.want) {
				t.Errorf("messages = %s\nwant %s", mustJSON(doc["messages"]), mustJSON(c.want))
			}
		})
	}
}

func TestNoteOpenAIChatSkipsEmbeddingsAndUnredacted(t *testing.T) {
	for name, body := range map[string]string{
		"embeddings":       `{"model":"text-embedding-3-small","input":"mail alice@corp.io"}`,
		"nothing redacted": `{"messages":[{"role":"user","content":"hello"}]}`,
	} {
		doc := redactDoc(t, OpenAIChat, body, redact.NewVault())
		if strings.Contains(mustJSON(doc), "privacy proxy") {
			t.Errorf("%s: note added: %s", name, mustJSON(doc))
		}
	}
	doc := redactDoc(t, OpenAIChat, `{"input":"mail alice@corp.io"}`, redact.NewVault())
	if _, ok := doc["messages"]; ok {
		t.Errorf("embeddings body gained messages: %s", mustJSON(doc))
	}
}

func TestNoteOpenAIResponses(t *testing.T) {
	const input = `"input":"mail alice@corp.io"`
	cases := []struct {
		name, body, want string
	}{
		{"present", `{"instructions":"be brief",` + input + `}`, "be brief\n\n" + PlaceholderNote},
		{"absent", `{` + input + `}`, PlaceholderNote},
		{"null", `{"instructions":null,` + input + `}`, PlaceholderNote},
		{"empty", `{"instructions":"",` + input + `}`, PlaceholderNote},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			doc := redactDoc(t, OpenAIResponses, c.body, redact.NewVault())
			if doc["instructions"] != c.want {
				t.Errorf("instructions = %#v, want %q", doc["instructions"], c.want)
			}
		})
	}
}

// A Responses chain continues the earlier request's vault: this turn has nothing to redact, but
// the history held at the provider does contain placeholders, and instructions don't carry over.
func TestNoteOpenAIResponsesChainedVault(t *testing.T) {
	v := redact.NewVault()
	v.Placeholder(redact.KindEmail, "alice@corp.io")
	body := `{"previous_response_id":"resp_prev","input":"and now?"}`
	doc := redactDoc(t, OpenAIResponses, body, v)
	if doc["instructions"] != PlaceholderNote {
		t.Errorf("instructions = %#v", doc["instructions"])
	}
	if doc := redactDoc(t, OpenAIResponses, body, redact.NewVault()); doc["instructions"] != nil {
		t.Errorf("empty vault got instructions %#v", doc["instructions"])
	}
}

func TestNoteIsNeverRedactedOrRestoredAway(t *testing.T) {
	for _, c := range []struct {
		d    Dialect
		body string
	}{
		{Anthropic, anthropicReq},
		{OpenAIChat, chatRequest()},
		{OpenAIResponses, responsesRequest()},
	} {
		out, _ := redactWith(t, c.d, c.body)
		if !strings.Contains(out, PlaceholderNote) {
			t.Errorf("%s: note missing or altered:\n%s", c.d.Name, out)
		}
		// The example placeholder is not one the vault issued, so restoring leaves it alone.
		v := redact.NewVault()
		v.Placeholder(redact.KindEmail, "alice@corp.io")
		back, err := RestoreResponse(c.d, []byte(out), v)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(back), PlaceholderNote) {
			t.Errorf("%s: restore changed the note", c.d.Name)
		}
	}
}

// Same body in, same bytes out: the note must not break prompt-cache stability.
func TestNoteIsCacheStable(t *testing.T) {
	for _, c := range []struct {
		d    Dialect
		body string
	}{
		{Anthropic, anthropicReq},
		{OpenAIChat, chatRequest()},
		{OpenAIResponses, responsesRequest()},
	} {
		first, _ := redactWith(t, c.d, c.body)
		for i := 0; i < 20; i++ {
			if got, _ := redactWith(t, c.d, c.body); got != first {
				t.Fatalf("%s run %d differs:\n%s\n%s", c.d.Name, i, first, got)
			}
		}
	}
}

func TestNoteLeavesCacheControlAlone(t *testing.T) {
	out, _ := redactWith(t, Anthropic, anthropicReq)
	if n := strings.Count(out, "cache_control"); n != strings.Count(anthropicReq, "cache_control") {
		t.Errorf("cache_control count = %d:\n%s", n, out)
	}
	if !strings.Contains(out, `"cache_control":{"type":"ephemeral"}`) {
		t.Errorf("existing block lost its cache_control:\n%s", out)
	}
}
