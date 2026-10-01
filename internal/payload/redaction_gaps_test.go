package payload

import (
	"strings"
	"testing"

	"nospyai/internal/redact"
)

func TestRedactRequestDataPrefixedText(t *testing.T) {
	for _, d := range []Dialect{Anthropic, OpenAIChat, OpenAIResponses} {
		t.Run(d.Name, func(t *testing.T) {
			text := "data: alice@example.com password=apricot42"
			body := `{"system":"x","messages":[{"role":"user","content":` + jsonStr(text) + `}]}`
			if d.Name == OpenAIChat.Name {
				body = `{"messages":[{"role":"system","content":"x"},{"role":"user","content":` + jsonStr(text) + `}]}`
			}
			if d.Name == OpenAIResponses.Name {
				body = `{"instructions":"x","input":` + jsonStr(text) + `}`
			}
			out, v := redactWith(t, d, body)
			for _, secret := range []string{"alice@example.com", "apricot42"} {
				if strings.Contains(out, secret) {
					t.Errorf("upstream would receive %q: %s", secret, out)
				}
			}
			back, err := RestoreResponse(d, []byte(out), v)
			if err != nil || !jsonEqual(stripNote(string(back)), body) {
				t.Fatalf("round trip changed text: %s, %v", back, err)
			}
		})
	}
}

func TestRedactRequestStructuredSecrets(t *testing.T) {
	args := `{"auth":"${AUTH_TOKEN}","author":"ordinary","monkey":"banana","nested":{"API_KEY":"tiny","client_secret":"pa\"ss\\word with spaces","token":"abc"},"password":"apricot42","password_hint":"remember it"}`
	for _, tc := range []struct {
		d    Dialect
		body string
	}{
		{Anthropic, `{"system":"x","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"login","input":` + args + `}]}]}`},
		{OpenAIChat, `{"messages":[{"role":"system","content":"x"},{"role":"assistant","tool_calls":[{"id":"t1","type":"function","function":{"name":"login","arguments":` + jsonStr(args) + `}}]}]}`},
		{OpenAIResponses, `{"instructions":"x","input":[{"type":"function_call","call_id":"t1","name":"login","arguments":` + jsonStr(args) + `}]}`},
	} {
		t.Run(tc.d.Name, func(t *testing.T) {
			out, v := redactWith(t, tc.d, tc.body)
			for _, secret := range []string{"apricot42", "tiny", "word with spaces", "abc"} {
				if strings.Contains(out, secret) {
					t.Errorf("upstream would receive %q: %s", secret, out)
				}
			}
			if v.Len() != 4 {
				t.Errorf("vault has %d values, want 4: %s", v.Len(), out)
			}
			back, err := RestoreResponse(tc.d, []byte(out), v)
			if err != nil || !jsonEqual(stripNote(string(back)), tc.body) {
				t.Fatalf("round trip changed arguments: %s, %v", back, err)
			}
			// Replaying already-redacted arguments must not treat a placeholder as a new secret.
			_, replayVault := redactWith(t, tc.d, out)
			if replayVault.Len() != 0 {
				t.Errorf("registered placeholders as secrets: %d", replayVault.Len())
			}
		})
	}
}

func TestRedactRequestMediaURLAndToolData(t *testing.T) {
	body := `{"messages":[{"role":"system","content":"x"},{"role":"user","content":[{"type":"image_url","image_url":{"url":` + jsonStr(pngDataURL) + `}},{"type":"text","text":"data: alice@example.com"}]},{"role":"assistant","tool_calls":[{"function":{"name":"inspect","arguments":` + jsonStr(`{"image_url":{"url":"data: bob@example.com"}}`) + `}}]}]}`
	out, v := redactWith(t, OpenAIChat, body)
	if !strings.Contains(out, pngDataURL) {
		t.Errorf("image data URL changed: %s", out)
	}
	for _, secret := range []string{"alice@example.com", "bob@example.com"} {
		if strings.Contains(out, secret) {
			t.Errorf("upstream would receive %q: %s", secret, out)
		}
	}
	back, err := RestoreResponse(OpenAIChat, []byte(out), v)
	if err != nil || !jsonEqual(stripNote(string(back)), body) {
		t.Fatalf("round trip changed media or tool data: %s, %v", back, err)
	}
}

func TestRedactRequestWholeSecretOverlappingDomain(t *testing.T) {
	text := "PASSWORD=foo.example.com/swordfish\nThe credential is foo.example.com/swordfish"
	body := `{"system":"x","messages":[{"role":"user","content":` + jsonStr(text) + `}]}`
	out, counts, v := redactFresh(t, body)
	if strings.Contains(out, "swordfish") || counts[redact.KindSecret] != 2 {
		t.Fatalf("secret was only partly redacted: %s, counts=%v", out, counts)
	}
	back, err := RestoreResponse(Anthropic, []byte(out), v)
	if err != nil || !jsonEqual(stripNote(string(back)), body) {
		t.Fatalf("round trip changed secret: %s, %v", back, err)
	}
}

// Ordinary arguments that merely look like secret keys (key, sort_key, auth, a "true" password)
// are neither redacted nor remembered, so the same words in prose survive.
func TestRedactRequestFieldKeyFalsePositives(t *testing.T) {
	args := `{"api_key":"zebra8841","auth":"none","clientSecret":"walrus7720","key":"Enter","password":"true","sort_key":"name"}`
	prose := "Press Enter, then sort by name. The flag is none."
	for _, tc := range []struct {
		d    Dialect
		body string
	}{
		{Anthropic, `{"system":"x","messages":[{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"press","input":` + args + `}]},{"role":"user","content":` + jsonStr(prose) + `}]}`},
		{OpenAIChat, `{"messages":[{"role":"system","content":"x"},{"role":"assistant","tool_calls":[{"id":"t1","type":"function","function":{"name":"press","arguments":` + jsonStr(args) + `}}]},{"role":"user","content":` + jsonStr(prose) + `}]}`},
		{OpenAIResponses, `{"instructions":"x","input":[{"type":"function_call","call_id":"t1","name":"press","arguments":` + jsonStr(args) + `},{"role":"user","content":` + jsonStr(prose) + `}]}`},
	} {
		t.Run(tc.d.Name, func(t *testing.T) {
			out, v := redactWith(t, tc.d, tc.body)
			if !strings.Contains(out, jsonStr(prose)) {
				t.Errorf("prose was redacted: %s", out)
			}
			for _, secret := range []string{"zebra8841", "walrus7720"} {
				if strings.Contains(out, secret) {
					t.Errorf("upstream would receive %q: %s", secret, out)
				}
			}
			if v.Len() != 2 {
				t.Errorf("vault has %d values, want 2: %s", v.Len(), out)
			}
			back, err := RestoreResponse(tc.d, []byte(out), v)
			if err != nil || !jsonEqual(stripNote(string(back)), tc.body) {
				t.Fatalf("round trip changed arguments: %s, %v", back, err)
			}
		})
	}
}

func TestRedactRequestComputerScreenshotUntouched(t *testing.T) {
	shot := `{"type":"computer_screenshot","image_url":` + jsonStr(pngDataURL) + `}`
	body := `{"instructions":"x","input":[{"type":"computer_call_output","call_id":"c1","output":` + shot + `}]}`
	out, _ := redactWith(t, OpenAIResponses, body)
	if !strings.Contains(out, jsonStr(pngDataURL)) {
		t.Errorf("screenshot changed: %s", out)
	}
}
