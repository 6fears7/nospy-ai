package payload

// PlaceholderNote tells the model what a placeholder is. Without it a model reads REDACTED as
// "this value is unavailable" and refuses to repeat it. It is constant (no counts, kinds or
// values), so it is cache-stable and leaks nothing about what was redacted.
const PlaceholderNote = "Some values in this conversation (in messages, files and tool output) were replaced by the user's privacy proxy with placeholders like [REDACTED_IP_1] (the form is [REDACTED_KIND_n]). " +
	"Each placeholder stands for a real value that the user has and sees. " +
	"The proxy puts the real value back into everything you write, including tool calls. " +
	"Wherever you need the value, use the placeholder exactly as written: quote it, repeat it, or put it in code and commands. " +
	"Don't say the value is missing, don't ask for it and don't guess it. " +
	"The same placeholder always means the same value."

// The note hooks run on the redacted body, so the note itself is never redacted. They merge the
// note into the existing system prompt instead of adding a message (some OpenAI-compatible
// backends reject a second system message), and they append at the end so the cached prefix
// stays intact.

// anthropicNote: "system" is a string, an array of blocks (the new block carries no
// cache_control, so the breakpoint count is unchanged) or absent.
func anthropicNote(top map[string]any) {
	if _, ok := top["messages"]; !ok {
		return
	}
	switch s := top["system"].(type) {
	case nil:
		top["system"] = PlaceholderNote
	case string:
		top["system"] = appendNote(s)
	case []any:
		top["system"] = append(s, textBlock())
	}
}

// openAIChatNote merges into a leading system/developer message, else inserts one. Bodies
// without "messages" (embeddings) are untouched.
func openAIChatNote(top map[string]any) {
	msgs, ok := top["messages"].([]any)
	if !ok {
		return
	}
	if len(msgs) > 0 {
		if first, _ := msgs[0].(map[string]any); first != nil && (first["role"] == "system" || first["role"] == "developer") {
			switch c := first["content"].(type) {
			case string:
				first["content"] = appendNote(c)
				return
			case []any:
				first["content"] = append(c, textBlock())
				return
			}
		}
	}
	top["messages"] = append([]any{map[string]any{"role": "system", "content": PlaceholderNote}}, msgs...)
}

// openAIResponsesNote: "instructions" does not carry over through previous_response_id, so
// every request needs it.
func openAIResponsesNote(top map[string]any) {
	switch s := top["instructions"].(type) {
	case nil:
		top["instructions"] = PlaceholderNote
	case string:
		top["instructions"] = appendNote(s)
	}
}

func appendNote(s string) string {
	if s == "" {
		return PlaceholderNote
	}
	return s + "\n\n" + PlaceholderNote
}

func textBlock() map[string]any {
	return map[string]any{"type": "text", "text": PlaceholderNote}
}
