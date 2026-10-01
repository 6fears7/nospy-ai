// Package payload applies redaction and restoration to LLM API JSON bodies and SSE streams.
package payload

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"nospyai/internal/redact"
)

// Dialect describes which parts of an API's JSON are structural (left alone) and which are
// user data (rewritten). Anything not named here is rewritten, so new fields fail closed.
type Dialect struct {
	Name        string
	SkipKeys    map[string]bool // structural keys whose values are never touched
	SkipTypes   map[string]bool // objects whose "type" is one of these pass through whole
	SkipPaths   [][]string      // paths from the root; "*" matches any array index
	OpaqueKeys  map[string]bool // subtrees of pure user data: SkipKeys/SkipTypes don't apply inside
	JSONStrKeys map[string]bool // string values that hold encoded JSON (OpenAI "arguments")
	// KeyOrder lists keys visited first, in this order, at every object; the rest follow
	// sorted. It follows the API's cache-prefix order so placeholder numbering (first
	// appearance) is stable when new messages are appended.
	KeyOrder []string
	// DropKeys are top-level request keys deleted before the walk: they carry client identity
	// (Anthropic "metadata.user_id", OpenAI "user", "safety_identifier") and no API needs them.
	DropKeys []string
	// ChainKey names a top-level request key that refers to server-side history (Responses
	// "previous_response_id"). The proxy continues the referenced request's vault for it.
	ChainKey string
	sse      sseHandler // streaming-event rewriting for this API
	// addNote merges PlaceholderNote into the redacted top-level request object's system prompt.
	addNote func(top map[string]any)
}

func set(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

// Anthropic is the Messages API (/v1/messages, /v1/messages/count_tokens).
var Anthropic = Dialect{
	Name: "anthropic-messages",
	SkipKeys: set("model", "type", "role", "id", "tool_use_id", "name", "media_type",
		"stop_reason", "stop_sequence", "cache_control", "signature"),
	SkipTypes:  set("thinking", "redacted_thinking", "base64"),
	SkipPaths:  [][]string{{"tools", "*", "input_schema"}},
	OpaqueKeys: set("input"),
	DropKeys:   []string{"metadata"},
	KeyOrder:   []string{"tools", "system", "messages"},
	sse:        anthropicSSE,
	addNote:    anthropicNote,
}

type walker struct {
	d    Dialect
	str  func(s string) string // visits one string leaf and returns its replacement
	scan bool                  // pass 1: str only looks, the tree comes out unchanged
	// jsonStr, when set, handles a JSONStrKeys value as one string (response restoring, where
	// placeholders are replaced in the raw text). Otherwise redactJSONStr decodes it.
	jsonStr func(s string) string
	field   func(key, value string) string // request-only secret-key context inside user data
}

// redactJSONStr handles a JSONStrKeys value: the encoded JSON is decoded and walked as user data.
func (w *walker) redactJSONStr(s string) string {
	inner, err := decode([]byte(s))
	if err != nil {
		return w.str(s) // model emitted invalid JSON: redact as plain text
	}
	walked := w.walk(inner, nil, true) // tool arguments: all user data
	if w.scan {
		return s
	}
	out, err := encode(walked)
	if err != nil {
		return w.str(s)
	}
	return string(out)
}

func (w *walker) walk(v any, path []string, opaque bool) any {
	switch t := v.(type) {
	case map[string]any:
		if !opaque {
			if typ, ok := t["type"].(string); ok && w.d.SkipTypes[typ] {
				return t
			}
		}
		for _, k := range w.orderedKeys(t) {
			child := t[k]
			if !opaque && w.d.SkipKeys[k] {
				continue
			}
			p := append(path, k)
			if !opaque && w.skipPath(p) {
				continue
			}
			if s, ok := child.(string); ok {
				// Image URLs can carry binary data. Text and tool arguments
				// beginning with "data:" are still user data and must be scanned.
				if !opaque && k == "url" && len(path) > 0 && strings.HasPrefix(s, "data:") {
					parent := path[len(path)-1]
					if parent == "image_url" || parent == "source" && t["type"] == "url" {
						continue
					}
				}
			}
			if s, ok := child.(string); ok && w.d.JSONStrKeys[k] {
				if w.jsonStr != nil {
					t[k] = w.jsonStr(s)
				} else {
					t[k] = w.redactJSONStr(s)
				}
				continue
			}
			// A number or bool under a secret key is left alone: registering it would redact every standalone copy (years, ports).
			if s, ok := child.(string); ok && opaque && w.field != nil {
				t[k] = w.field(k, s)
				continue
			}
			t[k] = w.walk(child, p, opaque || w.d.OpaqueKeys[k])
		}
		return t
	case []any:
		p := append(path, "*")
		for i, child := range t {
			t[i] = w.walk(child, p, opaque)
		}
		return t
	case string:
		return w.str(t)
	default:
		return v
	}
}

// orderedKeys returns m's keys: Dialect.KeyOrder first, then the rest sorted. Go map
// iteration is random, and placeholder numbers depend on visiting order.
func (w *walker) orderedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for _, k := range w.d.KeyOrder {
		if _, ok := m[k]; ok {
			keys = append(keys, k)
		}
	}
	rest := make([]string, 0, len(m))
	for k := range m {
		if !slices.Contains(w.d.KeyOrder, k) {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	return append(keys, rest...)
}

func (w *walker) skipPath(p []string) bool {
	for _, sp := range w.d.SkipPaths {
		if len(sp) != len(p) {
			continue
		}
		match := true
		for i := range sp {
			if sp[i] != p[i] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func decode(body []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func encode(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// RedactRequest redacts every user-data string in a request body. Any error means the body
// must not be forwarded.
func RedactRequest(d Dialect, body []byte, r *redact.Redactor) ([]byte, map[string]int, error) {
	v, err := decode(body)
	if err != nil {
		return nil, nil, err
	}
	if m, ok := v.(map[string]any); ok {
		for _, k := range d.DropKeys {
			delete(m, k)
		}
	}
	// Pass 1 registers every match in visiting order, so placeholder numbers follow first
	// appearance and don't depend on the second pass. Pass 2 rewrites, and also catches the
	// values pass 1 found wherever else they sit without their context.
	scan := &walker{d: d, scan: true, str: func(s string) string { r.Scan(s); return s },
		field: func(key, s string) string { r.ScanField(key, s); return s }}
	scan.walk(v, nil, false)
	counts := map[string]int{}
	count := func(out string, c map[string]int) string {
		for k, n := range c {
			counts[k] += n
		}
		return out
	}
	w := &walker{d: d, str: func(s string) string { return count(r.Rewrite(s)) },
		field: func(key, s string) string { return count(r.RewriteField(key, s)) }}
	v = w.walk(v, nil, false)
	// The model can see a placeholder when the vault is non-empty: new redactions, or a
	// Responses chain whose earlier input held them.
	if m, ok := v.(map[string]any); ok && d.addNote != nil && r.VaultLen() > 0 {
		d.addNote(m)
	}
	out, err := encode(v)
	if err != nil {
		return nil, nil, err
	}
	return out, counts, nil
}
