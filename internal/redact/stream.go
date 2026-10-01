package redact

import "strings"

const (
	placeholderPrefix = "[REDACTED_"
	maxHoldBack       = 64
)

// StreamRestorer restores placeholders in text that arrives in chunks, where a placeholder
// may be split across chunk boundaries. Not safe for concurrent use; use one per stream.
type StreamRestorer struct {
	v          *Vault
	jsonEscape bool
	pending    string
}

// NewStreamRestorer returns a restorer. jsonEscape is for text inside a JSON string literal.
func (v *Vault) NewStreamRestorer(jsonEscape bool) *StreamRestorer {
	return &StreamRestorer{v: v, jsonEscape: jsonEscape}
}

// Feed returns the restored text that is safe to emit now, holding back only a trailing
// fragment that could still turn into a placeholder.
func (s *StreamRestorer) Feed(chunk string) string {
	s.pending += chunk
	cut := len(s.pending)
	if i := strings.LastIndexByte(s.pending, '['); i >= 0 && couldBePlaceholder(s.pending[i:]) {
		cut = i
	}
	out := s.pending[:cut]
	s.pending = s.pending[cut:]
	return s.restore(out)
}

// Flush returns everything still held back, restored.
func (s *StreamRestorer) Flush() string {
	out := s.restore(s.pending)
	s.pending = ""
	return out
}

func (s *StreamRestorer) restore(t string) string {
	if s.jsonEscape {
		return s.v.RestoreJSONString(t)
	}
	return s.v.Restore(t)
}

// couldBePlaceholder reports whether t is an incomplete prefix of a placeholder, i.e. more
// input could still complete it. A complete placeholder returns false.
func couldBePlaceholder(t string) bool {
	if len(t) > maxHoldBack {
		return false
	}
	if len(t) <= len(placeholderPrefix) {
		return placeholderPrefix[:len(t)] == t
	}
	if !strings.HasPrefix(t, placeholderPrefix) {
		return false
	}
	rest := t[len(placeholderPrefix):]
	if rest[0] < 'A' || rest[0] > 'Z' {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false // includes ']': the placeholder is already complete
		}
	}
	return true
}
