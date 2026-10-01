package payload

import (
	"strings"
	"testing"

	"nospyai/internal/redact"
)

// A postal address inside a JSON string of an Anthropic request is redacted (one span across the
// "\n" escape) and restored in the response.
func TestRedactRequestAddress(t *testing.T) {
	req := `{"model":"claude-opus-5-5","max_tokens":64,"messages":[{"role":"user","content":"Ship to Acme\n1600 Pennsylvania Ave NW\nWashington, DC 20500 today"}]}`
	v := redact.NewVault()
	r := redact.NewRedactor(testDet, v)
	out, counts, err := RedactRequest(Anthropic, []byte(req), r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "Pennsylvania") || strings.Contains(s, "20500") {
		t.Errorf("leaked address: %s", s)
	}
	if !strings.Contains(s, `Ship to Acme\n[REDACTED_ADDRESS_1] today`) || counts[redact.KindAddress] != 1 {
		t.Errorf("counts = %v, body = %s", counts, s)
	}
	if got := v.RestoreJSONString("[REDACTED_ADDRESS_1]"); got != `1600 Pennsylvania Ave NW\nWashington, DC 20500` {
		t.Errorf("restore = %q", got)
	}
}
