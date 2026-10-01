package redact

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// corpus is every positive input from the detector tests plus every structured fixture.
func corpus(t *testing.T) []string {
	t.Helper()
	out := []string{
		"login password=hunter22", `{"api_key": "abc123xyz"}`, "postgres://u:p4ss@db.internal.example.com/x",
		"mail alice@corp.io now", "ssh 10.0.0.12", "ping 2001:db8::1", "call api.stripe.com today",
		"x Zx9Qm2Lp7Vt4Rb8Nk3Hs6Jd1Wf5Gc0Ya y", "Authorization: Bearer abcdefghijklmnop1234",
		"-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE\n-----END OPENSSH PRIVATE KEY-----",
	}
	files, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join("testdata", f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}

func TestRedactRoundTrip(t *testing.T) {
	v := NewVault()
	r := NewRedactor(testDetector, v)
	for _, s := range corpus(t) {
		red, counts := r.Redact(s)
		if red == s || len(counts) == 0 {
			t.Errorf("nothing redacted in %.40q", s)
		}
		if got := v.Restore(red); got != s {
			t.Errorf("round trip mismatch:\nwant %q\ngot  %q", s, got)
		}
	}
}

func TestPlaceholdersDeterministic(t *testing.T) {
	v := NewVault()
	r := NewRedactor(testDetector, v)
	a, _ := r.Redact("mail alice@corp.io and bob@corp.io")
	b, _ := r.Redact("again alice@corp.io")
	if a != "mail [REDACTED_EMAIL_1] and [REDACTED_EMAIL_2]" || b != "again [REDACTED_EMAIL_1]" {
		t.Fatalf("got %q / %q", a, b)
	}
}

func TestVaultLen(t *testing.T) {
	v := NewVault()
	if v.Len() != 0 {
		t.Fatalf("new vault Len = %d", v.Len())
	}
	v.Placeholder(KindEmail, "a@corp.io")
	v.Placeholder(KindEmail, "a@corp.io")
	v.Placeholder(KindIPv4, "10.0.0.1")
	if v.Len() != 2 || v.Clone().Len() != 2 {
		t.Errorf("Len = %d, clone %d, want 2", v.Len(), v.Clone().Len())
	}
	if NewRedactor(NewDetector(Config{}), v).VaultLen() != 2 {
		t.Error("Redactor.VaultLen disagrees with the vault")
	}
}

func TestRestoreIgnoresUnknown(t *testing.T) {
	v := NewVault()
	v.Placeholder(KindEmail, "alice@corp.io")
	in := "[REDACTED_EMAIL_1] [REDACTED_EMAIL_99] [REDACTED_PRIVATE_KEY_1]"
	if got := v.Restore(in); got != "alice@corp.io [REDACTED_EMAIL_99] [REDACTED_PRIVATE_KEY_1]" {
		t.Fatalf("got %q", got)
	}
}

func TestRestoreJSONString(t *testing.T) {
	v := NewVault()
	ph := v.Placeholder(KindPassword, `pa"ss\w<rd>`)
	frag := `{"cmd":"login ` + ph + `"}`
	var got map[string]string
	if err := json.Unmarshal([]byte(v.RestoreJSONString(frag)), &got); err != nil {
		t.Fatal(err)
	}
	if got["cmd"] != `login pa"ss\w<rd>` {
		t.Fatalf("got %q", got["cmd"])
	}
}

func TestRedactConcurrent(t *testing.T) {
	v := NewVault()
	r := NewRedactor(testDetector, v)
	var wg sync.WaitGroup
	results := make([]string, 50)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = r.Redact("a@corp.io b@corp.io c@corp.io 10.0.0.1 10.0.0.2")
		}(i)
	}
	wg.Wait()
	for _, got := range results {
		if got != results[0] || strings.Contains(got, "corp.io") {
			t.Fatalf("inconsistent or leaked: %q vs %q", got, results[0])
		}
	}
}
