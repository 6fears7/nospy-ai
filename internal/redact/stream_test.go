package redact

import (
	"strings"
	"testing"
)

func streamVault() (*Vault, string) {
	v := NewVault()
	a := v.Placeholder(KindEmail, "alice@corp.io")
	b := v.Placeholder(KindPrivateKey, `pa"ss\word`)
	return v, "hi " + a + " and " + b + "! [not a placeholder] [REDACTED_EMAIL_99] ["
}

// feedAll feeds s split at the given cut points and returns the concatenated output.
func feedAll(r *StreamRestorer, s string, cuts []int) string {
	var b strings.Builder
	last := 0
	for _, c := range cuts {
		if c < last || c > len(s) {
			continue
		}
		b.WriteString(r.Feed(s[last:c]))
		last = c
	}
	b.WriteString(r.Feed(s[last:]))
	b.WriteString(r.Flush())
	return b.String()
}

func TestStreamRestorerEverySplit(t *testing.T) {
	v, s := streamVault()
	for _, esc := range []bool{false, true} {
		want := v.Restore(s)
		if esc {
			want = v.RestoreJSONString(s)
		}
		for i := 0; i <= len(s); i++ {
			for j := i; j <= len(s); j++ {
				if got := feedAll(v.NewStreamRestorer(esc), s, []int{i, j}); got != want {
					t.Fatalf("esc=%v split %d,%d: got %q want %q", esc, i, j, got, want)
				}
			}
		}
	}
}

func TestStreamRestorerNoHoldBackWithoutBracket(t *testing.T) {
	v, _ := streamVault()
	r := v.NewStreamRestorer(false)
	if got := r.Feed("plain text, no brackets"); got != "plain text, no brackets" {
		t.Fatalf("got %q", got)
	}
	if got := r.Feed("x [REDACT"); got != "x " {
		t.Fatalf("got %q", got)
	}
	if got := r.Feed("ED_EMAIL_1] y"); got != "[REDACTED_EMAIL_1]"[:0]+"alice@corp.io y" {
		t.Fatalf("got %q", got)
	}
}

func FuzzStreamRestorer(f *testing.F) {
	v, s := streamVault()
	f.Add(s, 3, 17, 40)
	f.Add("[REDACTED_EMAIL_1][REDACTED_EMAIL_1]", 1, 18, 19)
	f.Fuzz(func(t *testing.T, s string, a, b, c int) {
		cuts := []int{abs(a) % (len(s) + 1), abs(b) % (len(s) + 1), abs(c) % (len(s) + 1)}
		if cuts[0] > cuts[1] {
			cuts[0], cuts[1] = cuts[1], cuts[0]
		}
		if cuts[1] > cuts[2] {
			cuts[1], cuts[2] = cuts[2], cuts[1]
		}
		if cuts[0] > cuts[1] {
			cuts[0], cuts[1] = cuts[1], cuts[0]
		}
		if got, want := feedAll(v.NewStreamRestorer(false), s, cuts), v.Restore(s); got != want {
			t.Fatalf("cuts %v: got %q want %q", cuts, got, want)
		}
		if got, want := feedAll(v.NewStreamRestorer(true), s, cuts), v.RestoreJSONString(s); got != want {
			t.Fatalf("json cuts %v: got %q want %q", cuts, got, want)
		}
	})
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
