package redact

import (
	"strings"
	"testing"
)

func TestRemembers(t *testing.T) {
	terms, err := LoadTerms(strings.NewReader("Orion\n[PROJECT]\nNimbus\n"))
	if err != nil {
		t.Fatal(err)
	}
	d := NewDetector(Config{Terms: terms})
	for kind, want := range map[string]bool{
		KindPassword: true, KindSecret: true, KindToken: true, KindPrivateKey: true,
		KindUser: true, KindAddress: true, KindTerm: true, "PROJECT": true,
		KindEmail: false, KindIPv4: false, KindIPv6: false, KindDomain: false, "OTHER": false,
	} {
		if got := d.Remembers(kind); got != want {
			t.Errorf("Remembers(%s) = %v, want %v", kind, got, want)
		}
	}
	if NewDetector(Config{}).Remembers(KindTerm) {
		t.Error("TERM remembered without a terms file")
	}
}

func scanRewrite(r *Redactor, s string) (string, map[string]int) {
	r.Scan(s)
	return r.Rewrite(s)
}

// A value the vault holds is replaced wherever it appears, with its own placeholder, and the
// per-kind count includes those hits. Boundaries follow whole-word matching.
func TestRewriteVaultLiterals(t *testing.T) {
	v := NewVault()
	v.Placeholder(KindSecret, "hunter2hunter2")
	v.Placeholder(KindUser, "admin")
	v.Placeholder(KindUser, "bob")
	v.Placeholder(KindPassword, "pw.")
	r := NewRedactor(NewDetector(Config{}), v)
	out, counts := scanRewrite(r, "is hunter2hunter2, administrator admin bob pw. hunter2hunter2x")
	want := "is [REDACTED_SECRET_1], administrator [REDACTED_USER_1] bob pw. hunter2hunter2x"
	if out != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}
	if counts[KindSecret] != 1 || counts[KindUser] != 1 || len(counts) != 2 {
		t.Errorf("counts = %v", counts)
	}
}

// A rule's wider span wins over a literal, a longer value over a shorter one inside it, and a
// placeholder is never cut into.
func TestRewriteLiteralOverlaps(t *testing.T) {
	v := NewVault()
	v.Placeholder(KindSecret, "mail")
	v.Placeholder(KindSecret, "alice@corp.io")
	v.Placeholder(KindSecret, "SECRET")
	v.Placeholder(KindUser, "corp.io")
	r := NewRedactor(NewDetector(Config{}), v)
	out, _ := scanRewrite(r, "to alice@corp.io via mail [REDACTED_SECRET_9] corp.io")
	if want := "to [REDACTED_SECRET_2] via [REDACTED_SECRET_1] [REDACTED_SECRET_9] [REDACTED_USER_1]"; out != want {
		t.Errorf("got  %s\nwant %s", out, want)
	}
}

func TestRewriteWholeSecretOverlaps(t *testing.T) {
	for _, tc := range []struct {
		name, value, text, want string
	}{
		{"domain inside secret", "foo.example.com/swordfish", "use foo.example.com/swordfish", "use [REDACTED_SECRET_1]"},
		{"multiple identifiers inside secret", "alice@corp.io/10.20.30.40", "use alice@corp.io/10.20.30.40", "use [REDACTED_SECRET_1]"},
		{"wider email", "mail", "mail@corp.io", "[REDACTED_EMAIL_1]"},
		{"protected placeholder", "[REDACTED_SECRET_9]/suffix", "[REDACTED_SECRET_9]/suffix", "[REDACTED_SECRET_9]/suffix"},
	} {
		for _, remembered := range []bool{false, true} {
			t.Run(tc.name+map[bool]string{false: "/vault", true: "/remembered"}[remembered], func(t *testing.T) {
				v := NewVault()
				r := NewRedactor(NewDetector(Config{}), v)
				if remembered {
					r.WithKnown(NewKnownSet([]Known{{KindSecret, tc.value}}))
				} else {
					v.Placeholder(KindSecret, tc.value)
				}
				out, _ := scanRewrite(r, tc.text)
				if out != tc.want {
					t.Fatalf("got %q, want %q", out, tc.want)
				}
				if back := v.Restore(out); back != tc.text {
					t.Errorf("restore = %q, want %q", back, tc.text)
				}
			})
		}
	}
}

func TestKnownFoundOnlyRememberedKinds(t *testing.T) {
	r := NewRedactor(NewDetector(Config{}), NewVault())
	scanRewrite(r, "mail a@corp.io on 10.1.2.3 password=hunter2hunter2 at build.corp.io")
	got := r.Found()
	if len(got) != 1 || got[0] != (Known{KindPassword, "hunter2hunter2"}) {
		t.Errorf("Found = %v", got)
	}
}

// The automaton agrees with a plain strings.Index search, including values that share
// prefixes and suffixes (the fail links).
func TestLiteralsMatchPlainSearch(t *testing.T) {
	ks := []Known{{KindSecret, "abcd"}, {KindSecret, "bcde"}, {KindSecret, "abcde"}, {KindSecret, "cdef!"},
		{KindSecret, "ab-ab-ab"}, {KindSecret, "b-ab"}, {KindSecret, "ab"}, {KindSecret, "héllo wörld"}}
	text := "abcde abcdef cdef! xabcd.bcde ab-ab-ab-ab héllo wörld; abcdabcde"
	got := map[[2]int]bool{}
	newLiterals(ks).find(text, func(start, end int, kind string, prio int, rule string) { got[[2]int{start, end}] = true })
	want := map[[2]int]bool{}
	for _, k := range ks {
		if len(k.Value) < minLiteralLen {
			continue
		}
		for pos := 0; ; {
			i := strings.Index(text[pos:], k.Value)
			if i < 0 {
				break
			}
			start := pos + i
			if wholeWord(text, start, start+len(k.Value)) {
				want[[2]int{start, start + len(k.Value)}] = true
			}
			pos = start + 1
		}
	}
	if len(want) == 0 || len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k := range want {
		if !got[k] {
			t.Errorf("missing %v (%q)", k, text[k[0]:k[1]])
		}
	}
}

func BenchmarkRewriteVaultLiterals(b *testing.B) {
	v := NewVault()
	for i := 0; i < 200; i++ {
		v.Placeholder(KindSecret, "secretvalue"+strings.Repeat("x", i%7)+string(rune('a'+i%26))+string(rune('a'+i/26)))
	}
	chunk := "The quick brown fox jumps over the lazy dog while reading config files and logs. "
	body := strings.Repeat(chunk, (1<<20)/len(chunk))
	r := NewRedactor(NewDetector(Config{}), v)
	r.Scan(body)
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r.Rewrite(body)
	}
}

// The extra cost of pass 2 alone: literal search over rule results Scan already cached.
func BenchmarkLiteralSearchOnly(b *testing.B) {
	var ks []Known
	for i := 0; i < 200; i++ {
		ks = append(ks, Known{KindSecret, "secretvalue" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + string(rune('a'+i/26))})
	}
	lits := newLiterals(ks)
	chunk := "The quick brown fox jumps over the lazy dog while reading config files and logs. "
	body := strings.Repeat(chunk, (1<<20)/len(chunk))
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lits.find(body, func(int, int, string, int, string) {})
	}
}
