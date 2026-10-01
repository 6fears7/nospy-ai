package redact

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// All names below are fictional.

func mustTerms(t *testing.T, src string) *Terms {
	t.Helper()
	tm, err := LoadTerms(strings.NewReader(src))
	if err != nil {
		t.Fatalf("LoadTerms: %v", err)
	}
	return tm
}

func termDet(t *testing.T, src string, hosts ...string) *Detector {
	t.Helper()
	return NewDetector(Config{AllowHosts: hosts, Terms: mustTerms(t, src)})
}

func redactWith(d *Detector, s string) string {
	out, _ := NewRedactor(d, NewVault()).Redact(s)
	return out
}

const sampleTerms = `# comments and blank lines are ignored

Project Falcon            # before any section: kind TERM
[CODENAME]
bluebird
Orion Next
[CUSTOMER]
Acme Corp
re:ACME-\d{4,}            # RE2 regex
[ALLOW]
docs.example.com          # never redacted
`

func TestTermsParse(t *testing.T) {
	tm := mustTerms(t, sampleTerms)
	if n, m := tm.Count(); n != 5 || m != 3 {
		t.Errorf("Count = %d terms in %d sections, want 5 in 3", n, m)
	}
	if !tm.allow["docs.example.com"] || len(tm.allow) != 1 {
		t.Errorf("allow = %v", tm.allow)
	}
	d := NewDetector(Config{Terms: tm})
	s := "Project Falcon, bluebird, Acme Corp, ACME-12345"
	want := map[string]string{"Project Falcon": "TERM", "bluebird": "CODENAME", "Acme Corp": "CUSTOMER", "ACME-12345": "CUSTOMER"}
	ms := d.Detect(s)
	if len(ms) != len(want) {
		t.Fatalf("matches = %+v", ms)
	}
	for _, m := range ms {
		txt := s[m.Start:m.End]
		if want[txt] != m.Kind {
			t.Errorf("%q kind = %s, want %s", txt, m.Kind, want[txt])
		}
	}
	rules := map[string]string{}
	for _, m := range ms {
		rules[s[m.Start:m.End]] = m.Rule
	}
	if rules["bluebird"] != "terms" || rules["ACME-12345"] != "terms-re" {
		t.Errorf("rules = %v", rules)
	}
}

func TestTermsEmptyAndNil(t *testing.T) {
	tm := mustTerms(t, "# nothing\n\n")
	if n, m := tm.Count(); n != 0 || m != 0 {
		t.Errorf("Count = %d, %d", n, m)
	}
	if got := redactWith(NewDetector(Config{Terms: tm}), "hello world"); got != "hello world" {
		t.Errorf("got %q", got)
	}
	var nilTerms *Terms
	if n, m := nilTerms.Count(); n != 0 || m != 0 {
		t.Errorf("nil Count = %d, %d", n, m)
	}
}

func TestTermsDedupeAndMergedSections(t *testing.T) {
	tm := mustTerms(t, "[CODENAME]\nbluebird\nBlueBird\nblue   bird\n[OTHER]\nred fox\n[CODENAME]\nred fox\nbluebird\n")
	// bluebird (once; case dupes), "blue bird" (once), "red fox" in OTHER and CODENAME (distinct sections).
	if n, m := tm.Count(); n != 4 || m != 2 {
		t.Errorf("Count = %d in %d, want 4 in 2", n, m)
	}
}

func TestTermsValidationErrors(t *testing.T) {
	src := strings.Join([]string{
		"[lower]",                  // 1 invalid section name
		"ab",                       // 2 too short
		"re:(unclosed-SECRETREGEX", // 3 invalid regex
		"re:a*",                    // 4 matches empty
		"re:",                      // 5 empty regex
		"[ALLOW]",                  // 6
		"re:foo.*",                 // 7 regex in allow
		"[BAD NAME]",               // 8
		"[X]",                      // 9 (fine)
		"good term",                // 10 fine
		"日本",                       // 11 two runes: too short
	}, "\n")
	_, err := LoadTerms(strings.NewReader(src))
	if err == nil {
		t.Fatal("expected errors")
	}
	msg := err.Error()
	for _, want := range []string{
		"terms line 1: invalid section name",
		"terms line 2: term shorter than 3 characters",
		"terms line 3: invalid regex",
		"terms line 4: regex matches the empty string",
		"terms line 5: empty regex",
		"terms line 7: regex not allowed in ALLOW",
		"terms line 8: invalid section name",
		"terms line 11: term shorter than 3 characters",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	for _, leak := range []string{"SECRETREGEX", "unclosed", "foo", "lower", "BAD NAME", "good term"} {
		if strings.Contains(msg, leak) {
			t.Errorf("error echoes file content %q:\n%s", leak, msg)
		}
	}
	if strings.Contains(msg, "line 9") || strings.Contains(msg, "line 10") {
		t.Errorf("valid lines reported:\n%s", msg)
	}
}

func TestTermsReservedAndNames(t *testing.T) {
	// ALLOW is reserved: it's the allowlist, never a kind. Names must match the placeholder regex.
	for _, name := range []string{"A", "CODE_NAME2", "X_1"} {
		if _, err := LoadTerms(strings.NewReader("[" + name + "]\nsomething\n")); err != nil {
			t.Errorf("[%s] rejected: %v", name, err)
		}
	}
	for _, name := range []string{"1A", "_A", "a", "A-B", "", "A B"} {
		if _, err := LoadTerms(strings.NewReader("[" + name + "]\nsomething\n")); err == nil {
			t.Errorf("[%s] accepted", name)
		}
	}
}

func TestTermsLineTooLong(t *testing.T) {
	_, err := LoadTerms(strings.NewReader("ok term\n" + strings.Repeat("x", maxTermsLine+10) + "\n"))
	if err == nil || !strings.Contains(err.Error(), "terms line 2: line too long") {
		t.Errorf("err = %v", err)
	}
}

func TestTermsCommentsAndBOM(t *testing.T) {
	tm := mustTerms(t, "\xef\xbb\xbfC# Team   # trailing\r\n#whole line\r\n\tbluebird\t\r\n")
	d := NewDetector(Config{Terms: tm})
	if got := redactWith(d, "the C# Team and bluebird"); got != "the [REDACTED_TERM_1] and [REDACTED_TERM_2]" {
		t.Errorf("got %q", got)
	}
}

func TestTermsMatching(t *testing.T) {
	d := termDet(t, "[CODENAME]\nFalcon\nOrion\nOrion Next\nC++ Team\n.NET\nPlatform Core\nnaïve\n")
	cases := []struct{ name, in, want string }{
		{"case-insensitive", "a FALCON and falcon", "a [REDACTED_CODENAME_1] and [REDACTED_CODENAME_2]"},
		{"whole word prefix", "Falconry", "Falconry"},
		{"whole word suffix", "Gyrfalcon", "Gyrfalcon"},
		{"underscore is a word char", "my_Falcon Falcon_x", "my_Falcon Falcon_x"},
		{"digit is a word char", "Falcon9 9Falcon", "Falcon9 9Falcon"},
		{"rejected match does not hide later one", "Falconry Falcon", "Falconry [REDACTED_CODENAME_1]"},
		{"rejected suffix then valid", "Gyrfalcon Falcon", "Gyrfalcon [REDACTED_CODENAME_1]"},
		{"punctuation neighbours are fine", "(Falcon), 'falcon'; Falcon.", "([REDACTED_CODENAME_1]), '[REDACTED_CODENAME_2]'; [REDACTED_CODENAME_1]."},
		{"across newline", "Platform\nCore rocks", "[REDACTED_CODENAME_1] rocks"},
		{"many spaces", "Platform \t Core", "[REDACTED_CODENAME_1]"},
		{"punctuation term", "join the C++ Team now", "join the [REDACTED_CODENAME_1] now"},
		{"punctuation edge next to letters", "use a_.NET and y.NETx", "use a_[REDACTED_CODENAME_1] and y.NETx"},
		{"longest first", "Orion Next ships", "[REDACTED_CODENAME_1] ships"},
		{"shorter alternative after rejected longer", "Orion Nextish", "[REDACTED_CODENAME_1] Nextish"},
		{"shorter alternative alone", "Orion flies", "[REDACTED_CODENAME_1] flies"},
		{"unicode letter neighbour", "Éfalcon falconé", "Éfalcon falconé"},
		{"non-ascii term", "a NAÏVE idea", "a [REDACTED_CODENAME_1] idea"},
	}
	for _, c := range cases {
		if got := redactWith(d, c.in); got != c.want {
			t.Errorf("%s: %q -> %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestTermsRegex(t *testing.T) {
	d := termDet(t, "[TICKET]\nre:ACME-\\d{4,}\nre:(?i)proj-[a-z]+\n")
	if got := redactWith(d, "ACME-1234 acme-1234 ACME-12 PROJ-beta"); got != "[REDACTED_TICKET_1] acme-1234 ACME-12 [REDACTED_TICKET_2]" {
		t.Errorf("got %q", got)
	}
}

// Terms rank below every other rule: a term inside a larger match doesn't split it.
func TestTermsPriority(t *testing.T) {
	d := termDet(t, "acme\nexample\n")
	s := "mail alice@acme.com or see acme"
	ms := d.Detect(s)
	if len(ms) != 2 || ms[0].Kind != KindEmail || s[ms[0].Start:ms[0].End] != "alice@acme.com" || ms[1].Kind != KindTerm {
		t.Fatalf("matches = %+v", ms)
	}
	out := redactWith(d, s)
	if out != "mail [REDACTED_EMAIL_1] or see [REDACTED_TERM_1]" || strings.Contains(out, "alice") {
		t.Errorf("out = %q", out)
	}
	// A term in a URL host/path: the DOMAIN rule (higher) owns the host.
	if got := redactWith(d, "https://acme.com/x"); got != "https://[REDACTED_DOMAIN_1]/x" {
		t.Errorf("got %q", got)
	}
	// Where only a term applies (no TLD), it does; a hyphen is a word boundary.
	if got := redactWith(d, "host acme-build01 is acme"); got != "host [REDACTED_TERM_1]-build01 is [REDACTED_TERM_1]" {
		t.Errorf("got %q", got)
	}
}

func TestTermsAllow(t *testing.T) {
	d := termDet(t, "example\n[ALLOW]\nDocs.Example.com\nhunter22\nhelp@example.com\n")
	for in, want := range map[string]string{
		"see https://docs.example.com/guide":     "see https://docs.example.com/guide",
		"see DOCS.EXAMPLE.COM":                   "see DOCS.EXAMPLE.COM",
		"see https://api.docs.example.com/guide": "see https://[REDACTED_DOMAIN_1]/guide",
		"mail help@example.com":                  "mail help@example.com",                      // identifiers can be allowed
		"password: hunter22":                     "password: [REDACTED_PASSWORD_1]",            // secrets never are
		"see docs.example.com and example":       "see docs.example.com and [REDACTED_TERM_1]", // allowed span shields the term inside it
	} {
		if got := redactWith(d, in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// An ALLOW entry the built-in rules see as a secret is a load error; the text is never echoed.
func TestTermsAllowRejectsSecrets(t *testing.T) {
	tok := "gh" + "p_" + strings.Repeat("a1B2", 9)
	for _, entry := range []string{tok, "password=" + "hunter22", "AKIA" + "IOSFODNN7EXAMPLE"} {
		_, err := LoadTerms(strings.NewReader("[ALLOW]\nok.example.com\n" + entry + "\n"))
		if err == nil || !strings.Contains(err.Error(), "terms line 3: ALLOW entry looks like a password") {
			t.Errorf("entry %d: err = %v", len(entry), err)
		} else if strings.Contains(err.Error(), entry) {
			t.Errorf("error echoes the entry")
		}
	}
}

// Upstream hosts and [ALLOW] are merged, and keep exact-host semantics.
func TestAllowMergesWithHosts(t *testing.T) {
	d := termDet(t, "[ALLOW]\ndocs.example.com\n", "api.anthropic.com")
	got := redactWith(d, "https://api.anthropic.com https://docs.example.com https://api.docs.example.com https://other.example.org")
	want := "https://api.anthropic.com https://docs.example.com https://[REDACTED_DOMAIN_1] https://[REDACTED_DOMAIN_2]"
	if got != want {
		t.Errorf("got %q", got)
	}
	// Host-only allowlist, no terms: same semantics as before.
	d = NewDetector(Config{AllowHosts: []string{"docs.example.com"}})
	if got := redactWith(d, "docs.example.com api.docs.example.com"); got != "docs.example.com [REDACTED_DOMAIN_1]" {
		t.Errorf("host allowlist: %q", got)
	}
}

func TestTermsRoundTripAndIdempotent(t *testing.T) {
	d := termDet(t, "[CODENAME]\nProject Falcon\nre:ACME-\\d{4,}\n")
	v := NewVault()
	r := NewRedactor(d, v)
	in := "Project Falcon (ACME-5555) and again project falcon"
	out, counts := r.Redact(in)
	if out != "[REDACTED_CODENAME_1] ([REDACTED_CODENAME_2]) and again [REDACTED_CODENAME_3]" {
		t.Fatalf("out = %q", out)
	}
	if counts["CODENAME"] != 3 {
		t.Errorf("counts = %v", counts)
	}
	// Same vault, redacting the placeholders again changes nothing.
	if again, _ := r.Redact(out); again != out {
		t.Errorf("not idempotent: %q", again)
	}
	// The vault keys exact text, so the lowercase spelling is its own value and restores as typed.
	if got := v.Restore(out); got != in {
		t.Errorf("restored %q", got)
	}
}

// A term that could match inside a placeholder must not corrupt it.
func TestTermsDontTouchPlaceholders(t *testing.T) {
	d := termDet(t, "REDACTED\nEMAIL\nTERM\n")
	s := "[REDACTED_EMAIL_1] and [REDACTED_TERM_7] and REDACTED"
	if got := redactWith(d, s); got != "[REDACTED_EMAIL_1] and [REDACTED_TERM_7] and [REDACTED_TERM_1]" {
		t.Errorf("got %q", got)
	}
}

func TestTermsManyTerms(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&b, "Codename Number%05d\n", i)
		fmt.Fprintf(&b, "zx%05dq\n", i)
	}
	tm := mustTerms(t, b.String())
	if n, _ := tm.Count(); n != 10000 {
		t.Fatalf("Count = %d", n)
	}
	d := NewDetector(Config{Terms: tm})
	start := time.Now()
	got := redactWith(d, "x codename   number04999 y ZX00042Q z Codename Number99999 zx00042qq")
	if got != "x [REDACTED_TERM_1] y [REDACTED_TERM_2] z Codename Number99999 zx00042qq" {
		t.Errorf("got %q", got)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("matching 10000 terms took %v", el)
	}
}

func TestExplainRuleNamesDetect(t *testing.T) {
	d := termDet(t, "bluebird\nre:ACME-\\d+\n")
	ms := d.Detect("bluebird ACME-12")
	if len(ms) != 2 || ms[0].Rule != "terms" || ms[1].Rule != "terms-re" {
		t.Errorf("matches = %+v", ms)
	}
}
