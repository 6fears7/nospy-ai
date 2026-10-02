package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dotenvSample = `# app settings
PORT=8080
MONKEY=banana
AUTHOR=me
DB_PASSWORD=hunter2
API_KEY="abc123xyz"
`

func TestScanRedacts(t *testing.T) {
	code, out, errb := runCLI(t, "ssh root@10.0.0.5 and alice@corp.io\n", "scan")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	if strings.Contains(out, "10.0.0.5") || strings.Contains(out, "alice@corp.io") {
		t.Errorf("stdout leaks values: %q", out)
	}
	if !strings.Contains(out, "[REDACTED_IPV4_1]") || !strings.Contains(out, "[REDACTED_EMAIL_1]") {
		t.Errorf("stdout lacks placeholders: %q", out)
	}
	// stderr carries counts per kind only.
	if !strings.Contains(errb, "EMAIL=1") || !strings.Contains(errb, "IPV4=1") || strings.Contains(errb, "10.0.0.5") {
		t.Errorf("stderr = %q", errb)
	}
}

func TestScanNothing(t *testing.T) {
	code, out, errb := runCLI(t, "hello world\n", "scan")
	if code != 0 || out != "hello world\n" || !strings.Contains(errb, "nothing redacted") {
		t.Errorf("code=%d out=%q err=%q", code, out, errb)
	}
	// No --terms: the hint says only built-in rules ran. With --terms it does not.
	if !strings.Contains(errb, "(built-in rules only; no --terms file)") {
		t.Errorf("no hint: %q", errb)
	}
	p := writeTerms(t, testTermsFile)
	_, _, errb = runCLI(t, "hello world\n", "scan", "--terms", p)
	if !strings.Contains(errb, "nothing redacted") || strings.Contains(errb, "built-in") {
		t.Errorf("hint with --terms: %q", errb)
	}
}

// failReader fails the test if it is read.
type failReader struct{ t *testing.T }

func (r failReader) Read([]byte) (int, error) {
	r.t.Helper()
	r.t.Error("stdin was read")
	return 0, errors.New("read")
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func runScanArgs(t *testing.T, stdin io.Reader, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"scan"}, args...), noEnv, stdin, &out, &errb)
	return code, out.String(), errb.String()
}

func TestScanFileArg(t *testing.T) {
	p := writeFile(t, "a.md", "mail alice@corp.io\n")
	code, out, errb := runScanArgs(t, failReader{t}, p)
	if code != 0 || out != "mail [REDACTED_EMAIL_1]\n" || !strings.Contains(errb, "EMAIL=1") {
		t.Errorf("code=%d out=%q err=%q", code, out, errb)
	}
}

func TestScanTwoFilesShareVault(t *testing.T) {
	a := writeFile(t, "a.md", "alice@corp.io and bob@corp.io\n")
	b := writeFile(t, "b.md", "again bob@corp.io\n")
	code, out, errb := runScanArgs(t, failReader{t}, a, b)
	want := "[REDACTED_EMAIL_1] and [REDACTED_EMAIL_2]\nagain [REDACTED_EMAIL_2]\n"
	if code != 0 || out != want {
		t.Errorf("code=%d out=%q, want %q", code, out, want)
	}
	if !strings.Contains(errb, "EMAIL=3") {
		t.Errorf("counts not summed: %q", errb)
	}
}

func TestScanDashIsStdin(t *testing.T) {
	a := writeFile(t, "a.md", "alice@corp.io\n")
	b := writeFile(t, "b.md", "10.0.0.5\n")
	code, out, _ := runScanArgs(t, strings.NewReader("alice@corp.io\n"), a, "-", b)
	if code != 0 || out != "[REDACTED_EMAIL_1]\n[REDACTED_EMAIL_1]\n[REDACTED_IPV4_1]\n" {
		t.Errorf("code=%d out=%q", code, out)
	}
	code, out, errb := runScanArgs(t, strings.NewReader("x"), "-", "-")
	if code != exitUsage || out != "" || !strings.Contains(errb, "more than once") {
		t.Errorf("code=%d out=%q err=%q", code, out, errb)
	}
}

func TestScanMissingFile(t *testing.T) {
	a := writeFile(t, "a.md", "alice@corp.io\n")
	missing := filepath.Join(t.TempDir(), "missing.md")
	code, out, errb := runScanArgs(t, failReader{t}, a, missing)
	if code != exitFail || out != "" || !strings.Contains(errb, "nospy: "+missing+": ") {
		t.Errorf("code=%d out=%q err=%q", code, out, errb)
	}
	if strings.Contains(errb, "alice") {
		t.Errorf("stderr leaks content: %q", errb)
	}
}

func TestScanExplainPrefixesNames(t *testing.T) {
	a := writeFile(t, "a.md", "x\nalice@corp.io\n")
	code, out, _ := runScanArgs(t, strings.NewReader("10.0.0.5\n"), "--explain", a, "-")
	want := a + ":2:1  EMAIL  email  \"alice@corp.io\"\n-:1:1  IPV4  ipv4  \"10.0.0.5\"\n"
	if code != 0 || out != want {
		t.Errorf("code=%d out=%q, want %q", code, out, want)
	}
	// One input keeps the unprefixed format.
	_, out, _ = runScanArgs(t, failReader{t}, "--explain", a)
	if out != "2:1  EMAIL  email  \"alice@corp.io\"\n" {
		t.Errorf("single input out = %q", out)
	}
}

func TestScanExplain(t *testing.T) {
	code, out, errb := runCLI(t, dotenvSample, "scan", "--explain")
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	want := []string{
		"5:13  SECRET  dotenv  \"hunter2\"\n",
		"6:10  SECRET  dotenv  \"abc123xyz\"\n",
	}
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("missing line %q in:\n%s", w, out)
		}
	}
	// Keys that merely end in a secret-looking word stay out.
	if strings.Contains(out, "MONKEY") || strings.Contains(out, "banana") || strings.Contains(out, "AUTHOR") {
		t.Errorf("explain lists a non-secret line:\n%s", out)
	}
	// The test's stdout is not a terminal, so the values get a warning.
	if !strings.Contains(errb, "warning") {
		t.Errorf("no warning on stderr: %q", errb)
	}
}

func TestScanExplainColumnsAndRules(t *testing.T) {
	// Multibyte text before the match: columns count runes. Also a multi-line match is quoted.
	in := "héllo\nmail: bob@corp.io\n"
	_, out, _ := runCLI(t, in, "scan", "--explain")
	if out != "2:7  EMAIL  email  \"bob@corp.io\"\n" {
		t.Errorf("out = %q", out)
	}
	pem := "-----BEGIN PRIVATE KEY-----\nFAKE\n-----END PRIVATE KEY-----"
	_, out, _ = runCLI(t, "k\n"+pem+"\n", "scan", "--explain")
	if !strings.HasPrefix(out, "2:1  PRIVATE_KEY  private-key  \"-----BEGIN PRIVATE KEY-----\\nFAKE") {
		t.Errorf("out = %q", out)
	}
}

func writeTerms(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "terms.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const testTermsFile = "Project Falcon\n[CUSTOMER]\nre:ACME-\\d{4,}\n[ALLOW]\ndocs.example.com\n"

func TestScanTerms(t *testing.T) {
	p := writeTerms(t, testTermsFile)
	in := "Project Falcon for ACME-12345, see docs.example.com and api.docs.example.com\n"
	code, out, errb := runCLI(t, in, "scan", "--terms", p)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	want := "[REDACTED_TERM_1] for [REDACTED_CUSTOMER_1], see docs.example.com and [REDACTED_DOMAIN_1]\n"
	if out != want {
		t.Errorf("out = %q, want %q", out, want)
	}
	if strings.Contains(errb, "Falcon") || strings.Contains(errb, "ACME") {
		t.Errorf("stderr leaks terms: %q", errb)
	}

	code, out, _ = runCLI(t, "Project Falcon / ACME-12345\n", "scan", "--terms", p, "--explain")
	if code != 0 || !strings.Contains(out, "TERM  terms  \"Project Falcon\"") || !strings.Contains(out, "CUSTOMER  terms-re  \"ACME-12345\"") {
		t.Errorf("explain code=%d out=%q", code, out)
	}
}

func TestScanBadTermsFile(t *testing.T) {
	p := writeTerms(t, "[bad]\nab\nre:(SECRETTEXT\nfine term\n")
	code, out, errb := runCLI(t, "hello Falcon\n", "scan", "--terms", p)
	if code != exitUsage || out != "" {
		t.Fatalf("code=%d out=%q", code, out)
	}
	for _, want := range []string{"terms line 1: invalid section name", "terms line 2: term shorter than 3 characters", "terms line 3: invalid regex"} {
		if !strings.Contains(errb, want) {
			t.Errorf("stderr lacks %q: %q", want, errb)
		}
	}
	if strings.Contains(errb, "SECRETTEXT") || strings.Contains(errb, "fine term") {
		t.Errorf("stderr echoes file content: %q", errb)
	}
	if code, _, _ := runCLI(t, "", "scan", "--terms", filepath.Join(t.TempDir(), "missing")); code != exitUsage {
		t.Errorf("missing file code = %d", code)
	}
}
