package redact

import (
	"strings"
	"testing"
)

var testDetector = NewDetector(Config{AllowHosts: []string{"api.anthropic.com"}})

// fakeBody returns n token-safe characters. Prefixes are concatenated in the cases below so
// secret scanners don't flag this file.
func fakeBody(n int) string {
	return strings.Repeat("Q7mZ2kLp9XvR4tWc8NbY3hJd6FgS1aUe", 4)[:n]
}

func hasMatch(ms []Match, s, kind, text string) bool {
	for _, m := range ms {
		if m.Kind == kind && s[m.Start:m.End] == text {
			return true
		}
	}
	return false
}

func TestDetectPositive(t *testing.T) {
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA\n-----END OPENSSH PRIVATE KEY-----"
	cases := []struct{ name, in, kind, want string }{
		{"anthropic key", "k=" + "sk-" + "ant-api03-" + fakeBody(30), KindToken, "sk-" + "ant-api03-" + fakeBody(30)},
		{"openai key", "use " + "sk-" + "proj-" + fakeBody(30), KindToken, "sk-" + "proj-" + fakeBody(30)},
		{"github token", "gh" + "p_" + fakeBody(36), KindToken, "gh" + "p_" + fakeBody(36)},
		{"github pat", "github" + "_pat_" + fakeBody(30), KindToken, "github" + "_pat_" + fakeBody(30)},
		{"aws key", "id AKIA" + "IOSFODNN7EXAMPLE end", KindToken, "AKIA" + "IOSFODNN7EXAMPLE"},
		{"slack", "xox" + "b-1234567890-FAKE", KindToken, "xox" + "b-1234567890-FAKE"},
		{"google", "AI" + "za" + fakeBody(35), KindToken, "AI" + "za" + fakeBody(35)},
		{"stripe", "sk_" + "live_" + fakeBody(24), KindToken, "sk_" + "live_" + fakeBody(24)},
		{"nospy proxy token", "tok " + "nspy" + "_" + fakeBody(43), KindToken, "nspy" + "_" + fakeBody(43)},
		{"jwt", "t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl", KindToken, "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJl"},
		{"bearer", "Authorization: Bearer abcdefghijklmnop1234", KindToken, "abcdefghijklmnop1234"},
		{"pem", "key:\n" + pem + "\n", KindPrivateKey, pem},
		{"password kv", "login password=hunter22", KindPassword, "hunter22"},
		{"dotenv at line start", "password=hunter22", KindSecret, "hunter22"},
		{"api_key json", `{"api_key": "abc123xyz"}`, KindPassword, "abc123xyz"},
		{"url password", "postgres://u:p4ss@db.internal.example.com/x", KindPassword, "p4ss"},
		{"url host", "postgres://u:p4ss@db.internal.example.com/x", KindDomain, "db.internal.example.com"},
		{"email", "mail alice@corp.io now", KindEmail, "alice@corp.io"},
		{"ipv4", "ssh 10.0.0.12", KindIPv4, "10.0.0.12"},
		{"ipv6", "ping 2001:db8::1", KindIPv6, "2001:db8::1"},
		{"ipv6 mapped", "from ::ffff:10.0.0.1 ok", KindIPv6, "::ffff:10.0.0.1"},
		{"domain", "call api.stripe.com today", KindDomain, "api.stripe.com"},
		{"ambiguous tld in url", "see https://foo.md/x", KindDomain, "foo.md"},
		{"internal host", "connect to db.internal", KindDomain, "db.internal"},
		{"high entropy", "x Zx9Qm2Lp7Vt4Rb8Nk3Hs6Jd1Wf5Gc0Ya y", KindToken, "Zx9Qm2Lp7Vt4Rb8Nk3Hs6Jd1Wf5Gc0Ya"},
		{"aws secret with slashes", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", KindToken, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := testDetector.Detect(c.in)
			if !hasMatch(ms, c.in, c.kind, c.want) {
				t.Errorf("want %s %q in %q, got %s", c.kind, c.want, c.in, describe(c.in, ms))
			}
		})
	}
}

func TestDetectNegative(t *testing.T) {
	cases := []string{
		"see README.md", "run build.sh", "python main.py", "print(user.name)", "app.run()",
		"os.Stdout", "std::vector<int>", "a :: b", "::", "Foo.pm", "config.fish", "key.pub",
		"~/.ssh/id_rsa.pub", `errors.New("x")`, "var m sync.Map", "e.g. this", "version 1.2.3",
		"commit da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"id 123e4567-e89b-12d3-a456-426614174000",
		"listen 127.0.0.1", "bind 0.0.0.0", "localhost:8080", "https://api.anthropic.com/v1/messages",
		"/opt/personal/nospyAI/internal/redact", // a home path is USER now (home_test.go)
		"TestStructuredSecretDocumentsKubeconfig2Fixture", "HandleIncomingWebhookRequestV2ForGitHubApps",
		"at 12:34:56", "mac aa:bb:cc:dd:ee:ff", "i32::MAX", "the password: is",
		`token := os.Getenv("X")`, "MONKEY=banana", "[REDACTED_EMAIL_1] and [REDACTED_PRIVATE_KEY_2]",
	}
	for _, in := range cases {
		if ms := testDetector.Detect(in); len(ms) > 0 {
			t.Errorf("%q: want no matches, got %s", in, describe(in, ms))
		}
	}
}

// The keyword rule also matches after an underscore, so UPPER_SNAKE names are caught.
func TestKeywordAfterUnderscore(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"DB_PASSWORD=hunter2hunter2", "hunter2hunter2"},
		{"echo hi && export GH_TOKEN=abcd1234 && run", "abcd1234"},
		{"FOO=1 DB_PASSWORD=hunter2hunter2 ./run", "hunter2hunter2"},
		{".env:3:DB_PASSWORD=x1y2z3w4", "x1y2z3w4"},
		{`cfg MY_API_KEY: "abcd1234"`, "abcd1234"},
		{"DB_PASSWORD=$ecret123", "$ecret123"},  // a value that starts with $
		{"login password=$hunter2", "$hunter2"}, // lowercase after $ is not a variable reference
	} {
		ms := testDetector.Detect(c.in)
		at := strings.Index(c.in, c.want)
		if !covered(ms, at, at+len(c.want)) {
			t.Errorf("%q: %q not redacted, got %s", c.in, c.want, describe(c.in, ms))
		}
	}
	for _, in := range []string{
		"password_hash=abcd1234", "tokenizer=abcd1234", "x OLD_PASSWORD=${DB_PASSWORD}", "x AUTH_TOKEN=$TOKEN",
	} {
		if ms := testDetector.Detect(in); len(ms) > 0 {
			t.Errorf("%q: want no matches, got %s", in, describe(in, ms))
		}
	}
}

func TestResolvePrefersPriorityThenLength(t *testing.T) {
	in := "login password=alice@corp.io"
	ms := testDetector.Detect(in)
	if len(ms) != 1 || ms[0].Kind != KindPassword || in[ms[0].Start:ms[0].End] != "alice@corp.io" {
		t.Fatalf("got %s", describe(in, ms))
	}
}

func describe(s string, ms []Match) string {
	var b strings.Builder
	for _, m := range ms {
		b.WriteString(m.Kind + "/" + m.Rule + "(" + s[m.Start:m.End] + ") ")
	}
	if b.Len() == 0 {
		return "none"
	}
	return b.String()
}

// Every match names the rule that found it (scan --explain prints it).
func TestDetectSetsRule(t *testing.T) {
	cases := []struct{ in, rule string }{
		{"mail alice@corp.io now", "email"},
		{"gh" + "p_" + fakeBody(36), "known-token/github"},
		{"use " + "nspy" + "_" + fakeBody(43), "known-token/nspy"},
		{"login password=hunter22", "keyword"},
		{"password=hunter22", "dotenv"},
		{"ssh 10.0.0.12", "ipv4"},
		{"call api.stripe.com today", "domain"},
		{"t=" + fakeBody(40), "entropy"},
	}
	for _, c := range cases {
		ms := testDetector.Detect(c.in)
		if len(ms) == 0 {
			t.Errorf("%q: no match", c.in)
			continue
		}
		for _, m := range ms {
			if m.Rule == "" {
				t.Errorf("%q: match %s has no rule", c.in, describe(c.in, []Match{m}))
			}
		}
		if ms[0].Rule != c.rule {
			t.Errorf("%q: rule = %q, want %q", c.in, ms[0].Rule, c.rule)
		}
	}
}
