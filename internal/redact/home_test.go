package redact

import (
	"strings"
	"testing"
)

func TestHomePathRedactsOnlyName(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"macos", "cwd /Users/alice/src/app", "cwd /Users/[REDACTED_USER_1]/src/app"},
		{"linux", "cd /home/alice && ls", "cd /home/[REDACTED_USER_1] && ls"},
		{"name at end", "/home/alice", "/home/[REDACTED_USER_1]"},
		{"windows", `open C:\Users\alice\Documents`, `open C:\Users\[REDACTED_USER_1]\Documents`},
		{"windows slash", "C:/Users/alice/x", "C:/Users/[REDACTED_USER_1]/x"},
		{"windows lowercase", `c:\users\alice\x`, `c:\users\[REDACTED_USER_1]\x`},
		{"json escaped", `C:\\Users\\alice\\x`, `C:\\Users\\[REDACTED_USER_1]\\x`},
		{"wsl", "/mnt/c/Users/alice/x", "/mnt/c/Users/[REDACTED_USER_1]/x"},
		{"file url", "file:///Users/alice/x", "file:///Users/[REDACTED_USER_1]/x"},
		{"quoted", `"/home/alice"`, `"/home/[REDACTED_USER_1]"`},
		{"dotted name", "/home/first.last/x", "/home/[REDACTED_USER_1]/x"},
		{"sentence period", "it is in /Users/alice.", "it is in /Users/[REDACTED_USER_1]."},
		{"same name twice", "/Users/alice /home/alice", "/Users/[REDACTED_USER_1] /home/[REDACTED_USER_1]"},
		{"two names", "/Users/alice /Users/bob", "/Users/[REDACTED_USER_1] /Users/[REDACTED_USER_2]"},
		{"windows space", `C:\Users\John Smith\Documents`, `C:\Users\[REDACTED_USER_1]\Documents`},
		{"windows space slash", "C:/Users/John Smith/x", "C:/Users/[REDACTED_USER_1]/x"},
		{"windows space escaped", `C:\\Users\\John Smith\\x`, `C:\\Users\\[REDACTED_USER_1]\\x`},
		{"windows space json", `{"cwd":"C:\\Users\\John Smith\\x"}`, `{"cwd":"C:\\Users\\[REDACTED_USER_1]\\x"}`},
		{"windows three words", `C:\Users\Mary Jane Watson\x`, `C:\Users\[REDACTED_USER_1]\x`},
		{"wsl space", "/mnt/c/Users/John Smith/x", "/mnt/c/Users/[REDACTED_USER_1]/x"},
		{"windows space unclosed", `C:\Users\John Smith`, `C:\Users\[REDACTED_USER_1] Smith`},
		{"windows space then prose", `C:\Users\John Smith: ok`, `C:\Users\[REDACTED_USER_1] Smith: ok`},
		{"windows space at quote", `"C:\Users\John Smith"`, `"C:\Users\[REDACTED_USER_1] Smith"`},
		{"windows double space", `C:\Users\John  Smith\x`, `C:\Users\[REDACTED_USER_1]  Smith\x`},
		{"windows space not across newline", "C:\\Users\\John\nSmith\\x", "C:\\Users\\[REDACTED_USER_1]\nSmith\\x"},
		{"windows over-redacts prose", `C:\Users\John said hi\x`, `C:\Users\[REDACTED_USER_1]\x`},
		{"unix stays one word", "/Users/John Smith/x", "/Users/[REDACTED_USER_1] Smith/x"},
		{"windows space too long", `C:\Users\` + strings.Repeat("a", 40) + " " + strings.Repeat("b", 40) + `\x`,
			`C:\Users\[REDACTED_USER_1] ` + strings.Repeat("b", 40) + `\x`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := NewRedactor(testDetector, NewVault()).Redact(c.in)
			if got != c.want {
				t.Errorf("Redact(%q)\n got  %q\n want %q", c.in, got, c.want)
			}
		})
	}
}

func TestHomePathNoMatch(t *testing.T) {
	for _, in := range []string{
		"/Users/Shared/x", "/Users/Public", "/Users/Default", "/Users/default/x", `C:\Users\Public\x`,
		`C:\Users\All Users\x`, `C:\Users\Default User\x`, `C:\\Users\\Default\\x`,
		"/home/", "/home/ x", "/Users/", "/usr/home", "/usr/home/", "/usr/home/alice",
		"see ~/home/x", "/Users/.localized", "/Users/'x", "/srv/app/home/alice",
		"/Users", "home/alice", "Users/alice", "http:/users/alice", "example/home/about",
	} {
		if ms := testDetector.Detect(in); len(ms) != 0 {
			t.Errorf("Detect(%q) = %+v, want none", in, ms)
		}
	}
}

func TestHomePathRule(t *testing.T) {
	s := "cwd /Users/alice"
	ms := testDetector.Detect(s)
	if len(ms) != 1 || ms[0].Kind != KindUser || ms[0].Rule != "home-path" || s[ms[0].Start:ms[0].End] != "alice" {
		t.Errorf("Detect(%q) = %+v", s, ms)
	}
}

func TestHomePathPriority(t *testing.T) {
	// EMAIL wins over USER: the whole address is one placeholder.
	got, _ := NewRedactor(testDetector, NewVault()).Redact("/Users/alice@corp.io/x")
	if got != "/Users/[REDACTED_EMAIL_1]/x" {
		t.Errorf("got %q", got)
	}
	// USER wins over DOMAIN: a dotted username is one USER.
	got, _ = NewRedactor(testDetector, NewVault()).Redact("/home/alice.example.com/x")
	if got != "/home/[REDACTED_USER_1]/x" {
		t.Errorf("got %q", got)
	}
}

func TestHomePathIdempotentAndRestores(t *testing.T) {
	v := NewVault()
	in := `cwd /Users/alice/src and C:\Users\bob\x and /home/alice and C:\Users\John Smith\x`
	once, _ := NewRedactor(testDetector, v).Redact(in)
	twice, _ := NewRedactor(testDetector, v).Redact(once)
	if once != twice {
		t.Errorf("not idempotent: %q then %q", once, twice)
	}
	if got := v.Restore(once); got != in {
		t.Errorf("Restore = %q, want %q", got, in)
	}
}
