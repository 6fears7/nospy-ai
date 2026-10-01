package main

import (
	"bytes"
	"io"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
)

func noEnv(string) string { return "" }

// runCLI runs the CLI with no stdin and returns exit code, stdout and stderr.
func runCLI(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, noEnv, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestHelpExitsZero(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--help"}, "usage: nospy [flags] -- <command>"},
		{[]string{"-h"}, "usage: nospy [flags] -- <command>"},
		{[]string{"help"}, "usage: nospy [flags] -- <command>"},
		{[]string{"help", "scan"}, "usage: nospy scan [--explain]"},
		{[]string{"scan", "--help"}, "usage: nospy scan [--explain]"},
		{[]string{"help", "env"}, "usage: nospy env --addr URL"},
		{[]string{"env", "-h"}, "--shell"},
		{[]string{"--log", "x.log", "--help"}, "--log"},
		{[]string{"--help"}, "-route PREFIX=URL"},
		{[]string{"--help"}, "-no-agent-config"},
	}
	for _, c := range cases {
		code, out, errb := runCLI(t, "", c.args...)
		if code != 0 || !strings.Contains(out, c.want) || errb != "" {
			t.Errorf("%v: code=%d stdout=%q stderr=%q, want 0 and %q", c.args, code, out, errb, c.want)
		}
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	cases := [][]string{
		{"--bogus"},
		{"scan", "--bogus"},
		{"env"},                      // --addr required
		{"env", "--addr", "ftp://x"}, // not http(s)
		{"env", "--addr", "http://x", "--shell", "powershell"},
		{"env", "--addr", "http://x", "--token", "a/b"},
		{"scan", "-", "-"}, // stdin twice
		{"help", "nosuchcommand"},
		{"version", "extra"},
		{},                   // no command
		{"--"},               // no command after --
		{"sh", "-c", "true"}, // missing --
		{"--route", "/anthropic=not a url", "--", "true"},
		{"--route", "/anthropic=ftp://x", "--", "true"},
		{"--route", "/nosuch=http://x", "--", "true"},
		{"--route", "http://x", "--", "true"}, // missing PREFIX=
		{"--route", "/anthropic=", "--", "true"},
		{"--route", "/anthropic=http://a", "--route", "/anthropic=http://b", "--", "true"},
		{"--anthropic-upstream", "http://x", "--", "true"}, // removed flag
	}
	for _, args := range cases {
		code, out, errb := runCLI(t, "", args...)
		if code != 2 || out != "" || !strings.Contains(errb, "usage:") {
			t.Errorf("%v: code=%d stdout=%q stderr=%q, want 2 with usage on stderr", args, code, out, errb)
		}
	}
}

func TestVersion(t *testing.T) {
	re := regexp.MustCompile(`^nospy \S+ \(`)
	for _, args := range [][]string{{"--version"}, {"version"}} {
		code, out, _ := runCLI(t, "", args...)
		if code != 0 || !re.MatchString(out) {
			t.Errorf("%v: code=%d out=%q", args, code, out)
		}
	}
}

func TestFormatVersion(t *testing.T) {
	bi := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "vcs.revision", Value: "0123456789abcdef"},
		{Key: "vcs.modified", Value: "true"},
	}}
	if got := formatVersion("1.2.3", bi); !strings.HasPrefix(got, "nospy 1.2.3 (0123456-dirty, go") {
		t.Errorf("got %q", got)
	}
	if got := formatVersion("dev", nil); !strings.HasPrefix(got, "nospy dev (unknown, go") {
		t.Errorf("got %q", got)
	}
}

type failingOutput struct{ writesLeft int }

func (w *failingOutput) Write(p []byte) (int, error) {
	if w.writesLeft == 0 {
		return 0, io.ErrClosedPipe
	}
	w.writesLeft--
	return len(p), nil
}

func TestCommandsFailWhenOutputCannotBeWritten(t *testing.T) {
	for _, tc := range []struct {
		name       string
		args       []string
		writesLeft int
	}{
		{"version", []string{"version"}, 0},
		{"scan", []string{"scan"}, 0},
		{"explain", []string{"scan", "--explain"}, 0},
		{"env first export", []string{"env", "--addr", "http://localhost:8788"}, 0},
		{"env second export", []string{"env", "--addr", "http://localhost:8788"}, 1},
		{"providers", []string{"providers"}, 0},
		{"generated token", []string{"hash-token", "--name", "test"}, 0},
		{"generated token hash", []string{"hash-token", "--name", "test"}, 1},
		{"stdin token hash", []string{"hash-token", "--name", "test", "--stdin"}, 0},
		{"check", []string{"check", "--auth", "none", "--route", "/anthropic=https://api.example.com"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := &failingOutput{writesLeft: tc.writesLeft}
			if code := run(tc.args, noEnv, strings.NewReader("canary@example.com"), out, io.Discard); code != exitFail {
				t.Fatalf("exit code %d, want %d for a failed output write", code, exitFail)
			}
		})
	}
}
