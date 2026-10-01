package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// fakeAgent writes an executable shell script called name (so basename matching applies) and returns its path.
func fakeAgent(t *testing.T, name, script string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// argLines parses the "ARG <value>" lines a fake agent prints, in order.
func argLines(out string) []string {
	var args []string
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "ARG "); ok {
			args = append(args, v)
		}
	}
	return args
}

const printArgs = `for a in "$@"; do echo "ARG $a"; done` + "\n"

func TestInjectAgentConfig(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	// Prints the args, the modes of the settings dir and file, and the file's content.
	claude := fakeAgent(t, "claude", printArgs+`
echo "DIRMODE $(ls -ld "$(dirname "$2")" | cut -c1-10)"
echo "FILEMODE $(ls -l "$2" | cut -c1-10)"
echo "BODY $(cat "$2")"
`)
	code, out, errb := runWrapCLI(t, noEnv, "--", claude, "-p", "hi")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	args := argLines(out)
	if len(args) != 4 || args[0] != "--settings" || args[2] != "-p" || args[3] != "hi" {
		t.Fatalf("args = %q, want --settings <path> right after the command", args)
	}
	if !strings.Contains(out, "DIRMODE drwx------\n") || !strings.Contains(out, "FILEMODE -rw-------\n") {
		t.Errorf("modes wrong:\n%s", out)
	}
	if filepath.Dir(filepath.Dir(args[1])) != tmp {
		t.Errorf("settings path %q is not one directory deep in TMPDIR", args[1])
	}
	m := regexp.MustCompile(`BODY (.*)`).FindStringSubmatch(out)
	var body struct{ Env map[string]string }
	if m == nil || json.Unmarshal([]byte(m[1]), &body) != nil {
		t.Fatalf("settings body not JSON: %q", out)
	}
	for _, rt := range routeTable {
		u := body.Env[rt.envVar]
		if !regexp.MustCompile(`^http://127\.0\.0\.1:\d+/[0-9a-f]{32}` + rt.prefix + rt.baseSuffix + `$`).MatchString(u) {
			t.Errorf("settings env %s = %q", rt.envVar, u)
		}
	}
	if len(body.Env) != len(routeTable) {
		t.Errorf("settings env has %d vars, want %d", len(body.Env), len(routeTable))
	}
	// The URL (with the session token) must not be in argv.
	if strings.Contains(strings.Join(args, " "), "127.0.0.1") || strings.Contains(strings.Join(args, " "), "http") {
		t.Errorf("argv carries a URL: %q", args)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("temp dir not cleaned after a normal exit: %v", left)
	}
}

func TestInjectCleanupAfterSIGTERM(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	claude := fakeAgent(t, "claude", `trap 'exit 7' TERM; echo "SETTINGS $2"; echo ready; while :; do sleep 0.05; done`+"\n")
	var out syncBuffer
	var errb bytes.Buffer
	done := make(chan int, 1)
	go func() { done <- run([]string{"--", claude}, noEnv, strings.NewReader(""), &out, &errb) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "ready") {
		if time.Now().After(deadline) {
			t.Fatal("child never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 1 {
		t.Fatalf("expected the settings dir while the child runs, got %v", left)
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-done:
		if code != 7 {
			t.Errorf("code=%d stderr=%q", code, errb.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("wrapper did not exit after SIGTERM")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("temp dir not cleaned after SIGTERM: %v", left)
	}
}

func TestInjectMatchesByBasename(t *testing.T) {
	var sink bytes.Buffer
	env := map[string]string{"X_BASE_URL": "http://h/tok/p"}
	got, cleanup, err := injectAgentConfig([]string{"/usr/local/bin/claude", "-p", "x"}, env, false, &sink)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(got) != 5 || got[0] != "/usr/local/bin/claude" || got[1] != "--settings" || !slices.Equal(got[3:], []string{"-p", "x"}) {
		t.Errorf("got %q", got)
	}
	cleanup()
	if _, err := os.Stat(filepath.Dir(got[2])); !os.IsNotExist(err) {
		t.Errorf("cleanup left the dir behind: %v", err)
	}

	for _, cmd := range []string{"sh", "/bin/sh", "claude-wrapper", "notclaude", "/opt/claude/run"} {
		in := []string{cmd, "-c", "true"}
		got, cleanup, err := injectAgentConfig(in, env, false, &sink)
		cleanup()
		if err != nil || !slices.Equal(got, in) {
			t.Errorf("%s: got %q, %v; want untouched", cmd, got, err)
		}
	}
	if sink.Len() != 0 {
		t.Errorf("unexpected output %q", sink.String())
	}
}

func TestInjectSkippedWhenUserGivesSettings(t *testing.T) {
	claude := fakeAgent(t, "claude", printArgs)
	for _, userArgs := range [][]string{
		{"--settings", "x.json", "-p", "hi"},
		{"--settings=x.json", "-p", "hi"},
	} {
		code, out, errb := runWrapCLI(t, noEnv, append([]string{"--", claude}, userArgs...)...)
		if code != 0 {
			t.Fatalf("code=%d stderr=%q", code, errb)
		}
		if got := argLines(out); !slices.Equal(got, userArgs) {
			t.Errorf("args = %q, want the user's %q", got, userArgs)
		}
		if strings.Count(errb, "\n") != 1 || !strings.HasPrefix(errb, "nospy: notice: --settings already given") {
			t.Errorf("want exactly one notice line, got %q", errb)
		}
		if strings.Contains(errb, "127.0.0.1") {
			t.Errorf("notice leaks the URL: %q", errb)
		}
	}
}

func TestNoAgentConfigFlag(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	claude := fakeAgent(t, "claude", printArgs)
	code, out, errb := runWrapCLI(t, noEnv, "--no-agent-config", "--", claude, "-p", "hi")
	if code != 0 || errb != "" {
		t.Fatalf("code=%d stderr=%q", code, errb)
	}
	if got := argLines(out); !slices.Equal(got, []string{"-p", "hi"}) {
		t.Errorf("args = %q, want the user's only", got)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("a settings dir was created: %v", left)
	}
}
