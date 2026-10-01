package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestEnvShells(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		shell string // $SHELL
		want  string
	}{
		{"sh flag", []string{"--addr", "http://10.0.0.1:8788", "--shell", "sh"},
			"/usr/bin/fish",
			"export ANTHROPIC_BASE_URL='http://10.0.0.1:8788/anthropic'\nexport OPENAI_BASE_URL='http://10.0.0.1:8788/openai/v1'\n"},
		{"fish flag", []string{"--addr", "http://10.0.0.1:8788/", "--shell", "fish"},
			"/bin/bash",
			"set -gx ANTHROPIC_BASE_URL 'http://10.0.0.1:8788/anthropic'\nset -gx OPENAI_BASE_URL 'http://10.0.0.1:8788/openai/v1'\n"},
		{"default from $SHELL=fish", []string{"--addr", "http://h:1"}, "/opt/homebrew/bin/fish",
			"set -gx ANTHROPIC_BASE_URL 'http://h:1/anthropic'\nset -gx OPENAI_BASE_URL 'http://h:1/openai/v1'\n"},
		{"default from $SHELL=zsh", []string{"--addr", "http://h:1"}, "/bin/zsh",
			"export ANTHROPIC_BASE_URL='http://h:1/anthropic'\nexport OPENAI_BASE_URL='http://h:1/openai/v1'\n"},
		{"default without $SHELL", []string{"--addr", "http://h:1"}, "",
			"export ANTHROPIC_BASE_URL='http://h:1/anthropic'\nexport OPENAI_BASE_URL='http://h:1/openai/v1'\n"},
		{"token", []string{"--addr", "http://h:1", "--token", "abc", "--shell", "sh"}, "",
			"export ANTHROPIC_BASE_URL='http://h:1/t/abc/anthropic'\nexport OPENAI_BASE_URL='http://h:1/t/abc/openai/v1'\n"},
		{"sh quoting", []string{"--addr", "http://h:1", "--token", "a'b c$d", "--shell", "sh"}, "",
			`export ANTHROPIC_BASE_URL='http://h:1/t/a'\''b c$d/anthropic'` + "\n" +
				`export OPENAI_BASE_URL='http://h:1/t/a'\''b c$d/openai/v1'` + "\n"},
		{"fish quoting", []string{"--addr", "http://h:1", "--token", `a'b\c`, "--shell", "fish"}, "",
			`set -gx ANTHROPIC_BASE_URL 'http://h:1/t/a\'b\\c/anthropic'` + "\n" +
				`set -gx OPENAI_BASE_URL 'http://h:1/t/a\'b\\c/openai/v1'` + "\n"},
	}
	for _, c := range cases {
		var out, errb bytes.Buffer
		getenv := func(k string) string {
			if k == "SHELL" {
				return c.shell
			}
			return ""
		}
		code := run(append([]string{"env"}, c.args...), getenv, strings.NewReader(""), &out, &errb)
		if code != 0 || out.String() != c.want || errb.Len() != 0 {
			t.Errorf("%s: code=%d\n got %q\nwant %q\nstderr %q", c.name, code, out.String(), c.want, errb.String())
		}
	}
}
