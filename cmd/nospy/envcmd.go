package main

import (
	"flag"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"
)

type envOpts struct {
	addr, token, shell string
}

func defineEnvFlags(fs *flag.FlagSet) *envOpts {
	o := &envOpts{}
	fs.StringVar(&o.addr, "addr", "", "base `URL` of the running nospy service (required)")
	fs.StringVar(&o.token, "token", "", "passthrough path `token`; the URLs then carry /t/<token>")
	fs.StringVar(&o.shell, "shell", "", "output `syntax`, sh or fish (default: from $SHELL, else sh)")
	return o
}

// runEnv prints the exports that point a shell at a running `nospy serve`.
func runEnv(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	fs := newFlagSet(io.Discard)
	o := defineEnvFlags(fs)
	if code, ok := parseFlags("env", fs, args, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() > 0 {
		return usageError("env", stderr, "unexpected argument %q", fs.Arg(0))
	}
	u, err := url.Parse(o.addr)
	if o.addr == "" || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return usageError("env", stderr, "--addr must be an absolute http(s) URL")
	}
	if strings.Contains(o.token, "/") {
		return usageError("env", stderr, "--token must not contain '/'")
	}
	shell := o.shell
	if shell == "" {
		shell = "sh"
		if filepath.Base(getenv("SHELL")) == "fish" {
			shell = "fish"
		}
	}
	quote, export := shQuote, "export %s=%s\n"
	switch shell {
	case "sh":
	case "fish":
		quote, export = fishQuote, "set -gx %s %s\n"
	default:
		return usageError("env", stderr, "--shell must be sh or fish, not %q", shell)
	}

	base := strings.TrimRight(o.addr, "/")
	if o.token != "" {
		base += "/t/" + o.token
	}
	if _, err := fmt.Fprintf(stdout, export, "ANTHROPIC_BASE_URL", quote(base+"/anthropic")); err != nil {
		return exitFail
	}
	if _, err := fmt.Fprintf(stdout, export, "OPENAI_BASE_URL", quote(base+"/openai/v1")); err != nil {
		return exitFail
	}
	return 0
}

// shQuote single-quotes s for POSIX shells.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fishQuote single-quotes s for fish, where only \' and \\ are escapes inside quotes.
func fishQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}
