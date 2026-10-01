package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"strings"
	"unicode"

	"nospyai/internal/proxy"
)

// tokenPrefix marks nospy proxy tokens. The redaction rule known-token/nspy matches it, so a
// token pasted into a prompt is redacted like any other key.
const tokenPrefix = "nspy_"

type hashTokenOpts struct {
	name  string
	stdin bool
}

func defineHashTokenFlags(fs *flag.FlagSet) *hashTokenOpts {
	o := &hashTokenOpts{}
	fs.StringVar(&o.name, "name", "", "the client's `name`, [a-z0-9][a-z0-9-]*; it appears in logs and scopes conversation state")
	fs.BoolVar(&o.stdin, "stdin", false, "hash the token read from standard input instead of generating one")
	return o
}

// newProxyToken returns 32 random bytes as nspy_<base64url>.
func newProxyToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// runHashToken prints a token (once) and the tokens-file line that authenticates it.
func runHashToken(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet(io.Discard)
	o := defineHashTokenFlags(fs)
	if code, ok := parseFlags("hash-token", fs, args, stdout, stderr); !ok {
		return code
	}
	if fs.NArg() > 0 {
		return usageError("hash-token", stderr, "unexpected argument %q", fs.Arg(0))
	}
	if !proxy.ClientNameRe.MatchString(o.name) {
		return usageError("hash-token", stderr, "--name is required and must match [a-z0-9][a-z0-9-]*")
	}

	var token string
	if o.stdin {
		b, err := io.ReadAll(io.LimitReader(stdin, 4097))
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "nospy: reading stdin: %v\n", err)
			return exitFail
		}
		token = strings.TrimSpace(string(b))
		if token == "" || len(token) > 4096 || strings.IndexFunc(token, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return usageError("hash-token", stderr, "stdin must hold one token (non-empty, no whitespace, at most 4096 bytes)")
		}
	} else {
		var err error
		if token, err = newProxyToken(); err != nil {
			_, _ = fmt.Fprintf(stderr, "nospy: generating token: %v\n", err)
			return exitFail
		}
		if _, err := fmt.Fprintf(stdout, "Token (shown once):\n  %s\n", token); err != nil {
			return exitFail
		}
	}
	if _, err := fmt.Fprintf(stdout, "Tokens-file line (add it to the file passed to --tokens-file):\n  %s:%s\n", o.name, proxy.HashToken(token)); err != nil {
		return exitFail
	}
	return 0
}
