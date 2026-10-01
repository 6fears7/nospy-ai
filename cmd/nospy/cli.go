package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// Exit codes. A wrapped command's own exit code is passed through unchanged.
const (
	exitFail  = 1 // nospy itself failed (listen, log file, ...)
	exitUsage = 2 // bad arguments or configuration
)

// command describes one subcommand for help output.
type command struct {
	usage    string
	summary  string
	examples []string
	define   func(fs *flag.FlagSet) // registers the command's flags; nil if it has none
}

// commands is keyed by name; "nospy" is the wrapper form `nospy [flags] -- <command>`.
var commands = map[string]command{
	"nospy": {
		usage: "nospy [flags] -- <command> [args...]\n       nospy serve|check|healthcheck|hash-token|scan|env|providers|version|help ...",
		summary: "Run <command> behind a local redacting proxy. Secrets and PII in requests to the LLM API\n" +
			"are replaced by placeholders like [REDACTED_EMAIL_1], and the real values are restored\n" +
			"in responses. The proxy listens on 127.0.0.1 behind a random per-run path token, and nospy\n" +
			"hands its address to the command through base-URL env vars (and, for known agents, a\n" +
			"settings file).\n" +
			"Commands:\n" +
			"  serve       run the proxy as a long-lived server with authentication\n" +
			"  check       validate a serve configuration and exit\n" +
			"  healthcheck probe a running serve's /healthz (for container health checks)\n" +
			"  hash-token  create a proxy token and its tokens-file line\n" +
			"  scan        redact stdin to stdout\n" +
			"  env         print shell exports that point an agent at a running nospy service\n" +
			"  providers   list the built-in providers for --provider\n" +
			"  version     print version information\n" +
			"  help        help for a command",
		examples: []string{"nospy -- claude", "nospy --log /tmp/nospy.log -- claude -p 'hello'", "nospy --terms terms.txt -- <agent>", "nospy --provider NAME -- <agent>   (see `nospy providers`)"},
		define:   func(fs *flag.FlagSet) { defineWrapFlags(fs) },
	},
	"serve": {
		usage: "nospy serve --auth none|static-tokens --route PREFIX=URL[,...] [flags]",
		summary: "Run the redacting proxy as a long-lived server, for a sidecar, a shared service or any agent\n" +
			"not started by `nospy --`. Every request is authenticated before its body is read; nothing\n" +
			"unauthenticated is forwarded. Only the routes you list are served. GET /healthz and /readyz need\n" +
			"no credentials. Logs are JSON on stdout, one line per request. SIGTERM stops accepting and\n" +
			"lets in-flight requests and streams finish, up to --shutdown-timeout.\n" +
			"A non-loopback --listen needs --auth static-tokens and TLS (or --insecure-plaintext);\n" +
			"--auth none is loopback only. See `nospy check` to validate the same flags without listening.",
		examples: []string{
			"nospy serve --auth none --listen 127.0.0.1:8788 --route /anthropic=https://api.example.com,key-mode=inject,key-file=/run/secrets/key",
			"nospy serve --auth static-tokens --tokens-file tokens.txt --listen :8443 --tls-cert tls.crt --tls-key tls.key --route /myllm=https://llm.example/v1,api=openai",
		},
		define: func(fs *flag.FlagSet) { defineServeFlags(fs) },
	},
	"check": {
		usage: "nospy check [serve flags]",
		summary: "Validate a serve configuration without listening: flag combinations, the terms file, the tokens\n" +
			"file, key files, the TLS pair (parses, matches, not expired) and the upstream URLs. It builds the\n" +
			"configuration with the same code as `nospy serve`. Exit 0 prints a one-line summary (no secrets,\n" +
			"tokens, keys or terms) and warns when the TLS certificate expires within 14 days; any problem\n" +
			"exits 1 and every problem is listed.",
		examples: []string{"nospy check --auth static-tokens --tokens-file tokens.txt --listen :8443 --tls-cert tls.crt --tls-key tls.key --route /myllm=https://llm.example/v1,api=openai"},
		define:   func(fs *flag.FlagSet) { defineServeFlags(fs) },
	},
	"healthcheck": {
		usage: "nospy healthcheck [--listen ADDR] [--scheme http|https] [--timeout DUR]",
		summary: "Probe a running `nospy serve`: GET /healthz, exit 0 on 200 and 1 otherwise, with the reason on stderr.\n" +
			"For container health checks and Kubernetes exec probes, since the image has no shell or curl.\n" +
			"The same --listen value serve got works here (a wildcard address probes 127.0.0.1). The probe\n" +
			"sends no token or key, follows no redirects and uses no proxy; with --scheme https it does not\n" +
			"verify the certificate.",
		examples: []string{"nospy healthcheck", "nospy healthcheck --listen 0.0.0.0:8788", "nospy healthcheck --listen 127.0.0.1:8443 --scheme https --timeout 3s"},
		define:   func(fs *flag.FlagSet) { defineHealthcheckFlags(fs) },
	},
	"hash-token": {
		usage: "nospy hash-token --name NAME [--stdin]",
		summary: "Create a proxy token for a client and print its tokens-file line. The token is 32 random bytes as\n" +
			"nspy_<base64url>; it is shown once and never stored, so give it to the client. The line, NAME:<sha256hex>,\n" +
			"goes in the file passed to `nospy serve --tokens-file`; only the hash is kept there. With --stdin, hash a\n" +
			"token you already have (read from standard input) and print only the line. NAME appears in logs.",
		examples: []string{"nospy hash-token --name ci-runner", "printf %s \"$TOKEN\" | nospy hash-token --name ci-runner --stdin"},
		define:   func(fs *flag.FlagSet) { defineHashTokenFlags(fs) },
	},
	"scan": {
		usage:   "nospy scan [--explain] [--terms FILE] [FILE...]",
		summary: "Read FILEs (or stdin when none are given; \"-\" is stdin), write them to stdout with sensitive values\nreplaced by placeholders, and print redaction counts per kind to stderr. The same value gets the same\nplaceholder in every file. With --explain, print one line per match instead (prefixed with the file\nname when there are several inputs).",
		examples: []string{
			`echo "ssh root@10.0.0.5" | nospy scan`,
			"nospy scan --explain < .env",
			"nospy scan --terms terms.txt notes.md",
			"git diff | nospy scan --terms terms.txt",
		},
		define: func(fs *flag.FlagSet) { defineScanFlags(fs) },
	},
	"env": {
		usage:   "nospy env --addr URL [--token T] [--shell sh|fish]",
		summary: "Print the exports that point a shell at a running nospy service. The shell defaults to\nthe basename of $SHELL (fish gets `set -gx`, anything else `export`).",
		examples: []string{
			"nospy env --addr http://127.0.0.1:8788 | source",
			"eval \"$(nospy env --addr http://nospy.internal:8788 --token abc --shell sh)\"",
		},
		define: func(fs *flag.FlagSet) { defineEnvFlags(fs) },
	},
	"providers": {
		usage:    "nospy providers",
		summary:  "List the built-in providers: name, API family and upstream. Use one with\n`nospy --provider NAME -- <command>`, which adds the route /NAME and points the API family's\nbase-URL variable (ANTHROPIC_BASE_URL or OPENAI_BASE_URL) at it. You still supply the provider's\nkey the usual way; nospy passes it through.",
		examples: []string{"nospy providers"},
	},
	"version": {
		usage:   "nospy version",
		summary: "Print the version, commit, Go version and platform.",
	},
	"help": {
		usage:    "nospy help [command]",
		summary:  "Show help for a command.",
		examples: []string{"nospy help scan"},
	},
}

func (c command) printHelp(w io.Writer) {
	_, _ = fmt.Fprintf(w, "usage: %s\n\n%s\n", c.usage, c.summary)
	if c.define != nil {
		fs := newFlagSet(w)
		c.define(fs)
		n := 0
		fs.VisitAll(func(*flag.Flag) { n++ })
		if n > 0 {
			_, _ = fmt.Fprint(w, "\nFlags:\n")
			fs.PrintDefaults()
		}
	}
	if len(c.examples) > 0 {
		_, _ = fmt.Fprint(w, "\nExamples:\n")
		for _, e := range c.examples {
			_, _ = fmt.Fprintf(w, "  %s\n", e)
		}
	}
}

func newFlagSet(out io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("nospy", flag.ContinueOnError)
	fs.SetOutput(out)
	return fs
}

// parseFlags parses args into fs. ok is false when the caller should stop and return code:
// help was requested (0) or the arguments were bad (exitUsage, short usage on stderr).
func parseFlags(name string, fs *flag.FlagSet, args []string, stdout, stderr io.Writer) (code int, ok bool) {
	fs.SetOutput(io.Discard) // we print errors and help ourselves
	fs.Usage = func() {}
	err := fs.Parse(args)
	switch {
	case err == nil:
		return 0, true
	case errors.Is(err, flag.ErrHelp):
		commands[name].printHelp(stdout)
		return 0, false
	}
	return usageError(name, stderr, "%v", err), false
}

// usageError prints msg and the command's usage line to stderr and returns exitUsage.
func usageError(name string, stderr io.Writer, format string, a ...any) int {
	first, _, _ := strings.Cut(commands[name].usage, "\n")
	_, _ = fmt.Fprintf(stderr, "nospy: %s\nusage: %s\nRun 'nospy help' for details.\n", fmt.Sprintf(format, a...), first)
	return exitUsage
}

// run is nospy's entry point, separate from main so tests can call it. getenv reads the
// parent's environment; the wrapped command gets the real os.Environ().
func run(args []string, getenv func(string) string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return runServe(args[1:], stdout, stderr)
		case "check":
			return runCheck(args[1:], stdout, stderr)
		case "healthcheck":
			return runHealthcheck(args[1:], stdout, stderr)
		case "hash-token":
			return runHashToken(args[1:], stdin, stdout, stderr)
		case "scan":
			return runScan(args[1:], stdin, stdout, stderr)
		case "env":
			return runEnv(args[1:], getenv, stdout, stderr)
		case "providers":
			return runProviders(args[1:], stdout, stderr)
		case "version", "--version", "-version":
			if len(args) > 1 {
				return usageError("version", stderr, "unexpected argument %q", args[1])
			}
			if _, err := fmt.Fprintln(stdout, versionString()); err != nil {
				return exitFail
			}
			return 0
		case "help":
			return runHelp(args[1:], stdout, stderr)
		}
	}
	return runWrap(args, getenv, stdin, stdout, stderr)
}

func runHelp(args []string, stdout, stderr io.Writer) int {
	name := "nospy"
	if len(args) > 0 {
		name = args[0]
	}
	c, ok := commands[name]
	if !ok || len(args) > 1 {
		return usageError("help", stderr, "no help for %q", strings.Join(args, " "))
	}
	c.printHelp(stdout)
	return 0
}
