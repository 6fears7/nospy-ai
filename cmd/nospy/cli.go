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
		usage: "nospy [flags] -- <command> [args...]",
		summary: "Redacts information from local agents.\n" +
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
		summary: "Run the redacting proxy as a long-lived server, a sidecar, or a shared service",
		examples: []string{
			"nospy serve --auth none --listen 127.0.0.1:8788 --route /anthropic=https://api.example.com,key-mode=inject,key-file=/run/secrets/key",
			"nospy serve --auth static-tokens --tokens-file tokens.txt --listen :8443 --tls-cert tls.crt --tls-key tls.key --route /myllm=https://llm.example/v1,api=openai",
		},
		define: func(fs *flag.FlagSet) { defineServeFlags(fs) },
	},
	"check": {
		usage:    "nospy check [serve flags]",
		summary:  "Validate a serve configuration",
		examples: []string{"nospy check --auth static-tokens --tokens-file tokens.txt --listen :8443 --tls-cert tls.crt --tls-key tls.key --route /myllm=https://llm.example/v1,api=openai"},
		define:   func(fs *flag.FlagSet) { defineServeFlags(fs) },
	},
	"healthcheck": {
		usage:    "nospy healthcheck [--listen ADDR] [--scheme http|https] [--timeout DUR]",
		summary:  "Probe a running `nospy serve`: GET /healthz",
		examples: []string{"nospy healthcheck", "nospy healthcheck --listen 0.0.0.0:8788", "nospy healthcheck --listen 127.0.0.1:8443 --scheme https --timeout 3s"},
		define:   func(fs *flag.FlagSet) { defineHealthcheckFlags(fs) },
	},
	"hash-token": {
		usage:    "nospy hash-token --name NAME [--stdin]",
		summary:  "Create a proxy token for a client and print its tokens-file line.",
		examples: []string{"nospy hash-token --name ci-runner", "printf %s \"$TOKEN\" | nospy hash-token --name ci-runner --stdin"},
		define:   func(fs *flag.FlagSet) { defineHashTokenFlags(fs) },
	},
	"scan": {
		usage:   "nospy scan [--explain] [--terms FILE] [FILE...]",
		summary: "Read FILEs (or stdin when none are given; \"-\" is stdin), write them to stdout with sensitive values\nreplaced by placeholders, and print redaction counts per kind to stderr.",
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
		summary: "Print the exports that point a shell at a running nospy service.",
		examples: []string{
			"nospy env --addr http://127.0.0.1:8788 | source",
			"eval \"$(nospy env --addr http://nospy.internal:8788 --token abc --shell sh)\"",
		},
		define: func(fs *flag.FlagSet) { defineEnvFlags(fs) },
	},
	"providers": {
		usage:    "nospy providers",
		summary:  "List the built-in providers: name, API family and upstream.",
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
