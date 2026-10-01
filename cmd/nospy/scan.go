package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"
	"unicode/utf8"

	"nospyai/internal/redact"
)

type scanOpts struct {
	explain bool
	terms   string
}

const termsFlagUsage = "redact the custom terms listed in `file` (one per line, [SECTION] headers set the placeholder kind, re: for a regex, [ALLOW] for exceptions). The file is sensitive and is never logged"

// loadTermsFlag loads the --terms file; "" means none. On failure it prints every line-numbered
// problem (never the terms themselves) and returns the exit code.
func loadTermsFlag(cmd, path string, stderr io.Writer) (*redact.Terms, int) {
	if path == "" {
		return nil, 0
	}
	t, err := redact.LoadTermsFile(path)
	if err != nil {
		return nil, usageError(cmd, stderr, "--terms %s:\n  %s", path, strings.ReplaceAll(err.Error(), "\n", "\n  "))
	}
	return t, 0
}

func defineScanFlags(fs *flag.FlagSet) *scanOpts {
	o := &scanOpts{}
	fs.BoolVar(&o.explain, "explain", false, "print one line per match (line:col  KIND  rule  \"text\") instead of the redacted text; prints real values")
	fs.StringVar(&o.terms, "terms", "", termsFlagUsage)
	return o
}

// runScan redacts the FILE arguments (stdin when there are none, and for "-") to stdout, for
// trying the detectors by hand. One detector and vault serve the whole run, so a value gets the
// same placeholder in every input.
func runScan(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := newFlagSet(io.Discard)
	o := defineScanFlags(fs)
	if code, ok := parseFlags("scan", fs, args, stdout, stderr); !ok {
		return code
	}
	names := fs.Args()
	if len(names) == 0 {
		if isTerminal(stdin) {
			return usageError("scan", stderr, "no input: pass a FILE or pipe text to stdin")
		}
		names = []string{"-"}
	}
	stdinUsed := false
	for _, n := range names {
		if n == "-" {
			if stdinUsed {
				return usageError("scan", stderr, "stdin (-) given more than once")
			}
			stdinUsed = true
		}
	}
	terms, code := loadTermsFlag("scan", o.terms, stderr)
	if code != 0 {
		return code
	}
	// Read every input before writing anything, so a bad path never leaves partial output.
	texts := make([]string, len(names))
	for i, n := range names {
		b, err := readInput(n, stdin)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "nospy: %v\n", err)
			return exitFail
		}
		texts[i] = string(b)
	}
	det := redact.NewDetector(redact.Config{AllowHosts: defaultHosts(), Terms: terms})

	if o.explain {
		// The one place real values are printed on purpose; never reachable from the proxy.
		if !isTerminal(stdout) {
			_, _ = fmt.Fprintln(stderr, "nospy: warning: --explain prints the real matched values and stdout is not a terminal")
		}
		for i, s := range texts {
			prefix := ""
			if len(names) > 1 {
				prefix = names[i] + ":"
			}
			if err := explain(stdout, prefix, s, det.Detect(s)); err != nil {
				return exitFail
			}
		}
		return 0
	}
	r := redact.NewRedactor(det, redact.NewVault())
	total := map[string]int{}
	var last byte
	for _, s := range texts {
		out, counts := r.Redact(s)
		if _, err := fmt.Fprint(stdout, out); err != nil {
			return exitFail
		}
		if out != "" {
			last = out[len(out)-1]
		}
		for k, n := range counts {
			total[k] += n
		}
	}
	// On a terminal, keep the summary off the unterminated last output line (stderr only; stdout stays byte-exact).
	if last != 0 && last != '\n' && isTerminal(stdout) {
		_, _ = fmt.Fprintln(stderr)
	}
	_, _ = fmt.Fprintln(stderr, summarize(total, terms != nil))
	return 0
}

// readInput reads one scan input: stdin for "-", else the file. Errors name the source, never contents.
func readInput(name string, stdin io.Reader) ([]byte, error) {
	if name == "-" {
		b, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("reading stdin: %w", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(name) //nolint:gosec // CLI argument chosen by the user
	if err != nil {
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return b, nil
}

// explain writes one line per match: [prefix]line:col  KIND  rule  "text". Columns count runes.
func explain(w io.Writer, prefix, s string, ms []redact.Match) error {
	line, prev := 1, 0
	for _, m := range ms {
		line += strings.Count(s[prev:m.Start], "\n")
		prev = m.Start
		col := utf8.RuneCountInString(s[strings.LastIndexByte(s[:m.Start], '\n')+1:m.Start]) + 1
		if _, err := fmt.Fprintf(w, "%s%d:%d  %s  %s  %q\n", prefix, line, col, m.Kind, m.Rule, s[m.Start:m.End]); err != nil {
			return err
		}
	}
	return nil
}

// summarize is the stderr line for a scan: counts per kind, never values.
func summarize(counts map[string]int, hasTerms bool) string {
	if len(counts) == 0 {
		if !hasTerms {
			return "nospy: nothing redacted (built-in rules only; no --terms file)"
		}
		return "nospy: nothing redacted"
	}
	kinds := make([]string, 0, len(counts))
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, len(kinds))
	for i, k := range kinds {
		parts[i] = fmt.Sprintf("%s=%d", k, counts[k])
	}
	return "nospy: redacted " + strings.Join(parts, " ")
}

// isTerminal reports whether v (stdin or stdout) is a character device (a tty), as opposed to a
// pipe, a file or a non-file reader. /dev/null is a character device too but is not a terminal.
func isTerminal(v any) bool {
	f, ok := v.(interface{ Stat() (os.FileInfo, error) })
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	null, err := os.Stat(os.DevNull)
	return err != nil || !os.SameFile(st, null)
}
