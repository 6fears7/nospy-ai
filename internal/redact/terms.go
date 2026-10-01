package redact

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// KindTerm is the default kind for terms listed before any [SECTION] header.
const KindTerm = "TERM"

const (
	minTermLen   = 3
	maxTermsLine = 1 << 20 // longest accepted line, in bytes
)

var sectionNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// Terms is a parsed custom terms file: employer-specific literals and regexes that become
// redaction kinds named by their section, plus an allowlist. It is immutable and safe for
// concurrent use. The file is sensitive: nothing here is ever logged or echoed in errors.
type Terms struct {
	literals []termLiteral
	regexes  []termRegex
	allow    map[string]bool // lowercased exact strings
	nTerms   int
	sections map[string]bool
}

// termLiteral is every literal of one section compiled into a single alternation.
type termLiteral struct {
	kind     string
	re       *regexp.Regexp // leftmost-longest search
	anchored *regexp.Regexp // same alternation anchored at the start, for retrying a shorter match
}

type termRegex struct {
	kind string
	re   *regexp.Regexp
}

// Count reports how many terms (literals and regexes, not allow entries) were loaded and in
// how many sections. This is all startup may log about the file.
func (t *Terms) Count() (terms, sections int) {
	if t == nil {
		return 0, 0
	}
	return t.nTerms, len(t.sections)
}

// LoadTermsFile opens path and parses it with LoadTerms. Errors from the file contents never
// include the terms themselves.
func LoadTermsFile(path string) (*Terms, error) {
	f, err := os.Open(path) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, fmt.Errorf("terms file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return LoadTerms(f)
}

// LoadTerms parses a terms file (see plan/10-custom-terms.md). All problems are collected
// and returned together, one "terms line N: <problem>" per line; the text of a term or regex
// is deliberately not included.
func LoadTerms(r io.Reader) (*Terms, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxTermsLine)

	var errs []error
	bad := func(n int, format string, a ...any) {
		errs = append(errs, fmt.Errorf("terms line %d: "+format, append([]any{n}, a...)...))
	}

	t := &Terms{allow: map[string]bool{}, sections: map[string]bool{}}
	lits := map[string][]string{} // kind -> normalized literals (whitespace collapsed to one space)
	seen := map[string]bool{}     // dedupe key: kind NUL lowercased literal, or kind NUL re: pattern
	section := KindTerm
	inAllow := false
	sectionOrder := []string{}

	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if n == 1 {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
		}
		line = strings.TrimSpace(stripComment(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := line[1 : len(line)-1]
			switch {
			case name == "ALLOW":
				inAllow = true
			case !sectionNameRe.MatchString(name):
				bad(n, "invalid section name")
				// Keep the previous section so following lines are still validated.
			default:
				inAllow, section = false, name
			}
			continue
		}
		if inAllow {
			if strings.HasPrefix(line, "re:") {
				bad(n, "regex not allowed in ALLOW")
				continue
			}
			if isSecret(line) {
				bad(n, "ALLOW entry looks like a password, token or key; secrets can never be allowed")
				continue
			}
			t.allow[strings.ToLower(line)] = true
			continue
		}
		if expr, ok := strings.CutPrefix(line, "re:"); ok {
			expr = strings.TrimSpace(expr)
			re, err := regexp.Compile(expr)
			switch {
			case expr == "":
				bad(n, "empty regex")
			case err != nil:
				bad(n, "invalid regex")
			case re.MatchString(""):
				bad(n, "regex matches the empty string")
			default:
				key := section + "\x00re:" + expr
				if !seen[key] {
					seen[key] = true
					t.regexes = append(t.regexes, termRegex{section, re})
					t.nTerms++
					t.sections[section] = true
				}
			}
			continue
		}
		if utf8.RuneCountInString(line) < minTermLen {
			bad(n, "term shorter than %d characters", minTermLen)
			continue
		}
		norm := strings.Join(strings.Fields(line), " ")
		key := section + "\x00" + strings.ToLower(norm)
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, ok := lits[section]; !ok {
			sectionOrder = append(sectionOrder, section)
		}
		lits[section] = append(lits[section], norm)
		t.nTerms++
		t.sections[section] = true
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			bad(n+1, "line too long")
		} else {
			errs = append(errs, fmt.Errorf("terms file: %w", err))
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	for _, kind := range sectionOrder {
		tl, err := compileLiterals(kind, lits[kind])
		if err != nil {
			return nil, err
		}
		t.literals = append(t.literals, tl)
	}
	return t, nil
}

// isSecret reports whether the built-in rules see a secret kind anywhere in s. It catches
// obvious mistakes at load time; dropAllowed enforces the rule at match time regardless.
func isSecret(s string) bool {
	for _, m := range NewDetector(Config{}).Detect(s) {
		if secretKinds[m.Kind] {
			return true
		}
	}
	return false
}

// stripComment drops a trailing comment: a '#' at the start of the line or after whitespace.
// A '#' glued to other text (C#) is part of the term.
func stripComment(line string) string {
	for i := 0; i < len(line); i++ {
		if line[i] == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') {
			return line[:i]
		}
	}
	return line
}

// compileLiterals builds one case-insensitive alternation of the section's literals, longest
// first, with internal whitespace matching \s+.
func compileLiterals(kind string, lits []string) (termLiteral, error) {
	sort.SliceStable(lits, func(i, j int) bool { return len(lits[i]) > len(lits[j]) })
	alts := make([]string, len(lits))
	for i, l := range lits {
		words := strings.Split(l, " ")
		for j, w := range words {
			words[j] = regexp.QuoteMeta(w)
		}
		alts[i] = strings.Join(words, `\s+`)
	}
	body := `(?i:` + strings.Join(alts, "|") + `)`
	re, err := regexp.Compile(body)
	if err != nil {
		return termLiteral{}, errors.New("terms: too many or too large literal terms to compile into one matcher; split or shorten the list")
	}
	re.Longest()
	anchored, err := regexp.Compile(`^` + body)
	if err != nil {
		return termLiteral{}, errors.New("terms: too many or too large literal terms to compile into one matcher; split or shorten the list")
	}
	anchored.Longest()
	return termLiteral{kind: kind, re: re, anchored: anchored}, nil
}

// detect reports every term occurrence in s through add (lowest priority, see NewDetector).
func (t *Terms) detect(s string, add addFunc) {
	if t == nil {
		return
	}
	for _, tl := range t.literals {
		tl.detect(s, add)
	}
	for _, tr := range t.regexes {
		for _, l := range tr.re.FindAllStringIndex(s, -1) {
			add(l[0], l[1], tr.kind, prioTerm, "terms-re")
		}
	}
}

func (tl termLiteral) detect(s string, add addFunc) {
	pos := 0
	for pos < len(s) {
		loc := tl.re.FindStringIndex(s[pos:])
		if loc == nil {
			return
		}
		start := pos + loc[0]
		if end, ok := tl.wholeWordAt(s, start, pos+loc[1]); ok {
			add(start, end, tl.kind, prioTerm, "terms")
			pos = end
			continue
		}
		// Rejected: resume just past this start, so a valid later match is not hidden.
		_, size := utf8.DecodeRuneInString(s[start:])
		pos = start + size
	}
}

// wholeWordAt returns the end of the longest whole-word match of the section's terms that
// starts at start, given that the longest match overall is s[start:end]. When that one is
// glued to a word character it retries with shorter alternatives (Orion Next vs Orion in
// "Orion Nextish") by shrinking the text the anchored search may see.
func (tl termLiteral) wholeWordAt(s string, start, end int) (int, bool) {
	for {
		if wholeWord(s, start, end) {
			return end, true
		}
		_, size := utf8.DecodeLastRuneInString(s[start:end])
		limit := end - size
		if limit <= start {
			return 0, false
		}
		l := tl.anchored.FindStringIndex(s[start:limit])
		if l == nil {
			return 0, false
		}
		end = start + l[1]
	}
}

// wholeWord enforces the boundary only on an edge whose own character is a word character, so
// terms that begin or end with punctuation (.NET, C++) still match next to letters.
func wholeWord(s string, start, end int) bool {
	first, _ := utf8.DecodeRuneInString(s[start:end])
	if isWordRune(first) && start > 0 {
		if prev, _ := utf8.DecodeLastRuneInString(s[:start]); isWordRune(prev) {
			return false
		}
	}
	last, _ := utf8.DecodeLastRuneInString(s[start:end])
	if isWordRune(last) && end < len(s) {
		if next, _ := utf8.DecodeRuneInString(s[end:]); isWordRune(next) {
			return false
		}
	}
	return true
}

func isWordRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r)
}
