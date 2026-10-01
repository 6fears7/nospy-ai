// Package redact finds sensitive values in text and swaps them for reversible placeholders.
package redact

import (
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Kinds of sensitive value. The kind is embedded in the placeholder: [REDACTED_<KIND>_<n>].
const (
	KindPrivateKey = "PRIVATE_KEY"
	KindToken      = "TOKEN"
	KindPassword   = "PASSWORD"
	KindSecret     = "SECRET"
	KindEmail      = "EMAIL"
	KindIPv4       = "IPV4"
	KindIPv6       = "IPV6"
	KindDomain     = "DOMAIN"
	KindAddress    = "ADDRESS"
)

// Match is a span of s[Start:End] that should be redacted.
type Match struct {
	Start, End int
	Kind       string
	Rule       string // short name of the rule that found it, e.g. "email" or "known-token/github" (scan --explain, test messages)
}

// Priorities: lower wins when two candidates overlap.
const (
	prioPlaceholder = iota // existing placeholders; protected, never re-redacted
	prioPrivateKey
	prioKnownToken
	prioSecretDoc
	prioURLPassword
	prioKeyword
	prioEntropy
	prioEmail
	prioUser    // home-directory usernames (home.go)
	prioAddress // postal addresses (address.go): below email, above IPs and hosts
	prioIP
	prioDomain
	prioTerm    // custom terms: lowest, so they only apply where nothing else matched (see terms.go)
	prioLiteral // values already redacted elsewhere, matched literally (literals.go): below every rule
)

type candidate struct {
	Match
	prio int
}

// placeholderRe matches any placeholder the vault could have produced.
var placeholderRe = regexp.MustCompile(`\[REDACTED_[A-Z][A-Z0-9_]*_\d+\]`)

// Config configures a Detector.
type Config struct {
	// AllowHosts are never redacted (e.g. the upstream API hosts). Exact, case-insensitive.
	AllowHosts []string
	// Terms are custom terms and allow entries from a terms file; nil for none.
	Terms *Terms
}

// Detector finds sensitive spans. It is immutable once built and safe for concurrent use.
type Detector struct {
	allow map[string]bool // lowercased exact strings: AllowHosts plus the terms file's [ALLOW]
	terms *Terms
}

// NewDetector returns a Detector built from cfg.
func NewDetector(cfg Config) *Detector {
	d := &Detector{allow: map[string]bool{}, terms: cfg.Terms}
	for _, h := range cfg.AllowHosts {
		d.allow[strings.ToLower(h)] = true
	}
	if cfg.Terms != nil {
		for a := range cfg.Terms.allow {
			d.allow[a] = true
		}
	}
	return d
}

// Detect returns non-overlapping matches in s, sorted by Start.
func (d *Detector) Detect(s string) []Match {
	return d.finish(s, d.candidates(s), nil)
}

// candidates runs every rule over s and returns all matches before overlap resolution. It is
// the expensive half of Detect; a Redactor keeps the result between its two passes.
func (d *Detector) candidates(s string) []candidate {
	var cands []candidate
	add := func(start, end int, kind string, prio int, rule string) {
		if start < end {
			cands = append(cands, candidate{Match{start, end, kind, rule}, prio})
		}
	}
	for _, loc := range placeholderRe.FindAllStringIndex(s, -1) {
		add(loc[0], loc[1], "", prioPlaceholder, "placeholder")
	}
	detectPatterns(s, d, add)
	detectAddresses(s, add)
	detectHomePaths(s, add)
	detectStructured(s, add)
	d.terms.detect(s, add)
	return cands
}

// finish adds literal hits of lits to cands (which it leaves untouched), resolves overlaps
// and drops allowed spans.
func (d *Detector) finish(s string, cands []candidate, lits *literals) []Match {
	all := append([]candidate(nil), cands...)
	lits.find(s, func(start, end int, kind string, prio int, rule string) {
		all = append(all, candidate{Match{start, end, kind, rule}, prio})
	})
	return d.dropAllowed(s, resolve(all))
}

// secretKinds can never be allowed: an allow entry that happens to equal a real password or
// token must not let it through. Allowing is for identifiers (hosts, IPs, emails, terms).
var secretKinds = map[string]bool{KindPrivateKey: true, KindToken: true, KindPassword: true, KindSecret: true}

// dropAllowed removes matches whose text is an allow entry, except secret kinds. It runs after
// overlap resolution, so an allowed span still shields its text from lower-priority rules
// (a term "example" can't cut into an allowed docs.example.com).
func (d *Detector) dropAllowed(s string, ms []Match) []Match {
	if len(d.allow) == 0 {
		return ms
	}
	out := ms[:0]
	for _, m := range ms {
		if secretKinds[m.Kind] || !d.allow[strings.ToLower(s[m.Start:m.End])] {
			out = append(out, m)
		}
	}
	return out
}

// resolve accepts candidates greedily by priority (then longer first). A known secret
// replaces smaller matches wholly inside it, so an identifier rule cannot expose its tail.
// Wider matches and existing placeholders still win. Placeholder spans are not returned.
func resolve(cands []candidate) []Match {
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.prio != b.prio {
			return a.prio < b.prio
		}
		if la, lb := a.End-a.Start, b.End-b.Start; la != lb {
			return la > lb
		}
		return a.Start < b.Start
	})
	var acc []Match // sorted by Start, non-overlapping
	for _, c := range cands {
		i := sort.Search(len(acc), func(i int) bool { return acc[i].Start >= c.End })
		if i > 0 && acc[i-1].End > c.Start {
			first := sort.Search(i, func(j int) bool { return acc[j].End > c.Start })
			if c.Rule != ruleKnown || !secretKinds[c.Kind] || acc[first].Start < c.Start || acc[i-1].End > c.End ||
				slices.ContainsFunc(acc[first:i], func(m Match) bool { return m.Kind == "" }) {
				continue
			}
			acc = slices.Delete(acc, first, i)
			i = first
		}
		acc = append(acc, Match{})
		copy(acc[i+1:], acc[i:])
		acc[i] = c.Match
	}
	out := acc[:0]
	for _, m := range acc {
		if m.Kind != "" {
			out = append(out, m)
		}
	}
	return out
}
