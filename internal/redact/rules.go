package redact

import (
	"math"
	"net/netip"
	"regexp"
	"strings"
)

var (
	privateKeyRe = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	knownTokenRes = []struct {
		rule string
		re   *regexp.Regexp
	}{
		{"known-token/anthropic", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
		{"known-token/openai", regexp.MustCompile(`\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}`)},
		{"known-token/github", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}`)},
		{"known-token/github-pat", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}`)},
		{"known-token/aws", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
		{"known-token/slack", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
		{"known-token/google", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`)},
		{"known-token/stripe", regexp.MustCompile(`\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}`)},
		{"known-token/nspy", regexp.MustCompile(`\bnspy_[A-Za-z0-9_-]{40,}`)},
		{"known-token/jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
	}
	bearerRe      = regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)`)
	urlPasswordRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@]+:([^\s/@]+)@`)
	keywordRe     = regexp.MustCompile(`(?i)(?:\b|_)(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth)\b["']?\s*[:=]\s*["']?([^\s"',;]{4,})`)
	varRefRe      = regexp.MustCompile(`^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Z_][A-Z0-9_]*)$`)
	entropyRe     = regexp.MustCompile(`[A-Za-z0-9+/=_-]{32,}`)
	emailRe       = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+([a-z]{2,63}))\b`)
	ipv4Re        = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)
	ipv6Re        = regexp.MustCompile(`(?i)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f.]*`)
	domainRe      = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
)

var allowIPs = map[string]bool{"127.0.0.1": true, "0.0.0.0": true, "::1": true}

type addFunc func(start, end int, kind string, prio int, rule string)

func detectPatterns(s string, d *Detector, add addFunc) {
	for _, l := range privateKeyRe.FindAllStringIndex(s, -1) {
		add(l[0], l[1], KindPrivateKey, prioPrivateKey, "private-key")
	}
	for _, kt := range knownTokenRes {
		for _, l := range kt.re.FindAllStringIndex(s, -1) {
			add(l[0], l[1], KindToken, prioKnownToken, kt.rule)
		}
	}
	for _, l := range bearerRe.FindAllStringSubmatchIndex(s, -1) {
		add(l[2], l[3], KindToken, prioKnownToken, "bearer")
	}
	for _, l := range urlPasswordRe.FindAllStringSubmatchIndex(s, -1) {
		add(l[2], l[3], KindPassword, prioURLPassword, "url-password")
	}
	for _, l := range keywordRe.FindAllStringSubmatchIndex(s, -1) {
		if varRefRe.MatchString(s[l[2]:l[3]]) {
			continue // ${DB_PASSWORD} or $TOKEN: a reference to a secret, not one (dotenv skips all `$` values)
		}
		add(l[2], l[3], KindPassword, prioKeyword, "keyword")
	}
	for _, l := range entropyRe.FindAllStringIndex(s, -1) {
		if highEntropy(s[l[0]:l[1]]) {
			add(l[0], l[1], KindToken, prioEntropy, "entropy")
		}
	}
	for _, l := range emailRe.FindAllStringSubmatchIndex(s, -1) {
		if tlds[strings.ToLower(s[l[4]:l[5]])] {
			add(l[0], l[1], KindEmail, prioEmail, "email")
		}
	}
	for _, l := range ipv4Re.FindAllStringIndex(s, -1) {
		if a, err := netip.ParseAddr(s[l[0]:l[1]]); err == nil && a.Is4() && !allowIPs[s[l[0]:l[1]]] {
			add(l[0], l[1], KindIPv4, prioIP, "ipv4")
		}
	}
	for _, l := range ipv6Re.FindAllStringIndex(s, -1) {
		if isIPv6(s, l[0], l[1]) {
			add(l[0], l[1], KindIPv6, prioIP, "ipv6")
		}
	}
	for _, l := range domainRe.FindAllStringIndex(s, -1) {
		if d.isDomain(s, l[0], l[1]) {
			add(l[0], l[1], KindDomain, prioDomain, "domain")
		}
	}
}

// highEntropy reports whether a long token-shaped run looks random rather than like a word,
// hex digest, UUID or file path.
func highEntropy(t string) bool {
	var up, lo, dig bool
	for i := 0; i < len(t); i++ {
		switch c := t[i]; {
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= '0' && c <= '9':
			dig = true
		}
	}
	if !up || !lo || !dig {
		return false
	}
	if strings.Contains(t, "/") {
		for _, seg := range strings.Split(t, "/") {
			if len(seg) >= 3 && strings.Trim(seg, "abcdefghijklmnopqrstuvwxyz") == "" {
				return false // path segment that's a plain lowercase word
			}
		}
	}
	return shannon(t) >= 4.0 && wordish(t) < 0.6
}

// wordish is the fraction of t inside runs of 3+ lowercase letters. CamelCase identifiers
// score >= 0.6; 99.9% of random base62 tokens (32-64 chars) score below it.
func wordish(t string) float64 {
	in, run := 0, 0
	for i := 0; i <= len(t); i++ {
		if i < len(t) && t[i] >= 'a' && t[i] <= 'z' {
			run++
			continue
		}
		if run >= 3 {
			in += run
		}
		run = 0
	}
	return float64(in) / float64(len(t))
}

func shannon(t string) float64 {
	var freq [256]int
	for i := 0; i < len(t); i++ {
		freq[t[i]]++
	}
	var h float64
	n := float64(len(t))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func isIPv6(s string, start, end int) bool {
	if start > 0 && isIPv6Edge(s[start-1]) || end < len(s) && isIPv6Edge(s[end]) {
		return false
	}
	t := s[start:end]
	a, err := netip.ParseAddr(t)
	if err != nil || !a.Is6() || allowIPs[t] {
		return false
	}
	groups, digit := 0, false
	for _, g := range strings.Split(t, ":") {
		if g != "" {
			groups++
		}
	}
	for i := 0; i < len(t); i++ {
		if t[i] >= '0' && t[i] <= '9' {
			digit = true
		}
	}
	return groups >= 3 || digit // rejects "::", "a::b", "dead::beef"
}

func isIPv6Edge(c byte) bool {
	return c == ':' || c == '.' || c == '_' || isAlnum(c)
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func (d *Detector) isDomain(s string, start, end int) bool {
	host := strings.ToLower(s[start:end])
	labels := strings.Split(host, ".")
	tld := labels[len(labels)-1]
	if !tlds[tld] {
		return false
	}
	if strings.HasSuffix(s[:start], "://") || start > 0 && s[start-1] == '@' {
		return true // URL or userinfo context: always a host
	}
	if start > 0 && s[start-1] == '.' {
		return false // tail of a longer identifier chain
	}
	if end < len(s) && s[end] == '(' {
		return false // method call: app.run(
	}
	if len(labels) == 2 && ambiguousTLDs[tld] {
		return false // README.md, user.name
	}
	orig := s[end-len(tld) : end]
	if orig != strings.ToLower(orig) && orig != strings.ToUpper(orig) {
		return false // mixed-case last label: errors.New, sync.Map
	}
	return true
}
