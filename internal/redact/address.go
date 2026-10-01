package redact

import (
	"regexp"
	"strings"
)

// Postal addresses (plan/15-postal-addresses.md). High-precision pattern families, not address
// parsing: US street lines, PO boxes, US city lines, UK postcodes and Canadian postal codes.
// Recall is partial by design; other formats belong in the terms file.

func wordSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(s) {
		m[w] = true
	}
	return m
}

// USPS state and territory codes.
var usStates = wordSet(`AL AK AZ AR CA CO CT DE FL GA HI ID IL IN IA KS KY LA ME MD MA MI MN MS MO MT NE NV NH NJ NM NY NC ND
	OH OK OR PA RI SC SD TN TX UT VT VA WA WV WI WY DC PR GU VI AS MP`)

// UK postcode areas (the letters before the first digit), plus the Crown dependencies and BFPO.
var ukAreas = wordSet(`AB AL B BA BB BD BF BH BL BN BR BS BT CA CB CF CH CM CO CR CT CV CW DA DD DE DG DH DL DN DT DY E EC EH EN EX
	FK FY G GL GU GY HA HD HG HP HR HS HU HX IG IM IP IV JE KA KT KW KY L LA LD LE LL LN LS LU M ME MK ML N NE NG NN NP NR NW OL OX
	PA PE PH PL PO PR RG RH RM S SA SE SG SK SL SM SN SO SP SR SS ST SW SY TA TD TF TN TQ TR TS TW UB W WA WC WD WF WN WR WS WV YO ZE`)

// Street suffixes from the USPS list. Matched capitalized or all caps, never lowercase.
var streetSuffixes = strings.Fields(`street st avenue ave av road rd boulevard blvd lane ln drive dr court ct place pl way
	terrace ter circle cir parkway pkwy highway hwy square sq trail trl loop alley aly plaza plz crescent cres
	expressway expy freeway fwy turnpike tpke pike`)

const (
	// One name word: capitalized ("Main", "W.", "O'Brien") or an ordinal ("5th").
	nameWord = `(?:[A-Z][A-Za-z'’-]*\.?|\d{1,3}(?:st|nd|rd|th|ST|ND|RD|TH))`
	unitID   = `(?:\d[A-Za-z0-9-]{0,5}|[A-Z]\b)`
	unit     = `(?:,?[ \t]+(?i:apartment|apt|suite|ste|unit|bldg|building|floor|fl|room|rm)\b\.?[ \t]*#?[ \t]*|,?[ \t]*#[ \t]*)` + unitID
	cityWord = `[A-Z][A-Za-z.'’-]*`
	city     = cityWord + `(?:[ \t]+` + cityWord + `){0,2}` // 1-3 capitalized words
	ukPC     = `([A-Z]{1,2})\d[A-Z\d]?[ ]?\d[A-Z]{2}`
	caPC     = `[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]([ \t]?)\d[ABCEGHJ-NPRSTV-Z]\d` // Canada Post never uses D F I O Q U; W, Z not first
)

var (
	streetRe = regexp.MustCompile(`(\d{1,6}(?:[A-Za-z]|-\d{1,6})?)[ \t]+((?:` + nameWord + `[ \t]+){1,4})(?:` + suffixAlt() + `)(?:\.|\b)` +
		`(?:[ \t]+(?:NE|NW|SE|SW|N|S|E|W)(?:\.|\b))?(?:` + unit + `)?`)
	poBoxRe = regexp.MustCompile(`(?i)\b(?:P\.?[ \t]?O\.?[ \t]?|Post[ \t]+Office[ \t]+)Box[ \t]+\d{1,6}\b`)
	// Anchored variants serve as the second line of a multi-line address (see addrTail).
	usCityBody = `\b(` + city + `),[ \t]+([A-Z]{2})[ \t]+\d{5}(?:-\d{4})?\b` // the comma is required: "Status OK 12345" is not a city line
	usCityRe   = regexp.MustCompile(usCityBody)
	usCityAnch = regexp.MustCompile(`^` + usCityBody)
	ukBody     = `\b` + ukPC + `\b`
	ukRe       = regexp.MustCompile(ukBody)
	ukAnch     = regexp.MustCompile(`^(?:` + city + `[ \t]*,?[ \t]*(?:\r?\n[ \t]*)?)?` + ukBody)
	caBody     = `\b` + caPC + `\b`
	caRe       = regexp.MustCompile(caBody)
	caAnch     = regexp.MustCompile(`^(?:` + city + `,?[ \t]+)?(?:(?:AB|BC|MB|NB|NL|NS|NT|NU|ON|PE|QC|SK|YT)[ \t]+)?` + caBody)
	provinceRe = regexp.MustCompile(`\b(?:AB|BC|MB|NB|NL|NS|NT|NU|ON|PE|QC|SK|YT)\b`)
	tailSepRe  = regexp.MustCompile(`^[ \t]*,?[ \t]*(?:\r?\n[ \t]*)?`)
)

// suffixAlt is the suffix alternation in both accepted spellings: "Street" and "STREET".
func suffixAlt() string {
	var alts []string
	for _, w := range streetSuffixes {
		alts = append(alts, strings.ToUpper(w[:1])+w[1:], strings.ToUpper(w))
	}
	return strings.Join(alts, "|")
}

func detectAddresses(s string, add addFunc) {
	detectStreets(s, add)
	for _, l := range poBoxRe.FindAllStringIndex(s, -1) {
		if !addrEdgeBefore(s, l[0]) {
			continue
		}
		end := l[1]
		if t, ok := addrTail(s, end); ok {
			end = t
		}
		add(l[0], end, KindAddress, prioAddress, "address/po-box")
	}
	for _, l := range usCityRe.FindAllStringSubmatchIndex(s, -1) {
		if usStates[s[l[4]:l[5]]] && addrEdgeBefore(s, l[0]) {
			add(l[0], l[1], KindAddress, prioAddress, "address/us-city-line")
		}
	}
	for _, l := range ukRe.FindAllStringSubmatchIndex(s, -1) {
		if ukAreas[s[l[2]:l[3]]] && ukInwardOK(s, l[1]) && addrEdgeBefore(s, l[0]) && addrEdgeAfter(s, l[1]) {
			add(l[0], l[1], KindAddress, prioAddress, "address/uk-postcode")
		}
	}
	for _, l := range caRe.FindAllStringSubmatchIndex(s, -1) {
		spaced := l[3] > l[2]
		if (spaced || provinceNear(s, l[0])) && addrEdgeBefore(s, l[0]) && addrEdgeAfter(s, l[1]) {
			add(l[0], l[1], KindAddress, prioAddress, "address/ca-postcode")
		}
	}
}

// detectStreets finds street lines. The regex has no lookahead, so the terminator rule is
// checked here: a street line must end the line, sit before punctuation, or be followed by a
// city line / postcode. "3 Main Way to do it" is prose, not an address.
func detectStreets(s string, add addFunc) {
	for pos := 0; pos < len(s); {
		loc := streetRe.FindStringIndex(s[pos:])
		if loc == nil {
			return
		}
		start, end := pos+loc[0], pos+loc[1]
		if !houseNumberEdge(s, start) {
			pos = start + 1
			continue
		}
		if s[end-1] == '.' {
			end-- // sentence period, not part of the address
		}
		if t, ok := addrTail(s, end); ok {
			end = t
		} else if !streetTerminated(s, end) {
			pos = start + 1
			continue
		}
		add(start, end, KindAddress, prioAddress, "address/us-street")
		pos = end
	}
}

// houseNumberEdge rejects numbers that are the tail of something else: v1.2 Main, a1234, 12,345.
func houseNumberEdge(s string, i int) bool {
	if !addrEdgeBefore(s, i) {
		return false
	}
	return i < 2 || s[i-1] != ',' || s[i-2] < '0' || s[i-2] > '9'
}

func streetTerminated(s string, i int) bool {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i == len(s) || strings.IndexByte("\r\n,.;)]}\"'`<!?|", s[i]) >= 0
}

// addrTail reports the end of a city line or postcode that directly follows a street line or PO
// box at s[at:] (after a comma, a space or a line break), so the whole address is one span.
func addrTail(s string, at int) (int, bool) {
	sep := tailSepRe.FindString(s[at:])
	if sep == "" {
		return 0, false
	}
	rest, base := s[at+len(sep):], at+len(sep)
	if l := usCityAnch.FindStringSubmatchIndex(rest); l != nil && usStates[rest[l[4]:l[5]]] {
		return base + l[1], true
	}
	if l := ukAnch.FindStringSubmatchIndex(rest); l != nil && ukAreas[rest[l[2]:l[3]]] && ukInwardOK(s, base+l[1]) && addrEdgeAfter(s, base+l[1]) {
		return base + l[1], true
	}
	if l := caAnch.FindStringIndex(rest); l != nil && addrEdgeAfter(s, base+l[1]) {
		return base + l[1], true
	}
	return 0, false
}

// ukInwardOK checks the last two letters of a postcode ending at s[:end]: Royal Mail never uses C I K M O V there.
func ukInwardOK(s string, end int) bool {
	return !strings.ContainsAny(s[end-2:end], "CIKMOV")
}

// provinceNear reports whether a province code sits on the same line as i or the one before.
func provinceNear(s string, i int) bool {
	from := strings.LastIndexByte(s[:i], '\n')
	if from > 0 {
		from = strings.LastIndexByte(s[:from], '\n')
	}
	return provinceRe.MatchString(s[from+1 : i])
}

// addrEdgeBefore rejects a match glued to a longer identifier, path or number.
func addrEdgeBefore(s string, i int) bool {
	return i == 0 || (!isAlnum(s[i-1]) && strings.IndexByte("_-./\\@#$%+=:", s[i-1]) < 0)
}

func addrEdgeAfter(s string, i int) bool {
	if i >= len(s) {
		return true
	}
	c := s[i]
	if isAlnum(c) || c == '_' || c == '-' || c == '@' || c == '/' {
		return false
	}
	return c != '.' || i+1 >= len(s) || !isAlnum(s[i+1])
}
