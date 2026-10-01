package redact

import (
	_ "embed"
	"strings"
)

// tlds.txt is the IANA root zone list. Refresh with:
//
//	curl -s https://data.iana.org/TLD/tlds-alpha-by-domain.txt > internal/redact/tlds.txt
//
//go:embed tlds.txt
var tldsRaw string

var tlds = func() map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(tldsRaw, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			m[strings.ToLower(line)] = true
		}
	}
	// Private-use suffixes that aren't delegated but name internal hosts.
	for _, t := range []string{"internal", "local", "localdomain", "lan", "corp", "home"} {
		m[t] = true
	}
	return m
}()

// ambiguousTLDs are real TLDs that are far more often file extensions or code identifiers.
// A bare two-label name ending in one of these (README.md, user.name) is not treated as a domain.
var ambiguousTLDs = map[string]bool{
	"md": true, "sh": true, "py": true, "rs": true, "pl": true, "pm": true, "cc": true,
	"so": true, "tf": true, "ps": true, "in": true, "am": true, "ml": true, "mk": true,
	"zip": true, "mov": true, "pub": true, "fish": true,
	"id": true, "name": true, "email": true, "info": true, "app": true, "run": true,
	"store": true, "data": true, "map": true, "page": true, "link": true, "local": true,
	"new": true, "save": true, "show": true, "read": true, "play": true, "live": true,
}
