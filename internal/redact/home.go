package redact

import (
	"regexp"
	"strings"
)

// KindUser is a local account name taken from a home-directory path. Claude Code's system
// prompt carries the working directory, so without this rule the username goes upstream on
// every request (plan/12-identity.md).
const KindUser = "USER"

var (
	// Unix: /Users/<name> (macOS) and /home/<name>.
	unixHomeRe = regexp.MustCompile(`(/Users/|/home/)(` + homeName + `)`)
	// Windows: C:\Users\<name>, C:/Users/<name>, and the JSON-escaped C:\\Users\\<name>.
	winHomeRe = regexp.MustCompile(`(?i)[a-z]:(?:\\{1,2}|/)users(?:\\{1,2}|/)` + winName)
	// WSL: /mnt/<drive>/Users/<name>, a Windows profile seen from Linux.
	wslHomeRe = regexp.MustCompile(`/mnt/[a-z]/Users/` + winName)
)

// homeName is one path segment: it starts with a letter, digit or underscore and doesn't end in a
// dot, so "/Users/.localized" and the period closing a sentence are left out. It stops at
// '/', '\', whitespace and quotes, which are not in the class.
const homeName = `[\pL\pN_](?:[\pL\pN._+~-]*[\pL\pN_+~-])?`

// winName is a Windows username, which may hold spaces ("John Smith"). Words joined by single
// spaces count as one name when a path separator closes them (group 1; the separator itself is
// outside the group). With no closing separator it is the first word alone (group 2), so prose
// like `C:\Users\John said` stays cheap to get wrong in the safe direction. Newlines, quotes and
// ':' are not in homeName, so a name never crosses them.
const winName = `(?:(` + homeName + `(?: ` + homeName + `)+)[\\/]|(` + homeName + `))`

// maxSpacedName caps a multi-word name in bytes; past it only the first word is taken.
const maxSpacedName = 64

// homeSkip are the shared and system profile directories, which identify nobody. Lowercase.
var homeSkip = map[string]bool{
	"shared": true, "public": true, "default": true, "all users": true, "default user": true,
}

func detectHomePaths(s string, add addFunc) {
	for _, l := range unixHomeRe.FindAllStringSubmatchIndex(s, -1) {
		// "/usr/home/x" and "example.com/home/x" are not home directories: the path must
		// start here, not continue a longer word.
		if l[0] > 0 && isPathWordByte(s[l[0]-1]) {
			continue
		}
		addHome(s, l[4], l[5], add)
	}
	for _, re := range []*regexp.Regexp{winHomeRe, wslHomeRe} {
		for _, l := range re.FindAllStringSubmatchIndex(s, -1) {
			if l[0] > 0 && isPathWordByte(s[l[0]-1]) {
				continue // "http:/users/x": the drive letter ends a longer word
			}
			start, end := l[4], l[5]
			if l[2] >= 0 {
				start, end = l[2], l[3]
				if end-start > maxSpacedName {
					end = start + strings.IndexByte(s[start:end], ' ')
				}
			}
			addHome(s, start, end, add)
		}
	}
}

func addHome(s string, start, end int, add addFunc) {
	name := strings.ToLower(s[start:end])
	if homeSkip[name] || name == "all" && hasPrefixFold(s[end:], " users") {
		return
	}
	add(start, end, KindUser, prioUser, "home-path")
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

func isPathWordByte(c byte) bool {
	return isAlnum(c) || c == '.' || c == '_' || c == '-' || c == '~' || c >= 0x80
}
