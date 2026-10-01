package redact

import (
	"regexp"
	"sort"
	"strings"
)

// Structured secret documents: K8s Secrets, kubeconfig, docker config, .env and tfstate.
// Each rule is gated on a document signature and redacts values only, never keys.

var (
	yamlDocSepRe     = regexp.MustCompile(`(?m)^---[ \t]*\r?$`)
	yamlKindSecretRe = regexp.MustCompile(`(?m)^kind:[ \t]*["']?Secret["']?[ \t]*\r?$`)
	yamlDataKeyRe    = regexp.MustCompile(`(?m)^(?:data|stringData):[ \t]*\r?$`)
	blockIndicatorRe = regexp.MustCompile(`^[|>][+-]?[0-9]?$`)

	// Optional backslashes let these also match the escaped copy kubectl stores in the
	// last-applied-configuration annotation.
	jsonKindSecretRe = regexp.MustCompile(`\\?"kind\\?"\s*:\s*\\?"Secret\\?"`)
	jsonDataObjRe    = regexp.MustCompile(`\\?"(?:data|stringData)\\?"\s*:\s*\{([^}]*)\}`)
	jsonPairRe       = regexp.MustCompile(`\\?"((?:[^"\\]|\\[^"])*)\\?"\s*:\s*\\?"((?:[^"\\]|\\[^"])*)\\?"`)

	kubeClustersRe  = regexp.MustCompile(`(?m)^clusters:`)
	kubeContextsRe  = regexp.MustCompile(`(?m)^contexts:`)
	kubeDataKeyRe   = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?(?:client-certificate-data|client-key-data|certificate-authority-data):[ \t]*([^\r\n]*)`)
	kubeShortKeyRe  = regexp.MustCompile(`(?m)^[ \t]*(?:-[ \t]+)?(?:token|password|username|access-token|refresh-token|id-token|client-secret):[ \t]*([^\r\n]*)`)
	dockerAuthsRe   = regexp.MustCompile(`"auths"\s*:`)
	dockerSecretRe  = regexp.MustCompile(`"(?:auth|identitytoken|registrytoken|password)"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	tfVersionRe     = regexp.MustCompile(`"terraform_version"\s*:`)
	tfSerialRe      = regexp.MustCompile(`"serial"\s*:`)
	tfLineageRe     = regexp.MustCompile(`"lineage"\s*:`)
	jsonStrPairRe   = regexp.MustCompile(`"([A-Za-z0-9_]+)"\s*:\s*"((?:[^"\\]|\\.)*)"`)
	dotenvLineRe    = regexp.MustCompile(`(?m)^[ \t]*(?:export[ \t]+)?([A-Za-z][A-Za-z0-9_.-]*)[ \t]*=[ \t]*("[^"\n]*"|'[^'\n]*'|[^\s#]*)`)
	dotenvSkipValRe = regexp.MustCompile(`(?i)^(?:true|false|yes|no|null|0|1)$`)
)

var (
	dotenvSuffixes = []string{"KEY", "SECRET", "TOKEN", "PASSWORD", "PASSWD", "PWD", "CREDENTIAL", "CREDENTIALS", "AUTH", "DSN", "CONNECTION_STRING"}
	// fieldSecretSuffixes are normalized (lowercase, no _ - .) suffixes of JSON tool-argument keys.
	// Narrower than dotenv's: no key, auth or pwd, which are ordinary arguments there.
	fieldSecretSuffixes = []string{"password", "passwd", "secret", "token", "apikey", "accesskey", "secretkey", "privatekey", "credential", "credentials", "connectionstring"}
	tfSecretKeys        = []string{
		"password", "secret", "secret_key", "access_key", "secret_access_key", "private_key",
		"private_key_pem", "private_key_openssh", "token", "client_secret", "connection_string",
		"credentials", "primary_key", "secondary_key", "secret_string", "secret_binary",
	}
)

func detectStructured(s string, add addFunc) {
	view, g := stripGutters(s)
	secret := func(rule string) func(int, int) {
		return func(start, end int) {
			if g != nil {
				start, end = g.orig(start), g.orig(end-1)+1
			}
			add(start, end, KindSecret, prioSecretDoc, rule)
		}
	}
	k8sSecretYAML(view, secret("k8s-secret-yaml"))
	k8sSecretJSON(view, secret("k8s-secret-json"))
	kubeconfig(view, secret("kubeconfig"))
	dockerConfig(view, secret("docker-config"))
	dotenv(view, secret("dotenv"))
	tfstate(view, secret("tfstate"))
}

// gutterRe is the line-number prefix of `cat -n` / `nl` ("     1\t") and of an agent's file view ("     1→").
var gutterRe = regexp.MustCompile(`(?m)^[ \t]*\d+(?:\t|→)`)

// gutters maps offsets in a gutter-stripped view back to the original text. view[viewAt[i]:]
// starts line i; origAt[i] is the original offset of that same character.
type gutters struct{ viewAt, origAt []int }

// stripGutters returns s without line-number gutters, plus the map back to s. A text with no
// gutter is returned as is with a nil map.
func stripGutters(s string) (string, *gutters) {
	locs := gutterRe.FindAllStringIndex(s, -1)
	if locs == nil {
		return s, nil
	}
	var b strings.Builder
	g := &gutters{}
	pos := 0 // in s
	for _, l := range locs {
		b.WriteString(s[pos:l[0]])
		pos = l[1]
		g.viewAt = append(g.viewAt, b.Len())
		g.origAt = append(g.origAt, l[1])
	}
	b.WriteString(s[pos:])
	return b.String(), g
}

// orig maps a view offset to the original text. Lines without a gutter are the identity, so
// only the gutter lines are recorded; the offset shift carries over from the last one before p.
func (g *gutters) orig(p int) int {
	i := sort.Search(len(g.viewAt), func(i int) bool { return g.viewAt[i] > p })
	if i == 0 {
		return p
	}
	return g.origAt[i-1] + (p - g.viewAt[i-1])
}

func k8sSecretYAML(s string, secret func(int, int)) {
	start := 0
	bounds := append(yamlDocSepRe.FindAllStringIndex(s, -1), []int{len(s), len(s)})
	for _, b := range bounds {
		doc := s[start:b[0]]
		if yamlKindSecretRe.MatchString(doc) {
			for _, l := range yamlDataKeyRe.FindAllStringIndex(doc, -1) {
				yamlMapValues(s, start+l[1], start+len(doc), secret)
			}
		}
		start = b[1]
	}
}

// yamlMapValues redacts every value of the block mapping that begins at pos (just after
// "data:"), stopping at the first line that is back at column 0.
func yamlMapValues(s string, pos, end int, secret func(int, int)) {
	child := -1
	lines := splitLines(s, pos, end)
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		ind, blank := indentOf(s[ln[0]:ln[1]])
		if blank {
			continue
		}
		if ind == 0 {
			return
		}
		if child < 0 {
			child = ind
		}
		if ind != child {
			continue
		}
		rest := s[ln[0]+ind : ln[1]]
		colon := strings.Index(rest, ":")
		if colon < 0 {
			continue
		}
		vs, ve := trimSpan(s, ln[0]+ind+colon+1, ln[1])
		if vs < ve && !blockIndicatorRe.MatchString(s[vs:ve]) {
			vs, ve = unquote(s, vs, ve)
			secret(vs, ve)
			continue
		}
		// Block scalar (or nested map): the value is every following deeper-indented line.
		first, last := -1, -1
		for i+1 < len(lines) {
			nl := lines[i+1]
			nind, nblank := indentOf(s[nl[0]:nl[1]])
			if !nblank && nind <= child {
				break
			}
			i++
			if !nblank {
				if first < 0 {
					first = nl[0] + nind
				}
				_, last = trimSpan(s, nl[0], nl[1])
			}
		}
		if first >= 0 {
			secret(first, last)
		}
	}
}

func k8sSecretJSON(s string, secret func(int, int)) {
	if !jsonKindSecretRe.MatchString(s) {
		return
	}
	for _, obj := range jsonDataObjRe.FindAllStringSubmatchIndex(s, -1) {
		inner := s[obj[2]:obj[3]]
		for _, p := range jsonPairRe.FindAllStringSubmatchIndex(inner, -1) {
			secret(obj[2]+p[4], obj[2]+p[5])
		}
	}
}

func kubeconfig(s string, secret func(int, int)) {
	yamlValues := func(re *regexp.Regexp) {
		for _, l := range re.FindAllStringSubmatchIndex(s, -1) {
			vs, ve := trimSpan(s, l[2], l[3])
			vs, ve = unquote(s, vs, ve)
			secret(vs, ve)
		}
	}
	yamlValues(kubeDataKeyRe) // unambiguous key names, no gate needed
	if kubeClustersRe.MatchString(s) && kubeContextsRe.MatchString(s) {
		yamlValues(kubeShortKeyRe)
	}
}

func dockerConfig(s string, secret func(int, int)) {
	if !dockerAuthsRe.MatchString(s) {
		return
	}
	for _, l := range dockerSecretRe.FindAllStringSubmatchIndex(s, -1) {
		secret(l[2], l[3])
	}
}

func tfstate(s string, secret func(int, int)) {
	if !tfVersionRe.MatchString(s) && (!tfSerialRe.MatchString(s) || !tfLineageRe.MatchString(s)) {
		return
	}
	for _, l := range jsonStrPairRe.FindAllStringSubmatchIndex(s, -1) {
		key := strings.ToLower(s[l[2]:l[3]])
		for _, k := range tfSecretKeys {
			if strings.HasSuffix(key, k) {
				secret(l[4], l[5])
				break
			}
		}
	}
}

func dotenv(s string, secret func(int, int)) {
	for _, l := range dotenvLineRe.FindAllStringSubmatchIndex(s, -1) {
		if !dotenvSecretKey(s[l[2]:l[3]]) {
			continue
		}
		vs, ve := unquote(s, l[4], l[5])
		v := s[vs:ve]
		if skipSecretValue(v) {
			continue
		}
		secret(vs, ve)
	}
}

// skipSecretValue reports whether v is empty, a variable reference, or a flag-like word.
func skipSecretValue(v string) bool {
	return v == "" || v[0] == '$' || v[0] == '=' || dotenvSkipValRe.MatchString(v)
}

// fieldSecretKey reports whether a JSON argument key ends with a secret suffix, ignoring case
// and _ - . separators: apiKey, client_secret and DB_PASSWORD match; key, auth and author don't.
func fieldSecretKey(key string) bool {
	k := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(key))
	for _, suf := range fieldSecretSuffixes {
		if strings.HasSuffix(k, suf) {
			return true
		}
	}
	return false
}

// dotenvSecretKey reports whether key is, or ends with a separator plus, a secret suffix.
// The separator requirement keeps MONKEY and AUTHOR out.
func dotenvSecretKey(key string) bool {
	k := strings.ToUpper(key)
	for _, suf := range dotenvSuffixes {
		if k == suf {
			return true
		}
		for _, sep := range "_-." {
			if strings.HasSuffix(k, string(sep)+suf) {
				return true
			}
		}
	}
	return false
}

// splitLines returns [start,end) of each line in s[pos:end], without the newline.
func splitLines(s string, pos, end int) [][2]int {
	var out [][2]int
	for pos < end {
		nl := strings.IndexByte(s[pos:end], '\n')
		if nl < 0 {
			out = append(out, [2]int{pos, end})
			break
		}
		out = append(out, [2]int{pos, pos + nl})
		pos += nl + 1
	}
	return out
}

func indentOf(line string) (n int, blank bool) {
	for n < len(line) && line[n] == ' ' {
		n++
	}
	return n, strings.TrimSpace(line[n:]) == ""
}

// trimSpan narrows [start,end) to exclude surrounding spaces, tabs and CR.
func trimSpan(s string, start, end int) (int, int) {
	for start < end && strings.IndexByte(" \t\r", s[start]) >= 0 {
		start++
	}
	for end > start && strings.IndexByte(" \t\r", s[end-1]) >= 0 {
		end--
	}
	return start, end
}

// unquote narrows [start,end) to exclude one pair of matching surrounding quotes.
func unquote(s string, start, end int) (int, int) {
	if end-start >= 2 && (s[start] == '"' || s[start] == '\'') && s[end-1] == s[start] {
		return start + 1, end - 1
	}
	return start, end
}
