package redact

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Vault maps real values to placeholders and back. It is scoped to one request: the proxy
// creates one per request, redacts the request with it and restores the response with it.
// Numbers follow first appearance, and the payload walker visits fields in a fixed order, so
// resent history gets the same placeholders every turn. Safe for concurrent use.
type Vault struct {
	mu       sync.Mutex
	byValue  map[string]string
	byPH     map[string]string
	counters map[string]int
}

func NewVault() *Vault {
	return &Vault{byValue: map[string]string{}, byPH: map[string]string{}, counters: map[string]int{}}
}

// Clone returns an independent copy that continues this vault's numbering (Responses chains).
func (v *Vault) Clone() *Vault {
	v.mu.Lock()
	defer v.mu.Unlock()
	c := NewVault()
	for k, val := range v.byValue {
		c.byValue[k] = val
	}
	for k, val := range v.byPH {
		c.byPH[k] = val
	}
	for k, n := range v.counters {
		c.counters[k] = n
	}
	return c
}

// Len returns the number of distinct values the vault holds.
func (v *Vault) Len() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.byValue)
}

// literals returns every value the vault holds, with its kind read back from the placeholder.
func (v *Vault) literals() *literals {
	v.mu.Lock()
	ks := make([]Known, 0, len(v.byValue))
	for val, ph := range v.byValue {
		kind := strings.TrimPrefix(ph, "[REDACTED_")
		kind = kind[:strings.LastIndexByte(kind, '_')]
		ks = append(ks, Known{kind, val})
	}
	v.mu.Unlock()
	return newLiterals(ks)
}

// Placeholder returns the placeholder for value, assigning [REDACTED_<kind>_<n>] on first sight.
func (v *Vault) Placeholder(kind, value string) string {
	v.mu.Lock()
	defer v.mu.Unlock()
	if ph, ok := v.byValue[value]; ok {
		return ph
	}
	v.counters[kind]++
	ph := fmt.Sprintf("[REDACTED_%s_%d]", kind, v.counters[kind])
	v.byValue[value] = ph
	v.byPH[ph] = value
	return ph
}

// Restore replaces every placeholder this vault issued with its real value. Unknown
// placeholders are left as they are.
func (v *Vault) Restore(s string) string {
	return v.restore(s, func(val string) string { return val })
}

// RestoreJSONString is Restore for text that sits inside a JSON string literal (streamed
// tool arguments): real values are JSON-escaped so the surrounding JSON stays valid.
func (v *Vault) RestoreJSONString(s string) string {
	return v.restore(s, jsonEscape)
}

func (v *Vault) restore(s string, enc func(string) string) string {
	if !strings.Contains(s, "[REDACTED_") {
		return s
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return placeholderRe.ReplaceAllStringFunc(s, func(ph string) string {
		if val, ok := v.byPH[ph]; ok {
			return enc(val)
		}
		return ph
	})
}

// jsonEscape returns s encoded as the body of a JSON string, without the surrounding quotes.
func jsonEscape(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s) // encoding a string cannot fail
	out := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	return string(out[1 : len(out)-1])
}

// Redactor replaces detected sensitive values with placeholders from one request's vault.
// Redacting a request takes two passes over its strings: Scan registers what the rules find, in
// visiting order (so numbers follow first appearance), and Rewrite then replaces those and
// every other literal occurrence of a value the vault holds. A context rule finds a password
// only next to its key; Rewrite also catches it where it comes back as prose. Not safe for
// concurrent use: it belongs to one request.
type Redactor struct {
	det       *Detector
	vault     *Vault
	known     *literals
	cache     map[string][]candidate // Scan's rule matches, so Rewrite doesn't rerun the rules
	vaultLits *literals
	vaultN    int               // vault size vaultLits was built for
	found     map[string]string // value -> kind, for kinds the known-values set keeps
}

// NewRedactor pairs a shared Detector with a request's vault.
func NewRedactor(det *Detector, v *Vault) *Redactor {
	return &Redactor{det: det, vault: v, cache: map[string][]candidate{}, found: map[string]string{}}
}

// WithKnown adds values an earlier request of the same client redacted. Scan finds them as
// plain text and registers them in this request's vault, which is how they get a placeholder
// here; they are never restored from the set. A nil set adds nothing. It returns r.
func (r *Redactor) WithKnown(ks *KnownSet) *Redactor {
	if ks != nil {
		r.known = ks.lits
	}
	return r
}

// Found returns the values this request redacted whose kind belongs in a known-values set.
func (r *Redactor) Found() []Known {
	out := make([]Known, 0, len(r.found))
	for val, kind := range r.found {
		out = append(out, Known{kind, val})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

// VaultLen returns the number of distinct values the request's vault holds.
func (r *Redactor) VaultLen() int { return r.vault.Len() }

func (r *Redactor) register(kind, value string) string {
	if r.det.Remembers(kind) {
		r.found[value] = kind
	}
	return r.vault.Placeholder(kind, value)
}

// Scan is pass 1: it registers every value the rules (and the known set) find in s.
func (r *Redactor) Scan(s string) {
	cands := r.det.candidates(s)
	r.cache[s] = cands
	for _, m := range r.det.finish(s, cands, r.known) {
		r.register(m.Kind, s[m.Start:m.End])
	}
}

// ScanField retains the key's secret context for a decoded tool argument. A key that
// fieldSecretKey accepts makes the whole decoded value a secret, including spaces and escapes.
func (r *Redactor) ScanField(key, value string) {
	if secretField(key, value) {
		r.register(KindSecret, value)
		return
	}
	r.Scan(value)
}

func secretField(key, value string) bool {
	return fieldSecretKey(key) && !skipSecretValue(value) && !placeholderRe.MatchString(value)
}

// RewriteField also handles short secrets that the literal matcher deliberately ignores.
func (r *Redactor) RewriteField(key, value string) (string, map[string]int) {
	if secretField(key, value) {
		return r.register(KindSecret, value), map[string]int{KindSecret: 1}
	}
	return r.Rewrite(value)
}

// Rewrite is pass 2: it returns s with every match and every vault value replaced, plus the
// number of replacements per kind. A string Scan never saw is detected here.
func (r *Redactor) Rewrite(s string) (string, map[string]int) {
	cands, ok := r.cache[s]
	if !ok {
		cands = r.det.candidates(s)
	}
	if n := r.vault.Len(); n != r.vaultN {
		r.vaultLits, r.vaultN = r.vault.literals(), n
	}
	ms := r.det.finish(s, cands, r.vaultLits)
	return substitute(s, ms, r.register)
}

// Redact redacts one string on its own, with the rules alone: no second pass, no known set.
// Unlike Scan and Rewrite it keeps no state, so it is safe for concurrent use.
func (r *Redactor) Redact(s string) (string, map[string]int) {
	ms := r.det.Detect(s)
	return substitute(s, ms, r.vault.Placeholder)
}

// substitute replaces each match in s with place(kind, value) and counts replacements per kind.
func substitute(s string, ms []Match, place func(kind, value string) string) (string, map[string]int) {
	if len(ms) == 0 {
		return s, nil
	}
	counts := map[string]int{}
	var b strings.Builder
	b.Grow(len(s))
	last := 0
	for _, m := range ms {
		b.WriteString(s[last:m.Start])
		b.WriteString(place(m.Kind, s[m.Start:m.End]))
		counts[m.Kind]++
		last = m.End
	}
	b.WriteString(s[last:])
	return b.String(), counts
}
