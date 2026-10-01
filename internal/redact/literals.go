package redact

import "unicode/utf8"

// minLiteralLen is the shortest value matched literally: keywordRe's minimum value length.
// Shorter values are still redacted where a rule finds them, but searching for them as text
// would hit ordinary words.
const minLiteralLen = 4

// ruleKnown names the rule of a match found by the known-value matcher.
const ruleKnown = "known"

// Known is a value an earlier request redacted, with its kind. A client's set of them is used
// only to find the value again where no rule can (see Redactor.WithKnown).
type Known struct{ Kind, Value string }

// KnownSet is a set of Known values prepared for searching. Building one costs time in
// proportion to the values, so a client's set is built once and shared. Immutable once built.
type KnownSet struct{ lits *literals }

// NewKnownSet builds the matcher over ks.
func NewKnownSet(ks []Known) *KnownSet { return &KnownSet{newLiterals(ks)} }

// rememberedKinds are the kinds worth carrying across requests: the ones found by context
// (a keyword, a file format, a path), which come back as bare prose once the model's answer is
// restored. Context-free kinds are found again wherever they appear. Terms-file sections are
// added by Detector.Remembers.
var rememberedKinds = map[string]bool{
	KindPassword: true, KindSecret: true, KindToken: true, KindPrivateKey: true,
	KindUser: true, KindAddress: true,
}

// Remembers reports whether values of kind belong in a client's known-values set.
func (d *Detector) Remembers(kind string) bool {
	return rememberedKinds[kind] || (d.terms != nil && d.terms.sections[kind])
}

// literals is a set of values searched for as plain text in one pass over the input: an
// Aho-Corasick automaton, so the cost doesn't grow with the number of values (a request can
// carry a few hundred, a client's known set up to a few thousand). Immutable once built. A nil
// *literals finds nothing.
type literals struct {
	vals  []literal
	nodes []acNode
	root  [256]int32 // transitions out of the root; 0 stays at the root
}

type literal struct{ kind, value string }

type acEdge struct {
	b  byte
	to int32
}

type acNode struct {
	edges []acEdge
	fail  int32 // longest proper suffix of this node's text that is also in the trie
	val   int32 // 1 + index in vals of the value ending here; 0 for none
	out   int32 // nearest node along fail links with val != 0; 0 for none
}

// newLiterals builds the automaton over the values long enough to search for.
func newLiterals(ks []Known) *literals {
	l := &literals{nodes: make([]acNode, 1)}
	for _, k := range ks {
		if utf8.RuneCountInString(k.Value) < minLiteralLen {
			continue
		}
		l.vals = append(l.vals, literal{k.Kind, k.Value})
		n := int32(0)
		for i := 0; i < len(k.Value); i++ {
			next, ok := l.child(n, k.Value[i])
			if !ok {
				next = int32(len(l.nodes)) //nolint:gosec // node count is bounded by total term bytes
				l.nodes = append(l.nodes, acNode{})
				l.nodes[n].edges = append(l.nodes[n].edges, acEdge{k.Value[i], next})
				if n == 0 {
					l.root[k.Value[i]] = next
				}
			}
			n = next
		}
		l.nodes[n].val = int32(len(l.vals)) //nolint:gosec // term count is far below MaxInt32
	}
	if len(l.vals) == 0 {
		return nil
	}
	// Breadth first, so every node's fail link points at a node that is already finished.
	queue := make([]int32, 0, len(l.nodes))
	for _, e := range l.nodes[0].edges {
		queue = append(queue, e.to)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, e := range l.nodes[n].edges {
			f := l.nodes[n].fail
			for {
				if to, ok := l.child(f, e.b); ok {
					f = to
					break
				}
				if f == 0 {
					break
				}
				f = l.nodes[f].fail
			}
			l.nodes[e.to].fail = f
			if l.nodes[f].val != 0 {
				l.nodes[e.to].out = f
			} else {
				l.nodes[e.to].out = l.nodes[f].out
			}
			queue = append(queue, e.to)
		}
	}
	return l
}

func (l *literals) child(n int32, b byte) (int32, bool) {
	if n == 0 {
		to := l.root[b]
		return to, to != 0
	}
	for _, e := range l.nodes[n].edges {
		if e.b == b {
			return e.to, true
		}
	}
	return 0, false
}

// find reports every whole-word occurrence of each value in s through add, at the lowest
// priority: a rule's wider span wins an overlap; a known secret covers smaller matches inside
// it. Of two values overlapping each other the longer wins. Whole-word is terms.go's rule:
// the boundary applies only at an edge that is itself a word character, so "admin" doesn't
// hit "administrator" while a value ending in punctuation matches as is.
func (l *literals) find(s string, add addFunc) {
	if l == nil {
		return
	}
	var n int32
	for i := 0; i < len(s); i++ {
		c := s[i]
		for {
			if to, ok := l.child(n, c); ok {
				n = to
				break
			}
			if n == 0 {
				break
			}
			n = l.nodes[n].fail
		}
		for m := n; m != 0; {
			if v := l.nodes[m].val; v != 0 {
				lit := l.vals[v-1]
				if start := i + 1 - len(lit.value); wholeWord(s, start, i+1) {
					add(start, i+1, lit.kind, prioLiteral, ruleKnown)
				}
			}
			m = l.nodes[m].out
		}
	}
}
