package redact

import (
	"fmt"
	"strings"
	"testing"
)

var gutterStyles = []struct{ name, format string }{
	{"cat-n", "%6d\t"},
	{"arrow", "%6d→"},
}

// withGutter numbers every line of s like `cat -n` does (format takes the line number). It also
// returns a map from offsets in s to offsets in the result, and the span of each gutter.
func withGutter(s, format string) (out string, pos func(int) int, gutters [][2]int) {
	var b strings.Builder
	var starts, outAt []int // line starts in s, and where their text starts in out
	at := 0
	for i, line := range strings.SplitAfter(s, "\n") {
		if line == "" {
			break
		}
		g := fmt.Sprintf(format, i+1)
		gutters = append(gutters, [2]int{b.Len(), b.Len() + len(g)})
		b.WriteString(g)
		starts = append(starts, at)
		outAt = append(outAt, b.Len())
		b.WriteString(line)
		at += len(line)
	}
	pos = func(p int) int {
		i := len(starts) - 1
		for starts[i] > p {
			i--
		}
		return outAt[i] + p - starts[i]
	}
	return b.String(), pos, gutters
}

// Every positive fixture still redacts the same values behind a line-number gutter, and the
// gutter itself is left alone unless a multi-line span has to swallow it.
func TestStructuredFixturesWithGutter(t *testing.T) {
	for _, st := range gutterStyles {
		for _, f := range structuredFixtures {
			t.Run(st.name+"/"+f.file, func(t *testing.T) {
				s := readFixture(t, f.file)
				w, pos, gutters := withGutter(s, st.format)
				ms := testDetector.Detect(w)
				if want := testDetector.Detect(s); len(ms) != len(want) {
					t.Errorf("%d matches with gutter, %d without: %s", len(ms), len(want), describe(w, ms))
				}
				for _, sec := range f.secrets {
					for _, at := range indexAll(s, sec) {
						if a, b := pos(at), pos(at+len(sec)-1)+1; !covered(ms, a, b) {
							t.Errorf("secret %q at %d not covered by a single match", sec, at)
						}
					}
				}
				for _, k := range f.keep {
					for _, at := range indexAll(s, k) {
						a, b := pos(at), pos(at+len(k)-1)+1
						for _, m := range ms {
							if m.Start < b && a < m.End {
								t.Errorf("keep %q overlaps %s(%q)", k, m.Kind, w[m.Start:m.End])
							}
						}
					}
				}
				for _, m := range ms {
					if strings.Contains(w[m.Start:m.End], "\n") {
						continue
					}
					for _, g := range gutters {
						if m.Start < g[1] && g[0] < m.End {
							t.Errorf("single-line match %s(%q) overlaps a gutter", m.Kind, w[m.Start:m.End])
						}
					}
				}
			})
		}
	}
}

func TestStructuredGatesWithGutter(t *testing.T) {
	for _, st := range gutterStyles {
		cm, _, _ := withGutter(configMapYAML, st.format)
		if ms := testDetector.Detect(cm); len(ms) > 0 {
			t.Errorf("%s ConfigMap: want no matches, got %s", st.name, describe(cm, ms))
		}
		for _, in := range noSecretDocs {
			w, _, _ := withGutter(in, st.format)
			for _, m := range testDetector.Detect(w) {
				if m.Kind == KindSecret {
					t.Errorf("%s %q: unexpected SECRET match %q", st.name, in, w[m.Start:m.End])
				}
			}
		}
	}
}

func TestStripGutters(t *testing.T) {
	in := "plain\n     2\tb: 1\n    10→c\n3 not a gutter\n"
	view, g := stripGutters(in)
	if want := "plain\nb: 1\nc\n3 not a gutter\n"; view != want {
		t.Fatalf("view = %q, want %q", view, want)
	}
	for i := 0; i < len(view); i++ {
		if view[i] != '\n' && in[g.orig(i)] != view[i] {
			t.Errorf("orig(%d) = %d: %q, want %q", i, g.orig(i), in[g.orig(i)], view[i])
		}
	}
	if same, g := stripGutters("a: 1\nb: 2\n"); same != "a: 1\nb: 2\n" || g != nil {
		t.Errorf("no gutter: got %q, %v", same, g)
	}
}

// A private key behind gutters is one span from BEGIN to END, so every body line is covered, and
// restoring it gives the gutters back with it.
func TestPrivateKeyWithGutter(t *testing.T) {
	pem := "-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEKEYDATA1\nFAKEKEYDATA2\n-----END OPENSSH PRIVATE KEY-----\n"
	for _, st := range gutterStyles {
		w, pos, _ := withGutter("key:\n"+pem, st.format)
		ms := testDetector.Detect(w)
		begin := strings.Index("key:\n"+pem, "-----BEGIN")
		end := strings.Index("key:\n"+pem, "-----END") + len("-----END OPENSSH PRIVATE KEY-----")
		if len(ms) != 1 || ms[0].Kind != KindPrivateKey || ms[0].Start != pos(begin) || ms[0].End != pos(end-1)+1 {
			t.Fatalf("%s: want one PRIVATE_KEY span over the whole key, got %s", st.name, describe(w, ms))
		}
		v := NewVault()
		red, _ := NewRedactor(testDetector, v).Redact(w)
		if strings.Contains(red, "FAKEKEYDATA") || v.Restore(red) != w {
			t.Errorf("%s: redacted %q, restored %q", st.name, red, v.Restore(red))
		}
	}
}
