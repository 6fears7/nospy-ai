package redact

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestAddressPositive(t *testing.T) {
	cases := []struct{ name, in, want, rule string }{
		{"us street", "ship to 742 Evergreen Terrace, please", "742 Evergreen Terrace", "address/us-street"},
		{"us street, comma after", "at 1600 Pennsylvania Ave NW, Washington", "1600 Pennsylvania Ave NW", "address/us-street"},
		{"uk style street", "10 Downing Street, London", "10 Downing Street", "address/us-street"},
		{"abbreviated with period", "office: 500 W. Main St. Suite 200", "500 W. Main St. Suite 200", "address/us-street"},
		{"period ends the sentence", "Send it to 1 Infinite Loop.", "1 Infinite Loop", "address/us-street"},
		{"ordinal", "meet at 350 5th Ave.", "350 5th Ave", "address/us-street"},
		{"unit with #", "221B Baker Street, Apt #4B, rest", "221B Baker Street, Apt #4B", "address/us-street"},
		{"unit hash only", "99 Oak Lane #12\nnext", "99 Oak Lane #12", "address/us-street"},
		{"all caps", "MAIL TO 1600 PENNSYLVANIA AVE NW\n", "1600 PENNSYLVANIA AVE NW", "address/us-street"},
		{"hyphenated number", "at 84-12 Roosevelt Avenue,", "84-12 Roosevelt Avenue", "address/us-street"},
		{"street and city line, comma", "1 Hacker Way, Menlo Park, CA 94025", "1 Hacker Way, Menlo Park, CA 94025", "address/us-street"},
		{"street and city line, next line", "Acme Corp\n123 Main St\nSpringfield, IL 62701-1234\nUSA", "123 Main St\nSpringfield, IL 62701-1234", "address/us-street"},
		{"street and city line, space", "123 Main St Springfield, IL 62701", "123 Main St Springfield, IL 62701", "address/us-street"},
		{"street and uk postcode", "10 Downing Street, London SW1A 2AA.", "10 Downing Street, London SW1A 2AA", "address/us-street"},
		{"street and ca line", "24 Sussex Drive\nOttawa, ON K1A 0B1", "24 Sussex Drive\nOttawa, ON K1A 0B1", "address/us-street"},
		{"po box", "write to P.O. Box 1234 today", "P.O. Box 1234", "address/po-box"},
		{"po box no dots", "PO Box 77", "PO Box 77", "address/po-box"},
		{"po box lower", "mail po box 9", "po box 9", "address/po-box"},
		{"post office box", "Post Office Box 4567", "Post Office Box 4567", "address/po-box"},
		{"po box and city", "PO Box 12\nBoise, ID 83702", "PO Box 12\nBoise, ID 83702", "address/po-box"},
		{"city line", "Springfield, IL 62701", "Springfield, IL 62701", "address/us-city-line"},
		{"city line zip+4", "live in Salt Lake City, UT 84101-1234.", "Salt Lake City, UT 84101-1234", "address/us-city-line"},
		{"city line territory", "San Juan, PR 00901", "San Juan, PR 00901", "address/us-city-line"},
		{"uk postcode", "postcode SW1A 1AA", "SW1A 1AA", "address/uk-postcode"},
		{"uk short", "ours is M1 1AE", "M1 1AE", "address/uk-postcode"},
		{"uk no space", "EC1A1BB here", "EC1A1BB", "address/uk-postcode"},
		{"ca postcode", "Ottawa K1A 0B1", "K1A 0B1", "address/ca-postcode"},
		{"ca no space with province", "Toronto, ON M5V3L9", "M5V3L9", "address/ca-postcode"},
		{"ca province on previous line", "ON\nM5V3L9", "M5V3L9", "address/ca-postcode"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := testDetector.Detect(c.in)
			if !hasMatch(ms, c.in, KindAddress, c.want) {
				t.Fatalf("want ADDRESS %q in %q, got %s", c.want, c.in, describe(c.in, ms))
			}
			for _, m := range ms {
				if m.Kind == KindAddress && c.in[m.Start:m.End] == c.want && m.Rule != c.rule {
					t.Errorf("rule = %q, want %q", m.Rule, c.rule)
				}
			}
		})
	}
}

func TestAddressNegative(t *testing.T) {
	cases := []string{
		"3 way merge", "404 Not Found", "12 dr", "Route 66", "v1.2.3 Main", "HTTP/2 Way", "3 Way",
		"10 Downing", "see 3 Main Streets", "use 3 Foo Way to do it", "ship to 742 Evergreen Terrace please", "the 12 Elm St and more", "a 12,345 Main Street",
		"version 1.2 Main Street", "x1234 Main Street", "5 main street", "12 Main street",
		"port 12345", "zip 62701", "ST 12345", "Springfield, XX 62701", "Status OK 12345", "Springfield IL 62701",
		"Springfield, IL 6270", "Springfield, il 62701",
		"A1B2C3", "id A1B2C3D4", "sw1a 1aa", "k1a 0b1", "ZZ1 1AA", "SW1A 1CC", "SW1A 1AAX", "ab12cd", "W1W 1W1",
		"D1A 0B1", "K1A 0B1x", "file_K1A 0B1", "M5V3L9", "AB-SW1A 1AA",
		"PO Boxes 12", "Post Box 12", "P O Box", "spo box 12",
	}
	for _, in := range cases {
		for _, m := range testDetector.Detect(in) {
			if m.Kind == KindAddress {
				t.Errorf("%q: want no ADDRESS, got %s", in, describe(in, testDetector.Detect(in)))
				break
			}
		}
	}
}

func TestAddressPriority(t *testing.T) {
	// An email wins over an overlapping address; an address wins over the domain and IPs it touches.
	in := "to 10 Downing Street, London SW1A 2AA or x@corp.io via 10.0.0.12"
	ms := testDetector.Detect(in)
	for _, want := range []struct{ kind, text string }{
		{KindAddress, "10 Downing Street, London SW1A 2AA"}, {KindEmail, "x@corp.io"}, {KindIPv4, "10.0.0.12"},
	} {
		if !hasMatch(ms, in, want.kind, want.text) {
			t.Errorf("want %s %q, got %s", want.kind, want.text, describe(in, ms))
		}
	}
}

func TestAddressRoundTripAndIdempotent(t *testing.T) {
	in := "Deliver to Acme, 123 Main St\nSpringfield, IL 62701 or P.O. Box 5, and 10 Downing Street, London SW1A 2AA."
	v := NewVault()
	r := NewRedactor(testDetector, v)
	red, counts := r.Redact(in)
	if counts[KindAddress] != 3 {
		t.Fatalf("counts = %v in %q", counts, red)
	}
	if strings.Contains(red, "Main St") || strings.Contains(red, "Box 5") || strings.Contains(red, "Downing") {
		t.Fatalf("leaked: %q", red)
	}
	if !strings.Contains(red, "[REDACTED_ADDRESS_1]") {
		t.Fatalf("no ADDRESS placeholder: %q", red)
	}
	if again, c := r.Redact(red); again != red || len(c) != 0 {
		t.Errorf("second pass changed output: %q (%v)", again, c)
	}
	if got := v.Restore(red); got != in {
		t.Errorf("round trip mismatch:\nwant %q\ngot  %q", in, got)
	}
}

// Go's own source tree is ~8k files of code and prose with no postal addresses in it, so every
// match here is a false positive. It runs only the address rules (the other detectors would
// dominate the runtime and can't add ADDRESS matches; overlap resolution can only remove them),
// across all CPUs; under -race it scans every tenth file. Skipped with -short (it reads the whole tree).
func TestAddressFalsePositivesGoroot(t *testing.T) {
	if testing.Short() {
		t.Skip("reads all of GOROOT/src")
	}
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		t.Skipf("go env GOROOT: %v", err)
	}
	root := filepath.Join(strings.TrimSpace(string(out)), "src")
	var paths []string
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if raceEnabled { // the full tree takes ~18s under -race; a sample keeps the check in the race run
		sample := paths[:0:0]
		for i := 0; i < len(paths); i += 10 {
			sample = append(sample, paths[i])
		}
		paths = sample
	}
	var (
		mu   sync.Mutex
		hits []string
		wg   sync.WaitGroup
	)
	work := make(chan string)
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			for path := range work {
				b, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				s := string(b)
				detectAddresses(s, func(start, end int, kind string, prio int, rule string) {
					mu.Lock()
					hits = append(hits, fmt.Sprintf("%s:%d (%s)", path, 1+strings.Count(s[:start], "\n"), rule))
					mu.Unlock()
				})
			}
		})
	}
	for _, p := range paths {
		work <- p
	}
	close(work)
	wg.Wait()
	sort.Strings(hits)
	t.Logf("%d files, %d ADDRESS matches:\n%s", len(paths), len(hits), strings.Join(hits, "\n"))
	if len(hits) > 5 {
		t.Errorf("%d ADDRESS false positives (max 5)", len(hits))
	}
}
