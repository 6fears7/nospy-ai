package redact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var structuredFixtures = []struct {
	file          string
	secrets, keep []string
}{
	{
		file:    "k8s_secret.yaml",
		secrets: []string{"cGFzc3dvcmQxMjM=", "YWRtaW4=", "hunter2", "host: db\n    db_pass: hunter2", "us-east-1"},
		keep: []string{"password:", "username:", "config.yaml: |", "kind: Secret", "name: db-creds", "region:",
			"immutable: true", "LOG_LEVEL: debug", "DB_HOST_ALIAS: primary", "greeting: aGVsbG8="},
	},
	{
		file:    "k8s_secret.json",
		secrets: []string{"cGFzc3dvcmQxMjM=", "YWRtaW4=", "tok-abc-123"},
		keep:    []string{`"kind": "Secret"`, "password", "username", "api-token", `"name": "db-creds"`},
	},
	{
		file: "kubeconfig.yaml",
		secrets: []string{
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkZBS0UtQ0EtRk9SLVRFU1RTCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K",
			"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCkZBS0UtQ0xJRU5ULUNFUlQKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=",
			"LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpGQUtFLUNMSUVOVC1LRVkKLS0tLS1FTkQgUlNBIFBSSVZBVEUgS0VZLS0tLS0K",
			"t0k3n-for-ci", "ci-user", "s3cret-pw", "10.0.0.1",
		},
		keep: []string{"apiVersion: v1", "kind: Config", "current-context: dev-admin@dev-cluster", "name: dev-cluster",
			"cluster: dev-cluster", "name: dev-admin", "name: ci-bot", "token:", "username:", "password:"},
	},
	{
		file:    "docker_config.json",
		secrets: []string{"dXNlcjpwYXNz", "idt-fake-0123456789", "ghcr.io", "registry.example.com"},
		keep:    []string{`"auths"`, `"auth"`, `"identitytoken"`, `"credsStore": "desktop"`},
	},
	{
		file: "dotenv",
		secrets: []string{"hunter2", "abc", "sk_test_x", "t0k", "https://abc123@o0.ingest.example.com/1",
			"AKIAFAKE:fakesecret", "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE"},
		keep: []string{"# app settings", "PORT=8080", "DEBUG=true", "MONKEY=banana", "AUTHOR=me", "DB_PASSWORD=",
			`API_KEY="`, "\"\nSTRIPE_SECRET='", "'\nAUTH_TOKEN=", "${DB_PASSWORD}", "EMPTY_TOKEN="},
	},
	{
		file: "terraform.tfstate",
		secrets: []string{"Sup3rS3cretDbPass", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "AKIAIOSFODNN7EXAMPLE",
			`-----BEGIN RSA PRIVATE KEY-----\nFAKEFAKEFAKE\n-----END RSA PRIVATE KEY-----`},
		keep: []string{`"terraform_version": "1.9.5"`, `"instance_class": "db.t3.micro"`, `"engine": "postgres"`,
			`"value": "password"`, `"type": "aws_db_instance"`, `"name": "main"`, `"user": "ci"`},
	},
}

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// indexAll returns the start of every occurrence of sub in s.
func indexAll(s, sub string) []int {
	var out []int
	for i := 0; ; {
		j := strings.Index(s[i:], sub)
		if j < 0 {
			return out
		}
		out = append(out, i+j)
		i += j + 1
	}
}

func TestStructuredFixtures(t *testing.T) {
	for _, f := range structuredFixtures {
		t.Run(f.file, func(t *testing.T) {
			s := readFixture(t, f.file)
			ms := testDetector.Detect(s)
			for _, sec := range f.secrets {
				occ := indexAll(s, sec)
				if len(occ) == 0 {
					t.Fatalf("fixture has no %q", sec)
				}
				for _, at := range occ {
					if !covered(ms, at, at+len(sec)) {
						t.Errorf("secret %q at %d not covered by a single match", sec, at)
					}
				}
			}
			for _, k := range f.keep {
				occ := indexAll(s, k)
				if len(occ) == 0 {
					t.Fatalf("fixture has no %q", k)
				}
				for _, at := range occ {
					for _, m := range ms {
						if m.Start < at+len(k) && at < m.End {
							t.Errorf("keep %q overlaps %s(%q)", k, m.Kind, s[m.Start:m.End])
						}
					}
				}
			}
		})
	}
}

// Inputs that must not produce a secret match, bare or behind a line-number gutter.
var (
	configMapYAML = "apiVersion: v1\nkind: ConfigMap\ndata:\n  LOG_LEVEL: debug\n  greeting: aGVsbG8=\n"
	noSecretDocs  = []string{
		"name: x\ntoken: abc123\nusername: bob\n", // kubeconfig short keys without clusters/contexts
		`{"password": "x", "user": "bob"}`,        // no tfstate or docker signature
		`{"auth": "abc"}`,                         // docker key without "auths"
	}
)

func TestStructuredGates(t *testing.T) {
	if ms := testDetector.Detect(configMapYAML); len(ms) > 0 {
		t.Errorf("ConfigMap: want no matches, got %s", describe(configMapYAML, ms))
	}
	for _, in := range noSecretDocs {
		for _, m := range testDetector.Detect(in) {
			if m.Kind == KindSecret {
				t.Errorf("%q: unexpected SECRET match %q", in, in[m.Start:m.End])
			}
		}
	}
}

func TestStructuredKnownTokenWins(t *testing.T) {
	s := readFixture(t, "dotenv")
	val := "sk-ant-api03-FAKEFAKEFAKEFAKEFAKEFAKE"
	at := strings.Index(s, val)
	var hits []Match
	for _, m := range testDetector.Detect(s) {
		if m.Start < at+len(val) && at < m.End {
			hits = append(hits, m)
		}
	}
	if len(hits) != 1 || hits[0].Kind != KindToken || hits[0].Start != at || hits[0].End != at+len(val) {
		t.Fatalf("want one TOKEN match on the value, got %s", describe(s, hits))
	}
}

// Redacting already-redacted text must find nothing new.
func TestStructuredIdempotent(t *testing.T) {
	for _, f := range structuredFixtures {
		s := readFixture(t, f.file)
		red := replaceMatches(s, testDetector.Detect(s))
		if ms := testDetector.Detect(red); len(ms) > 0 {
			t.Errorf("%s: second pass found %s", f.file, describe(red, ms))
		}
	}
}

func covered(ms []Match, start, end int) bool {
	for _, m := range ms {
		if m.Start <= start && end <= m.End {
			return true
		}
	}
	return false
}

func replaceMatches(s string, ms []Match) string {
	var b strings.Builder
	last := 0
	for i, m := range ms {
		b.WriteString(s[last:m.Start])
		fmt.Fprintf(&b, "[REDACTED_%s_%d]", m.Kind, i+1)
		last = m.End
	}
	b.WriteString(s[last:])
	return b.String()
}

func TestFieldSecretKey(t *testing.T) {
	for key, want := range map[string]bool{
		"apiKey": true, "api_key": true, "clientSecret": true, "DB_PASSWORD": true, "access_token": true,
		"password": true, "private-key": true, "connection.string": true,
		"key": false, "sort_key": false, "auth": false, "pwd": false, "primary_key": false,
		"monkey": false, "author": false, "password_hint": false,
	} {
		if got := fieldSecretKey(key); got != want {
			t.Errorf("fieldSecretKey(%q) = %v, want %v", key, got, want)
		}
	}
}

func TestSecretField(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		want       bool
	}{
		{"password", "hunter22", true},
		{"password", "", false},
		{"password", "true", false},
		{"password", "null", false},
		{"token", "$X", false},
		{"token", "${AUTH_TOKEN}", false},
		{"token", "[REDACTED_TOKEN_1]", false},
		{"token", "Bearer [REDACTED_TOKEN_1]", false},
		{"key", "hunter22", false},
	} {
		if got := secretField(tc.key, tc.value); got != tc.want {
			t.Errorf("secretField(%q, %q) = %v, want %v", tc.key, tc.value, got, tc.want)
		}
	}
}
