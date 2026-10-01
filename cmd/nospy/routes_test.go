package main

import (
	"net/url"
	"slices"
	"strings"
	"testing"
)

func TestParseRoutes(t *testing.T) {
	got, err := parseRoutes([]string{
		"/anthropic=https://gw.example/x",
		"/openai=https://gw.example/v1,api=openai", // api may be repeated for a built-in prefix when it matches
		"/myllm=https://llm.example/v1,api=openai",
		"/other=http://h/a?x=1,2,api=anthropic", // a comma inside the URL stays in the URL
	})
	want := []routeSpec{
		{prefix: "/anthropic", rawURL: "https://gw.example/x", api: "anthropic"},
		{prefix: "/openai", rawURL: "https://gw.example/v1", api: "openai"},
		{prefix: "/myllm", rawURL: "https://llm.example/v1", api: "openai"},
		{prefix: "/other", rawURL: "http://h/a?x=1,2", api: "anthropic"},
	}
	if err != nil || !slices.Equal(got, want) {
		t.Errorf("got %v, %v", got, err)
	}
	if got, err := parseRoutes(nil); err != nil || len(got) != 0 {
		t.Errorf("no flags: got %v, %v", got, err)
	}
}

func TestParseRoutesErrors(t *testing.T) {
	// A URL may hold credentials; no error may echo it.
	const secret = "hunter2"
	for name, bad := range map[string][]string{
		"new prefix without api":   {"/myllm=https://u:" + secret + "@x"},
		"missing PREFIX=":          {"https://u:" + secret + "@x"},
		"missing PREFIX= with =":   {"https://u:" + secret + "@x/p?a=b"},
		"prefix not one segment":   {"/a/b=http://x/" + secret},
		"prefix without slash":     {"myllm=http://x/" + secret + ",api=openai"},
		"empty URL":                {"/anthropic="},
		"empty URL with api":       {"/myllm=,api=openai"},
		"duplicate":                {"/anthropic=http://a/" + secret, "/anthropic=http://b/" + secret},
		"duplicate new prefix":     {"/x=http://a/" + secret + ",api=openai", "/x=http://b/" + secret + ",api=openai"},
		"bad api":                  {"/myllm=http://x/" + secret + ",api=gemini"},
		"api given twice":          {"/myllm=http://x/" + secret + ",api=openai,api=openai"},
		"api conflicts w/ builtin": {"/anthropic=http://x/" + secret + ",api=openai"},
	} {
		_, err := parseRoutes(bad)
		if err == nil {
			t.Errorf("%s: want error", name)
		} else if strings.Contains(err.Error(), secret) {
			t.Errorf("%s: error echoes the URL: %v", name, err)
		}
	}
}

func TestRouteFlagHelpNamesNoVendorOutsideValues(t *testing.T) {
	_, out, _ := runCLI(t, "", "--help")
	i := strings.Index(out, "-route")
	if i < 0 {
		t.Fatalf("no -route in help:\n%s", out)
	}
	// Everything before the per-route lines (which list values from the table) is vendor
	// free, apart from the api= values themselves.
	first, _, _ := strings.Cut(out[i:], "/anthropic")
	first = strings.ReplaceAll(first, "api="+apiNames(), "")
	for _, vendor := range []string{"anthropic", "openai", "ollama"} {
		if strings.Contains(strings.ToLower(first), vendor) {
			t.Errorf("route help names a vendor (%s) outside a value:\n%s", vendor, out[i:])
		}
	}
	j := strings.Index(out, "-provider")
	if j < 0 {
		t.Fatalf("no -provider in help:\n%s", out)
	}
	prov, _, _ := strings.Cut(out[j:], "\n  -")
	for _, vendor := range []string{"anthropic", "openai", "ollama"} {
		if strings.Contains(strings.ToLower(prov), vendor) {
			t.Errorf("provider help names a vendor (%s):\n%s", vendor, prov)
		}
	}
}

func noGetenv(string) string { return "" }

func routeByPfx(t *testing.T, rs []wrapRoute, prefix string) wrapRoute {
	t.Helper()
	for _, r := range rs {
		if r.Prefix == prefix {
			return r
		}
	}
	t.Fatalf("no route %s in %v", prefix, rs)
	return wrapRoute{}
}

func TestBuildWrapRoutesDefaults(t *testing.T) {
	rs, err := buildWrapRoutes(nil, nil, noGetenv)
	if err != nil || len(rs) != 2 {
		t.Fatalf("got %v, %v", rs, err)
	}
	a, o := routeByPfx(t, rs, "/anthropic"), routeByPfx(t, rs, "/openai")
	if a.Upstream.String() != "https://api.anthropic.com" || a.envVar != "ANTHROPIC_BASE_URL" || a.baseSuffix != "" {
		t.Errorf("anthropic route = %+v", a)
	}
	if o.Upstream.String() != "https://api.openai.com/v1" || o.envVar != "OPENAI_BASE_URL" || o.baseSuffix != "/v1" {
		t.Errorf("openai route = %+v", o)
	}
	if !slices.Equal(upstreamHosts(rs), []string{"api.anthropic.com", "api.openai.com"}) {
		t.Errorf("allowlist hosts = %v", upstreamHosts(rs))
	}
}

func TestBuildWrapRoutesOverrideAndEnv(t *testing.T) {
	env := map[string]string{"OPENAI_BASE_URL": "https://gw.corp.example/v1"}
	specs, _ := parseRoutes([]string{"/anthropic=https://flag.example"})
	rs, err := buildWrapRoutes(specs, nil, func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if got := routeByPfx(t, rs, "/anthropic").Upstream.String(); got != "https://flag.example" {
		t.Errorf("flag over default: %s", got)
	}
	if got := routeByPfx(t, rs, "/openai").Upstream.String(); got != "https://gw.corp.example/v1" {
		t.Errorf("env over default: %s", got)
	}
}

func TestBuildWrapRoutesNewPrefix(t *testing.T) {
	specs, _ := parseRoutes([]string{"/myllm=https://llm.example/v1,api=openai"})
	rs, err := buildWrapRoutes(specs, nil, noGetenv)
	if err != nil || len(rs) != 3 {
		t.Fatalf("got %v, %v", rs, err)
	}
	r := routeByPfx(t, rs, "/myllm")
	if r.envVar != "" {
		t.Errorf("a new --route prefix must not take over an env var: %+v", r)
	}
	if _, ok := r.Dialect("/v1/chat/completions"); !ok {
		t.Error("api=openai route does not resolve chat completions")
	}
	if _, ok := r.Dialect("/v1/messages"); ok {
		t.Error("api=openai route resolves Anthropic paths")
	}
	if hs := upstreamHosts(rs); !slices.Contains(hs, "llm.example") || len(hs) != 3 {
		t.Errorf("allowlist hosts = %v, want every route's host", hs)
	}
}

func TestBuildWrapRoutesProvider(t *testing.T) {
	rs, err := buildWrapRoutes(nil, []string{"ollama"}, func(k string) string {
		return map[string]string{"OPENAI_BASE_URL": "https://ignored.example"}[k]
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 {
		t.Fatalf("the provider must replace the built-in route of its family: %v", rs)
	}
	p := routeByPfx(t, rs, "/ollama")
	if p.Upstream.String() != "http://127.0.0.1:11434/v1" || p.envVar != "OPENAI_BASE_URL" || p.baseSuffix != "/v1" {
		t.Errorf("provider route = %+v", p)
	}
	for _, r := range rs {
		if r.Prefix == "/openai" {
			t.Error("built-in /openai route still served")
		}
	}
	if routeByPfx(t, rs, "/anthropic").envVar != "ANTHROPIC_BASE_URL" {
		t.Error("the other family's route changed")
	}
	if !slices.Contains(upstreamHosts(rs), "127.0.0.1") {
		t.Errorf("hosts = %v", upstreamHosts(rs))
	}
}

func TestBuildWrapRoutesErrors(t *testing.T) {
	nospyURL := "http://127.0.0.1:5555/" + strings.Repeat("ab", 16) + "/openai/v1"
	chainEnv := func(k string) string {
		if k == "OPENAI_BASE_URL" {
			return nospyURL
		}
		return ""
	}
	for name, c := range map[string]struct {
		routes, providers []string
		getenv            func(string) string
		want              string
	}{
		"unknown provider":        {providers: []string{"nosuch"}, want: "nospy providers"},
		"duplicate provider":      {providers: []string{"ollama", "ollama"}, want: "more than once"},
		"provider vs route":       {routes: []string{"/ollama=http://x,api=openai"}, providers: []string{"ollama"}, want: "already defined"},
		"provider vs builtin":     {routes: []string{"/openai=http://x/v1"}, providers: []string{"ollama"}, want: "conflicts"},
		"chain via env (openai)":  {getenv: chainEnv, want: "chain"},
		"chain via new route":     {routes: []string{"/x=" + nospyURL + ",api=openai"}, want: "chain"},
		"chain via flag override": {routes: []string{"/openai=" + nospyURL}, want: "chain"},
		"new route not http":      {routes: []string{"/x=ftp://h,api=openai"}, want: "absolute http(s)"},
	} {
		specs, err := parseRoutes(c.routes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		getenv := c.getenv
		if getenv == nil {
			getenv = noGetenv
		}
		_, err = buildWrapRoutes(specs, c.providers, getenv)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		} else if strings.Contains(err.Error(), "5555") || strings.Contains(err.Error(), "abab") {
			t.Errorf("%s: error echoes the URL: %v", name, err)
		}
	}
}

// 127.0.0.1:11434 (Ollama) is a plain local server, not a nospy address.
func TestLocalProviderIsNotChaining(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:11434/v1")
	if isNospyAddr(u) {
		t.Error("a plain local upstream was taken for a nospy address")
	}
}
