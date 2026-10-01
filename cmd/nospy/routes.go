package main

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"nospyai/internal/payload"
	"nospyai/internal/proxy"
)

// apiFamily is a protocol a route can speak. It names the path resolver (which endpoints exist
// and which dialect redacts their bodies) and the env var and base-URL shape that agents of this
// family expect. The env var is data here, not a flag: nospy sets it on the child, and reads
// the parent's value of it as the upstream when --route doesn't name one.
type apiFamily struct {
	name       string
	envVar     string
	baseSuffix string // appended to the route's URL when handed to the agent (OpenAI SDKs expect .../v1)
	dialect    func(path string) (payload.Dialect, bool)
	// keyHeader and keyScheme are where clients of this family put their API key; an inject
	// route takes the proxy token from there and sets the real key there ("" scheme = bare value).
	keyHeader, keyScheme string
}

var apiFamilies = []apiFamily{
	{name: "anthropic", envVar: "ANTHROPIC_BASE_URL", dialect: proxy.AnthropicDialect, keyHeader: "X-Api-Key"},
	{name: "openai", envVar: "OPENAI_BASE_URL", baseSuffix: "/v1", dialect: proxy.OpenAIDialect, keyHeader: "Authorization", keyScheme: "Bearer"},
}

func apiByName(name string) *apiFamily {
	for i := range apiFamilies {
		if apiFamilies[i].name == name {
			return &apiFamilies[i]
		}
	}
	return nil
}

func apiNames() string {
	var ns []string
	for _, f := range apiFamilies {
		ns = append(ns, f.name)
	}
	return strings.Join(ns, "|")
}

// routeDef is one route: a path prefix on the proxy, its API family, and (for built-in
// routes) the upstream it forwards to by default.
type routeDef struct {
	prefix          string
	api             string
	defaultUpstream string
	envVar          string // the family's base-URL env var; "" for a route no agent variable points at
	baseSuffix      string
	dialect         func(path string) (payload.Dialect, bool)
}

func newRouteDef(prefix, api, defaultUpstream string) routeDef {
	f := apiByName(api)
	return routeDef{prefix: prefix, api: api, defaultUpstream: defaultUpstream,
		envVar: f.envVar, baseSuffix: f.baseSuffix, dialect: f.dialect}
}

const (
	defaultAnthropicUpstream = "https://api.anthropic.com"
	defaultOpenAIUpstream    = "https://api.openai.com/v1"
)

// routeTable lists the built-in routes.
var routeTable = []routeDef{
	newRouteDef("/anthropic", "anthropic", defaultAnthropicUpstream),
	newRouteDef("/openai", "openai", defaultOpenAIUpstream),
}

// multiFlag collects repeated flag values verbatim. Validation happens afterwards, because
// flag.Func errors echo the value and a URL may carry credentials.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// routeFlagUsage is the --route help text, with the upstream order spelled out per route.
func routeFlagUsage() string {
	var b strings.Builder
	b.WriteString("add or override a route, as `PREFIX=URL[,api=" + apiNames() + "]`; repeatable. " +
		"api is inferred for a built-in PREFIX and required for a new one. " +
		"Upstream of a built-in route: --route, else the parent's env var, else the default:")
	for _, rt := range routeTable {
		fmt.Fprintf(&b, "\n%s: $%s, else %s", rt.prefix, rt.envVar, rt.defaultUpstream)
	}
	return b.String()
}

// routeSpec is one parsed --route value. The URL is unchecked (selectUpstream does that).
// keyMode is "" (the default, passthrough), "passthrough" or "inject"; keyFile is set only with
// inject. Both are serve options: the wrapper refuses them.
type routeSpec struct {
	prefix, rawURL, api string
	keyMode, keyFile    string
}

// prefixRe is one path segment, starting with an alphanumeric.
var prefixRe = regexp.MustCompile(`^/[A-Za-z0-9][A-Za-z0-9._~-]*$`)

// routeOptions are the ,key=value options a --route value can end with.
var routeOptions = map[string]bool{"api": true, "key-mode": true, "key-file": true}

// parseRoutes parses the --route values. Errors never include the URL (it may carry
// credentials), and the prefix is echoed only once it has passed validation. Every bad value
// is reported, joined, so `check` can list all problems at once.
func parseRoutes(vals []string) ([]routeSpec, error) {
	var out []routeSpec
	var errs []error
	seen := map[string]bool{}
	for _, v := range vals {
		spec, err := parseRoute(v, seen)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, spec)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

func parseRoute(v string, seen map[string]bool) (routeSpec, error) {
	prefix, rest, ok := strings.Cut(v, "=")
	if !ok {
		return routeSpec{}, errors.New("--route must be PREFIX=URL[,api=" + apiNames() + "]")
	}
	if !prefixRe.MatchString(prefix) {
		return routeSpec{}, errors.New("--route: PREFIX must be a single path segment such as /myllm")
	}
	// Options are the trailing ",key=value" segments; a comma inside the URL stays in the URL.
	opts := map[string]string{}
	for {
		i := strings.LastIndex(rest, ",")
		if i < 0 {
			break
		}
		k, val, _ := strings.Cut(rest[i+1:], "=")
		if !routeOptions[k] {
			break
		}
		if _, dup := opts[k]; dup {
			return routeSpec{}, fmt.Errorf("--route %s: %s given more than once", prefix, k)
		}
		opts[k] = val
		rest = rest[:i]
	}
	if rest == "" {
		return routeSpec{}, fmt.Errorf("--route %s needs a URL", prefix)
	}
	if seen[prefix] {
		return routeSpec{}, fmt.Errorf("--route %s given more than once", prefix)
	}
	seen[prefix] = true

	api := opts["api"]
	if api != "" && apiByName(api) == nil {
		return routeSpec{}, fmt.Errorf("--route %s: api must be one of %s", prefix, strings.ReplaceAll(apiNames(), "|", ", "))
	}
	if b := routeByPrefix(prefix); b != nil {
		if api != "" && api != b.api {
			return routeSpec{}, fmt.Errorf("--route %s is a built-in %s route; api=%s does not apply", prefix, b.api, api)
		}
		api = b.api
	} else if api == "" {
		return routeSpec{}, fmt.Errorf("--route %s is not a built-in route, so it needs ,api=%s", prefix, apiNames())
	}

	keyMode, keyFile := opts["key-mode"], opts["key-file"]
	switch keyMode {
	case "", "passthrough":
		if _, set := opts["key-file"]; set {
			return routeSpec{}, fmt.Errorf("--route %s: key-file is only valid with key-mode=inject", prefix)
		}
	case "inject":
		if keyFile == "" {
			return routeSpec{}, fmt.Errorf("--route %s: key-mode=inject needs key-file=FILE", prefix)
		}
	default:
		return routeSpec{}, fmt.Errorf("--route %s: key-mode must be passthrough or inject", prefix)
	}
	return routeSpec{prefix: prefix, rawURL: rest, api: api, keyMode: keyMode, keyFile: keyFile}, nil
}

func routeByPrefix(prefix string) *routeDef {
	for i := range routeTable {
		if routeTable[i].prefix == prefix {
			return &routeTable[i]
		}
	}
	return nil
}

// wrapRoute is a route the wrapper serves, plus how the child is pointed at it.
type wrapRoute struct {
	proxy.Route
	envVar     string // set on the child to this route's URL; "" = no variable points here
	baseSuffix string
}

// buildWrapRoutes resolves the wrapper's routes: the built-in routes (upstream from --route,
// else the parent's env var, else the default), any new --route prefixes, and --provider
// routes. A provider takes over its API family's env var from the built-in route, which it
// replaces. Error text never includes a URL.
func buildWrapRoutes(specs []routeSpec, providers []string, getenv func(string) string) ([]wrapRoute, error) {
	override := map[string]string{} // built-in prefix -> raw URL
	var custom []routeSpec
	for _, s := range specs {
		if s.keyMode != "" || s.keyFile != "" {
			return nil, fmt.Errorf("--route %s: key-mode and key-file are only valid for `nospy serve`", s.prefix)
		}
		if routeByPrefix(s.prefix) != nil {
			override[s.prefix] = s.rawURL
		} else {
			custom = append(custom, s)
		}
	}
	// A provider replaces the built-in route of its family, unless --route already set that one.
	replaced := map[string]bool{} // env var -> taken over by a provider
	var provs []proxy.Provider
	seenProv := map[string]bool{}
	for _, name := range providers {
		p, ok := proxy.LookupProvider(name)
		if !ok {
			return nil, fmt.Errorf("--provider %q is not a known provider (run 'nospy providers' to list them)", name)
		}
		if seenProv[name] {
			return nil, fmt.Errorf("--provider %s given more than once", name)
		}
		seenProv[name] = true
		f := apiByName(p.API)
		if replaced[f.envVar] {
			return nil, fmt.Errorf("--provider %s: %s already points at another provider", name, f.envVar)
		}
		for _, rt := range routeTable {
			if rt.envVar == f.envVar {
				if _, set := override[rt.prefix]; set {
					return nil, fmt.Errorf("--provider %s conflicts with --route %s: both set %s", name, rt.prefix, f.envVar)
				}
			}
		}
		replaced[f.envVar] = true
		provs = append(provs, p)
	}

	var out []wrapRoute
	taken := map[string]bool{}
	add := func(prefix string, up *url.URL, f *apiFamily, withEnv bool) {
		wr := wrapRoute{Route: proxy.Route{Prefix: prefix, Upstream: up, Dialect: f.dialect}}
		if withEnv {
			wr.envVar, wr.baseSuffix = f.envVar, f.baseSuffix
		}
		out = append(out, wr)
		taken[prefix] = true
	}
	for _, rt := range routeTable {
		if replaced[rt.envVar] {
			continue
		}
		up, err := selectUpstream(rt, override[rt.prefix], getenv(rt.envVar))
		if err != nil {
			return nil, err
		}
		add(rt.prefix, up, apiByName(rt.api), true)
	}
	for _, s := range custom {
		up, err := parseUpstream(s.rawURL, "--route "+s.prefix, s.prefix)
		if err != nil {
			return nil, err
		}
		add(s.prefix, up, apiByName(s.api), false)
	}
	for _, p := range provs {
		prefix := "/" + p.Name
		if taken[prefix] {
			return nil, fmt.Errorf("--provider %s: route %s is already defined by --route", p.Name, prefix)
		}
		up, err := parseUpstream(p.Upstream, "provider "+p.Name, prefix)
		if err != nil {
			return nil, err
		}
		add(prefix, up, apiByName(p.API), true)
		out[len(out)-1].ExtraHeaders = p.ExtraHeaders
	}
	return out, nil
}

// upstreamHosts lists every route's upstream hostname, for the detector allowlist.
func upstreamHosts(routes []wrapRoute) []string {
	var hs []string
	for _, r := range routes {
		hs = append(hs, r.Upstream.Hostname())
	}
	return hs
}

// defaultHosts lists the built-in routes' default upstream hosts (for `nospy scan`).
func defaultHosts() []string {
	var hs []string
	for _, rt := range routeTable {
		hs = append(hs, upstreamHost(rt.defaultUpstream))
	}
	return hs
}

// routeHosts lists every route's upstream hostname, for the detector allowlist.
func routeHosts(routes []proxy.Route) []string {
	var hs []string
	for _, r := range routes {
		hs = append(hs, r.Upstream.Hostname())
	}
	return hs
}

// serveRoute is a route `nospy serve` serves, plus where its real key comes from.
type serveRoute struct {
	proxy.Route
	api     string
	keyFile string // inject routes only
}

// serveReservedPrefixes can't be routes: the health endpoints and the path-token prefix.
var serveReservedPrefixes = map[string]bool{"/t": true, "/healthz": true, "/readyz": true}

// buildServeRoutes resolves serve's routes: exactly the --route and --provider entries, with no
// implicit built-ins and no environment lookups (a server serves only what its flags say). A
// provider becomes a passthrough route named after it. All problems are returned, not just the
// first. Error text never includes a URL.
func buildServeRoutes(specs []routeSpec, providers []string) ([]serveRoute, []error) {
	var out []serveRoute
	var errs []error
	taken := map[string]bool{}
	for _, s := range specs {
		f := apiByName(s.api)
		if serveReservedPrefixes[s.prefix] {
			errs = append(errs, fmt.Errorf("--route %s: %s is reserved (health endpoints and the /t/<token> prefix)", s.prefix, s.prefix))
			continue
		}
		up, err := parseUpstream(s.rawURL, "--route "+s.prefix, s.prefix)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rt := serveRoute{Route: proxy.Route{Prefix: s.prefix, Upstream: up, Dialect: f.dialect}, api: s.api, keyFile: s.keyFile}
		if s.keyMode == "inject" {
			rt.KeyMode, rt.KeyHeader, rt.KeyScheme = proxy.KeyInject, f.keyHeader, f.keyScheme
		}
		out = append(out, rt)
		taken[s.prefix] = true
	}
	seenProv := map[string]bool{}
	for _, name := range providers {
		p, ok := proxy.LookupProvider(name)
		if !ok {
			errs = append(errs, fmt.Errorf("--provider %q is not a known provider (run 'nospy providers' to list them)", name))
			continue
		}
		if seenProv[name] {
			errs = append(errs, fmt.Errorf("--provider %s given more than once", name))
			continue
		}
		seenProv[name] = true
		prefix := "/" + p.Name
		if taken[prefix] {
			errs = append(errs, fmt.Errorf("--provider %s: route %s is already defined by --route", p.Name, prefix))
			continue
		}
		up, err := parseUpstream(p.Upstream, "provider "+p.Name, prefix)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, serveRoute{Route: proxy.Route{Prefix: prefix, Upstream: up, Dialect: apiByName(p.API).dialect, ExtraHeaders: p.ExtraHeaders}, api: p.API})
		taken[prefix] = true
	}
	return out, errs
}
