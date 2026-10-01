package proxy

// Provider is a built-in upstream that speaks one of the API families, so a consumer can
// write `--provider NAME` instead of a route by hand.
type Provider struct {
	Name     string // route prefix is "/" + Name
	Upstream string // absolute http(s) URL; for the openai family it ends in /v1
	API      string // "anthropic" or "openai"
	// ExtraHeaders names client request headers to forward on this provider's route in
	// addition to the header allowlist (step 12), e.g. OpenRouter's HTTP-Referer and X-Title.
	ExtraHeaders []string
}

// Providers is the provider table. Only entries verified against the provider's current docs
// AND a real call may be added; do not add one from memory. Each needs a docs link in a comment.
// Candidates (unverified, deliberately not listed yet): deepseek, moonshot, zhipu, groq, xai,
// mistral, openrouter, together (see plan/09-openai.md).
var Providers = []Provider{
	// Ollama's OpenAI-compatible API. Docs: https://github.com/ollama/ollama/blob/main/docs/openai.md
	// Verified 2026-09-30 against a local Ollama container (chat completions, streaming, tool calls).
	{Name: "ollama", Upstream: "http://127.0.0.1:11434/v1", API: "openai"},
}

// LookupProvider returns the provider table entry called name.
func LookupProvider(name string) (Provider, bool) {
	for _, p := range Providers {
		if p.Name == name {
			return p, true
		}
	}
	return Provider{}, false
}
