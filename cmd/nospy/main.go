// Command nospy is a local reverse proxy that redacts secrets and PII in requests to LLM
// APIs and restores them in responses. See `nospy help`.
package main

import "os"

// version is set at build time: go build -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdin, os.Stdout, os.Stderr))
}
