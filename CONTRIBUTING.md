# Contributing

Thanks for helping! I've felt like there's been a lack of emphasis on privacy and decided that building a tool to support a lower digital footprint would be helpful for you and others.

`nospy` sits between an agent and an LLM and decides what gets sent, so changes are reviewed with that in mind. Small, focused pull requests move fastest.

## Before you start

- For a bug fix or small improvement, open a pull request.
- For a new flag, route, detector or mode, open an issue first and ping me @6fears7.

## Setup

Needs Go 1.27. The project aims to only use the standard library

```
go build -o nospy ./cmd/nospy
go test ./...
```

## What CI checks

A pull request needs all of these to pass. Run them locally first:

```
go mod tidy -diff
go vet ./...
go build ./...
go test -race -shuffle=on ./...
golangci-lint run        # v2.13, config in .golangci.yml (includes gosec and gofmt/goimports)
```

If you change the Helm chart, also run `deploy/helm/test.sh` (needs `helm`, no cluster).

## Guidelines

- **Add a test with every behavior change.** For a redaction fix, add the failing input first. See `internal/payload/redaction_gaps_test.go`.
- **Use fake data in tests, docs and examples.** Use `example.com` addresses, documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and obviously made-up tokens. Never paste a real credential or personal value.
- **Never retain or log redacted values.** Logs, errors and metrics must not contain request bodies, paths, clients, credentials or the original values. Metric labels are limited to configured routes, redaction kinds and other bounded sets.
- **Keep flags and messages provider-neutral.** Say "LLM" or "the agent", not a vendor name. Vendor names are fine as values, such as route prefixes and the provider table, but not in flag names or user-facing text.
- **Update the docs.** If you change a flag, route, metric or limitation, update the matching page in `docs/` and the README if it is mentioned there.
- **Keep error messages free of URLs.** An upstream URL may carry credentials.

## Pull requests

- Describe what changed and why, and how you tested it.
- Keep unrelated changes, such as reformatting, in a separate pull request.
- Maintainers may ask for changes. Please be patient with the review.

## Releases

- Maintainers publish by pushing a tag: `git tag v0.2.0 && git push origin v0.2.0` (`v0.2.0-rc.1` makes a pre-release). 
- The Release workflow will then run
- Before tagging a final release, edit `VERSION` on `main` and run `deploy/helm/sync-version.sh`; the workflow refuses a tag that does not match `VERSION`
- `VERSION` manages the chart version and appVersion (`version` and `appVersion` in Chart.yaml, the `nospy.appVersion` helper, and the sidecar image tag in `examples/sidecar-deployment.yaml`)

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE), the same as the rest of the project. There is no separate contributor agreement.
