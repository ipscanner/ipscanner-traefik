# Contributing

## Reporting bugs

Open an issue at https://github.com/ipscanner/ipscanner-traefik/issues. Include the version you use, what you expected, what happened, and the smallest example that reproduces it.

Report security issues privately as described in [SECURITY.md](SECURITY.md).

## Proposing changes

Open a pull request against `main`. For larger changes, open an issue first so we can agree on the approach.

## Code and tests

- Every new feature or bug fix comes with tests.
- CI must pass before a pull request is merged.
- Follow the existing code style.

Run the same checks as CI before you push:

```sh
gofmt -l $(git ls-files '*.go' | grep -v '^vendor/')
go mod vendor
go vet ./...
go test -race ./...
sh test/yaegi/run.sh
```

`gofmt -l` must print nothing and `go mod vendor` must leave `vendor/` unchanged.

Contributions are licensed under the project's license (MIT, see [LICENSE](LICENSE)).
