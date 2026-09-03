# Contributing

## Build and test

[docs/development.md](docs/development.md) covers the toolchain, `build.sh`
and the test suites. `./build.sh --strict` is what CI runs.

## Pull requests

CI must pass. It builds the wasm, runs the solver and module suites, fuzzes
the module's input parsing, checks the solver under ASan, UBSan and valgrind
against an OpenSSL oracle, and loads the module into nginx.

A change to the solver or the verifier carries a test that fails without it.
A change to a measured number in the docs carries the measurement.

Write commit messages as
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
[AGENTS.md](AGENTS.md) holds the writing rules for documentation, code
comments and commit messages.

## Licence

Contributions are dual licensed under the Blue Oak Model License 1.0.0 and the
Apache License 2.0, as stated in [README.md](README.md#contribution).

## Vulnerabilities

[SECURITY.md](SECURITY.md) gives the disclosure route.
