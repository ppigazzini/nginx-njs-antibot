# nginx-njs-antibot

A proof-of-work gate for nginx, written as an njs module. Browser-facing
routes are placed behind `auth_request`. A request without a valid challenge
cookie is answered with a page that solves a challenge and sets one.

The solver is SHA-256 in four-way SIMD WebAssembly, spread over a pool of Web
Workers, with a pure-JS fallback for engines without SIMD.

The deployable module is a single file, `antibot.js`. It is built, not
committed: run `./build.sh`, which writes it to `dist/antibot.js`. Published
builds appear under
[releases](https://github.com/ppigazzini/nginx-njs-antibot/releases).

## Documentation

[docs/](docs/README.md)

## Licence

Licensed under either of

- [Blue Oak Model License 1.0.0](https://blueoakcouncil.org/license/1.0.0)
  ([LICENSE-BLUEOAK](LICENSE-BLUEOAK))
- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
licence, shall be dual licensed as above, without any additional terms or
conditions.
