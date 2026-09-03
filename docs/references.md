# References

Sources these docs rely on.

## Technique

- [Hashcash](http://www.hashcash.org/hashcash.pdf): the construction. A client
  searches for an input whose hash has a required number of leading zero bits.
- [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final): SHA-256, the
  hash both solvers implement and `pow_valid()` verifies.
- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104): HMAC, which derives the
  challenge from the secret and the identity in `expected_challenge()`.
- [Gueron and Krasnov, *Simultaneous hashing of multiple messages*, IACR
  2012/371](https://eprint.iacr.org/2012/371.pdf): the multi-buffer SIMD
  construction the wasm solver uses to retire four nonces per round set.
- [WebAssembly SIMD](https://github.com/WebAssembly/simd/blob/main/proposals/simd/SIMD.md):
  the `v128` operations `src/pow_solver.c` is written against.

## Optimization

- [V8: fast, parallel applications with WebAssembly SIMD](https://v8.dev/features/simd):
  what the wasm solver's `i32x4` lanes compile to.

## Comparable systems

- [Anubis](https://github.com/TecharoHQ/anubis): browser proof-of-work gate
  using the same Hashcash construction. Expresses difficulty in leading zero
  hex digits, defaults to 4 or 5 of them, and spawns a worker pool at
  `hardwareConcurrency / 2`.

## Threat model

- [Please Show Your Work: Bypassing JavaScript Proof-of-Work
  CAPTCHAs](https://www.sprocketsecurity.com/blog/please-show-your-work-bypassing-javascript-proof-of-work-captchas):
  why none of the challenge can be secret, and the limits of raising
  difficulty.

## nginx and njs

Upstream documentation for the directives this module uses and for the njs
runtime.

- [njs documentation](https://nginx.org/en/docs/njs/)
- [njs reference](https://nginx.org/en/docs/njs/reference.html)
- [`ngx_http_js_module`](https://nginx.org/en/docs/http/ngx_http_js_module.html)
- [`ngx_http_auth_request_module`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
- [`ngx_http_limit_req_module`](https://nginx.org/en/docs/http/ngx_http_limit_req_module.html)
- [`error_page`](https://nginx.org/en/docs/http/ngx_http_core_module.html#error_page):
  the `=` form is why a challenged request answers 200.
- [`env`](https://nginx.org/en/docs/ngx_core_module.html#env): how every
  setting reaches the module.

## The browser side

- [Cookie prefixes, RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#name-cookie-name-prefixes):
  what `__Host-` requires and what it guarantees.
- [Fetch Metadata](https://www.w3.org/TR/fetch-metadata/): `Sec-Fetch-Dest`,
  which the re-screening rule reads to tell a navigation from a subresource.
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/):
  `'wasm-unsafe-eval'` and the directives the challenge page needs.
