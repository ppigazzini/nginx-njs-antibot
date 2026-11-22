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
- [`$request_uri`](https://nginx.org/en/docs/http/ngx_http_core_module.html#var_request_uri):
  the URI the challenge line logs, which `error_page` leaves unchanged.
- [PCRE2 API, compile options](https://www.pcre.org/current/doc/html/pcre2api.html):
  `PCRE2_DOLLAR_ENDONLY`, without which `$` also matches before a final
  newline. njs compiles its regular expressions with PCRE2 and without it.

## Addresses

- [RFC 6052](https://www.rfc-editor.org/rfc/rfc6052): the well-known prefix
  `64:ff9b::/96` and how IPv4/IPv6 translation embeds an IPv4 address.
- [RFC 8215](https://www.rfc-editor.org/rfc/rfc8215): the local-use
  translation prefix `64:ff9b:1::/48`.
- [RFC 4380](https://www.rfc-editor.org/rfc/rfc4380): Teredo, which carries
  its server's IPv4 address in `2001::/32` addresses.

## Supply chain

- [Workflow dependency lockfiles](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles):
  what `.github/workflows/actions.lock` records and what the runner enforces.
- [zizmor audits](https://docs.zizmor.sh/audits/): the checks the `workflows`
  job runs.
- [Artifact attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds):
  how a release signs provenance for `antibot.js`.
- [SLSA build provenance v1.0](https://slsa.dev/spec/v1.0/provenance): the
  predicate the attestation carries.
- [Sigstore](https://www.sigstore.dev/): the short-lived certificate the
  attestation is signed with.

## The browser side

- [Beacon](https://www.w3.org/TR/beacon/): `navigator.sendBeacon`, which sends
  the solve report.
- [High Resolution Time](https://www.w3.org/TR/hr-time-3/):
  `performance.now()`, which counts from navigation and gives the wait the
  report carries.

- [Cookie prefixes, RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis#name-cookie-name-prefixes):
  what `__Host-` requires and what it guarantees.
- [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/):
  `'wasm-unsafe-eval'` and the directives the challenge page needs.
