# Installation

## Requirements

- nginx with
  [`ngx_http_js_module`](https://nginx.org/en/docs/http/ngx_http_js_module.html)
  and
  [`ngx_http_auth_request_module`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html).
  CI runs the module under njs 0.8.2 on Ubuntu 24.04 and njs 0.9.4 on Ubuntu
  26.04; the newest library method it uses is `String.prototype.startsWith`.
- `ANTIBOT_SECRET` in the environment nginx starts in, exported to the
  workers with `env ANTIBOT_SECRET;`, at least 32 characters. A reload keeps
  the secret the master started with, so rotating it, after a leak or
  otherwise, takes a stop and a start, and invalidates every cookie in
  circulation. Every other setting is optional and read the same way;
  [configuration](configuration.md) lists them and says what a reload and
  the `env NAME=value;` form do to them.
- Every host serving the site needs the same `ANTIBOT_SECRET`,
  `ANTIBOT_WINDOW_SIZE`, `ANTIBOT_COOKIE_NAME` and `ANTIBOT_POW_BITS`. A
  cookie is solved against one host and presented to the next, and those four
  decide whether it is accepted: the first three change the challenge or the
  name it is stored under, and the fourth changes how much work it takes. A
  host that differs in any of them answers 401 and serves the challenge again,
  so a visitor whose requests reach both solves on every request that reaches
  the one that disagrees.
- `$remote_addr` must be the client address. Behind a CDN, set
  `set_real_ip_from` and `real_ip_header`, or every visitor shares one
  identity and a single solved cookie serves all of them.
- A `Content-Security-Policy` reaching the challenge location must allow
  `'unsafe-inline'`, `'unsafe-eval'` and `'wasm-unsafe-eval'` in `script-src`,
  `'unsafe-inline'` in `style-src`, `blob:` in `worker-src`, and `'self'` in
  `connect-src`. The page carries its script and style inline, builds the JS
  solver with `new Function`, compiles the wasm one, runs both in a blob
  worker, and sends its solve report to the site's own origin. Under a
  stricter policy every solver fails and the visitor reads "Verification
  failed", except that without `connect-src 'self'` the page solves and its
  report is dropped. The example carries the header for that location; a
  site-wide policy must be overridden there, not relaxed everywhere.
- Browsers must reach the site over HTTPS. The cookie carries the
  [`__Host-` prefix](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#cookie_prefixes)
  and the `Secure` attribute, which a browser stores only on a secure origin.
  Over plain HTTP the page reports a failure after it solves.

## The module

`antibot.js` is the only file a server needs. The proof-of-work solver is
compiled from `src/pow_solver.c` and embedded in it.

Run `./build.sh`, which writes it to `dist/antibot.js`. Published builds
appear under
[releases](https://github.com/ppigazzini/nginx-njs-antibot/releases).

A release after v0.0.2 carries a signed
[build provenance attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds),
which binds the SHA-256 of `antibot.js` to the commit and the run of
`release.yml` on `main` that built it. The
[GitHub CLI](https://cli.github.com/manual/gh_attestation_verify) verifies a
downloaded copy against it:

```sh
gh attestation verify antibot.js \
  --repo ppigazzini/nginx-njs-antibot \
  --cert-identity https://github.com/ppigazzini/nginx-njs-antibot/.github/workflows/release.yml@refs/heads/main \
  --deny-self-hosted-runners
```

`--cert-identity` matches the signing workflow and its branch exactly, so a
file built by another workflow, or from another branch, fails. A release's
file can be replaced after it is published; the attestation is what a
download is checked against, and [decisions](decisions.md#the-build) says why
releases are not immutable.

## Wiring

The module must be reachable through `js_path` and imported with `js_import`.
`check` is served from an internal location used as the `auth_request` target,
and `serve_challenge` from the internal location that `error_page 401` points
at. `report` is served at `REPORT_PATH` from a location gated by the same
`auth_request`; [configuration](configuration.md#the-solve-report) gives it.
Routes for non-browser clients must be matched before the gated catch-all.

A request without a valid cookie is answered with the challenge page, and its
body is discarded before the backend sees it. Gate the pages a visitor
navigates to, and match the endpoints they submit to before the gated
catch-all, as the example's API route is. A form posted through the gate
loses what the visitor typed.

There is no default layout: paths, service names and reload commands differ
per installation. `examples/nginx.conf.example` is a complete working
configuration, and CI runs it under a real nginx on every push.

`nginx -t` loads the module and reports an error before any traffic reaches
it.

## Further reading

nginx and njs are documented upstream, in the
[njs documentation](https://nginx.org/en/docs/njs/).
