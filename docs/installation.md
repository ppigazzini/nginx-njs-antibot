# Installation

## Requirements

- nginx with
  [`ngx_http_js_module`](https://nginx.org/en/docs/http/ngx_http_js_module.html)
  and
  [`ngx_http_auth_request_module`](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html).
  CI runs the module under njs 0.8.2; the newest library method it uses is
  `String.prototype.startsWith`.
- `ANTIBOT_SECRET` exported to the nginx workers with `env ANTIBOT_SECRET;`,
  at least 32 characters. Every other setting is optional and read the same
  way; [configuration](configuration.md) lists them. It is read when the module loads, so changing it
  takes effect on the next nginx reload and invalidates every cookie in
  circulation. Every host serving the site needs the same value, because the
  challenge is derived from it and a cookie solved against one host is
  presented to the next.
- `$remote_addr` must be the client address. Behind a CDN, set
  `set_real_ip_from` and `real_ip_header`, or every visitor shares one
  identity and a single solved cookie serves all of them.
- A `Content-Security-Policy` reaching the challenge location must allow
  `'unsafe-inline'`, `'unsafe-eval'` and `'wasm-unsafe-eval'` in `script-src`,
  `'unsafe-inline'` in `style-src`, and `blob:` in `worker-src`. The page
  carries its script and style inline, builds the JS solver with
  `new Function`, compiles the wasm one, and runs both in a blob worker. Under
  a stricter policy every solver fails and the visitor reads "Verification
  failed". The example carries the header for that location; a site-wide
  policy must be overridden there, not relaxed everywhere.
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

## Wiring

The module must be reachable through `js_path` and imported with `js_import`.
`check` is served from an internal location used as the `auth_request` target,
and `serve_challenge` from the internal location that `error_page 401` points
at. Routes for non-browser clients must be matched before the gated
catch-all.

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
