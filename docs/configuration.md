# Configuration

Each setting is read from an `ANTIBOT_` environment variable where nginx
exports one with
[`env`](https://nginx.org/en/docs/ngx_core_module.html#env), and falls back to
the constant at the top of `src/antibot.js` otherwise. One built `antibot.js`
therefore runs unmodified on any site, and an upgrade replaces the file rather
than merging an edit into it.

```nginx
env ANTIBOT_SECRET;
env ANTIBOT_POW_BITS;
```

An unset or empty variable is absent, not a value.

## Contract

`check(r)` returns 204 when the request carries a valid cookie and 401 when it
does not. `serve_challenge(r)` returns the challenge page with status 200.
`status(r)` returns the counters. The module keeps no state a
request can reach; rate limiting belongs to `limit_req`.

A challenged client therefore receives 200 with the page in the body, because
`error_page 401 = /__antibot_challenge` takes the status from the location it
sends the request to. A browser renders the page either way. A health check
reading the status line sees the same 200 whether the deployment is serving
its site or challenging every visitor, so give the check a cookie, or have it
assert on the body.

The challenge is an HMAC-SHA256 over the client's identity and the current
time slot; [security model](security.md) defines the identity. The client
passes by finding a nonce such that

```
SHA-256(challenge || ":" || decimal(nonce))
```

begins with `POW_BITS` zero bits, then stores `<slot>.<nonce>` in a cookie. A
cookie is valid for its own slot and the one after it, so it lasts between
`WINDOW_SIZE` and twice `WINDOW_SIZE`.

## Constants

| Setting | Environment | Default | Meaning |
|---|---|---|---|
| `SECRET` | `ANTIBOT_SECRET` | none | HMAC key, at least 32 characters |
| `POW_BITS` | `ANTIBOT_POW_BITS` | 22 | difficulty, in leading zero bits |
| `WINDOW_SIZE` | `ANTIBOT_WINDOW_SIZE` | 6h | length of one time slot, 60s to 30d |
| `COOKIE_TTL` | `ANTIBOT_COOKIE_TTL` | 12h | cookie lifetime in the browser; at least twice `WINDOW_SIZE` |
| `COOKIE_NAME` | `ANTIBOT_COOKIE_NAME` | `__Host-antibot-ac` | cookie name |
| `SITE_NAME` | `ANTIBOT_SITE_NAME` | `""` | heading on the challenge page; empty means none |
| `RESCREEN_RATE` | `ANTIBOT_RESCREEN_RATE` | 0.02 | fraction of document requests re-challenged; below 1 |
| `POW_BITS_MAX` | source only | 32 | ceiling; `POW_BITS` is clamped to it |
| `POW_EFFORT_FACTOR` | source only | 64 | work cap before a client gives up |
| `IDENTITY_FIELD_MAX` | source only | 256 | characters of each identity component compared |
| `MAX_COOKIE_CANDIDATES` | source only | 4 | cookies under the name that are verified |

Changing `COOKIE_NAME` invalidates existing cookies and challenges every
visitor once. `SITE_NAME` is HTML-escaped before insertion.

`POW_BITS`, `WINDOW_SIZE`, `COOKIE_TTL`, `RESCREEN_RATE` and `COOKIE_NAME`
are checked when the module loads, whether they came from the environment or
from the source. A value outside its range is reported in the error log on the
first request and replaced by the default. A cookie name without the
`__Host-` prefix is kept and reported, because it gives up the guarantee that
a host holds only one cookie under the name.

`IDENTITY_FIELD_MAX` and `MAX_COOKIE_CANDIDATES` bound the work one request
can ask for. A browser sends one cookie under the name, because the `__Host-`
prefix forces `Path=/` and a host cannot then hold two.

## Difficulty

Each bit doubles the work. Mean solve time with the SIMD solver on a desktop
core:

| Bits | 1 worker | 2 workers | 4 workers |
|---|---|---|---|
| 22 | 0.5s | 0.2s | 0.2s |
| 24 | 1.9s | 1.0s | 0.6s |
| 26 | 7.5s | 3.9s | 2.4s |
| 28 | 30.0s | 15.7s | 9.8s |

Every figure above is node on one desktop core, an Intel i7-3770K. The table
gives the shape of the curve. A browser figure and a phone figure are absent.

The pure-JS fallback runs at 2.2x the SIMD solver's time on that core.
`test/solver.test.mjs` prints both rates for the machine it runs on.

The wait is geometrically distributed: 5% of visitors wait more than 3x the
mean and 0.7% more than 5x, so no visitor can be told how long to expect.

For reference, Anubis expresses difficulty in leading zero hex digits and
defaults to 4 or 5 of them, which is 16 to 20 bits.

## Re-screening

`RESCREEN_RATE` of document requests holding a valid cookie are challenged
again. A request is a document request when `Sec-Fetch-Dest` is `document` or
absent. Subresource and background requests are never re-screened, because the
challenge page is only a correct response to a navigation.

A solved cookie otherwise admits unlimited requests until its slot expires, so
`RESCREEN_RATE` is what applies a per-request cost to a client that reuses
cookies.

## Counters

`status(r)` returns the counters as text:

```
version 0.1.0
bits 22
zone antibot
challenges 3
accepted 0
rejected 7
rescreened 0
misconfigured 0
```

njs creates a VM per request, so a counter in a module variable is reset
before anything reads it. The counters live in a shared dictionary, which
outlives the request and is shared across workers:

```nginx
js_shared_dict_zone zone=antibot:32k type=number;
```

Without that zone the gate behaves exactly as it does with it, and `status`
answers `zone missing` rather than reporting zeros. Counting never fails a
request: a full zone is not a reason to refuse a visitor.

`challenges` counts pages served, `accepted` requests answered 204, `rejected`
requests answered 401 without a valid cookie, `rescreened` requests that held
one and were challenged anyway, and `misconfigured` requests that found no
usable secret. They count from the moment the zone was created and reset when
nginx reloads.

Restrict the location that serves them: the ratio of challenges to accepted
says how much of the traffic is being challenged.

## Logging

The module writes one
[`info`](https://nginx.org/en/docs/ngx_core_module.html#error_log) line per
challenge served, carrying the client address and the request URI. Set
`error_log` to `info` to keep them; nginx drops them at its default level, and
one challenge is served for every request that arrives without a cookie.

A misconfigured secret is written at `error` on the first request that reaches
the module.

Addresses and URIs are encoded before they are logged: bytes outside printable
ASCII become `\xNN` and characters above U+00FF become `\uNNNN`, so each entry
occupies one line.
