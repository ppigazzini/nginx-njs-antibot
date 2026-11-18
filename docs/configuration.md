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

An unset or empty variable is absent, not a value. Four of these settings
must match on every host serving the site;
[installation](installation.md) says which and why.

A variable reaches the module from the environment the nginx master process
started in. A reload keeps the values the master started with, so a new value
takes a stop and a start; `test/nginx/check.sh` asserts it under njs 0.8.2 and
0.9.4. Whether the `env NAME=value;` form reaches the module depends on the
njs version: njs 0.8.2 with nginx 1.24.0 ignored it on a reload and on a
start, and njs 0.9.4 applied it on a reload. Set values in the environment.

## Contract

`check(r)` returns 204 when the request carries a valid cookie and 401 when it
does not. `serve_challenge(r)` returns the challenge page with status 200.
`report(r)` takes the solver path and rate the page sends after it solves,
and returns 204, or 400 for anything else. `status(r)` returns the counters.
The module keeps no state a request can reach; rate limiting belongs to
`limit_req`.

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
| `POW_BITS` | `ANTIBOT_POW_BITS` | 22 | difficulty, in leading zero bits, at least 1 |
| `WINDOW_SIZE` | `ANTIBOT_WINDOW_SIZE` | 21600 | length of one time slot in seconds, 60 to 2592000 |
| `COOKIE_TTL` | `ANTIBOT_COOKIE_TTL` | twice `WINDOW_SIZE` | cookie lifetime in the browser in seconds; at least twice `WINDOW_SIZE` |
| `COOKIE_NAME` | `ANTIBOT_COOKIE_NAME` | `__Host-antibot-ac` | cookie name |
| `SITE_NAME` | `ANTIBOT_SITE_NAME` | `""` | heading on the challenge page; empty means none |
| `CHALLENGE_LOG_LEVEL` | `ANTIBOT_CHALLENGE_LOG_LEVEL` | `info` | level the challenge and report lines are written at: `off`, `info`, `warn` or `error` |
| `REPORT_PATH` | `ANTIBOT_REPORT_PATH` | `/__antibot_report` | where the page sends its solve report; an absolute path |
| `POW_BITS_MAX` | source only | 32 | ceiling; `POW_BITS` is clamped to it |
| `POW_EFFORT_FACTOR` | source only | 64 | work cap before a client gives up |
| `IDENTITY_FIELD_MAX` | source only | 256 | characters of each identity component compared |
| `MAX_COOKIE_CANDIDATES` | source only | 4 | cookies under the name that are verified |
| `SLOW_SOLVE_SECONDS` | source only | 10 | mean solve time above which a report counts as slow |

Changing `COOKIE_NAME` invalidates existing cookies and challenges every
visitor once. `SITE_NAME` is HTML-escaped before insertion.

Every setting except `SITE_NAME` is checked when the module loads. Its value
is the first valid one among the environment, the constant in
`src/antibot.js`, and a built-in value equal to the default in the table. A
number is decimal digits and nothing else: whitespace, a sign, a fraction, an
exponent and a hexadecimal prefix are invalid. `POW_BITS` above `POW_BITS_MAX`
is clamped to it. Each value passed over is reported in the error log with the
rule it breaks and the value used instead, once, or on every request where no
shared zone is configured to record that it was reported. A cookie name
without the `__Host-` prefix is kept and reported, because it gives up the
guarantee that a host holds only one cookie under the name.

`IDENTITY_FIELD_MAX` and `MAX_COOKIE_CANDIDATES` bound the work one request
can ask for. A browser sends one cookie under the name, because the `__Host-`
prefix forces `Path=/` and a host cannot then hold two.

## Difficulty

Each bit doubles the work. Mean solve time with the SIMD solver, from its rate
of 8.6M hashes/sec per core on an Intel i7-3770K, the same under node and in
Chromium ([solver rates](security.md#solver-rates)), and the scaling over
workers in [design](design.md#the-worker-pool):

| Bits | 1 worker | 2 workers | 4 workers |
|---|---|---|---|
| 22 | 0.5s | 0.3s | 0.2s |
| 24 | 1.9s | 1.0s | 0.6s |
| 26 | 7.8s | 4.1s | 2.5s |
| 28 | 31.1s | 16.3s | 10.1s |

The pure-JS fallback runs at 2.3x the SIMD solver's time under node and 2.4x
in Chromium. With the JIT off, Chromium has no WebAssembly and runs the JS
solver at 0.019M hashes/sec per core: a mean solve at 22 bits takes 221s on
one worker and 72s on four. A phone figure is absent.
`test/solver.test.mjs` prints both rates for the machine it runs on.

The wait is geometrically distributed: 5% of visitors wait more than 3x the
mean and 0.7% more than 5x, so no visitor can be told how long to expect.

For reference, Anubis expresses difficulty in leading zero hex digits and
defaults to 4 or 5 of them, which is 16 to 20 bits.

## The solve report

After the page stores the cookie, it sends the solver that won, `wasm` or
`js`, and its rate in hashes per second to `REPORT_PATH` with
`navigator.sendBeacon`. The rate is the winning nonce over the time since the
workers started: the workers scan interleaved blocks at one speed, so the
nonces below the winning one are about the number tried.

nginx serves `REPORT_PATH` from a location gated by `check()` that calls
`report(r)`, so only a client holding a valid cookie is counted:

```nginx
location = /__antibot_report {
    auth_request /__antibot_check;
    js_content   antibot.report;
}
```

`report(r)` counts the solver, counts the solve as slow when the rate puts the
mean solve at the current difficulty above `SLOW_SOLVE_SECONDS`, and writes
one line at `CHALLENGE_LOG_LEVEL`. A holder of a valid cookie can send a
report again, or send any rate, so the counts are what visitors report.
Without the location the report reaches the gated catch-all and the backend,
and nothing is counted.

## Counters

`status(r)` returns the counters as text:

```
version 0.0.2
bits 22
window 21600
zone antibot
challenges 8
accepted 5
rejected 9
misconfigured 0
solved_wasm 1
solved_js 0
solved_slow 0
```

njs creates a VM per request, so a counter in a module variable is reset
before anything reads it. The counters live in a shared dictionary, which
outlives the request and is shared across workers:

```nginx
js_shared_dict_zone zone=antibot:32k type=number;
```

Without that zone the gate behaves exactly as it does with it, `status`
answers `zone missing` rather than reporting zeros, and a configuration
warning is written on every request rather than once, because njs clones a VM
per request and there is nowhere else to record that one was written.

Counting never fails a request: a full zone is not a reason to refuse a
visitor.

`bits` and `window` are the difficulty and the slot length in effect.
`challenges` counts pages served, `accepted` requests answered 204, `rejected`
requests answered 401, and `misconfigured` requests that found no usable
secret. `solved_wasm` and `solved_js` count [solve reports](#the-solve-report)
by solver, and `solved_slow` those whose rate puts the mean solve above
`SLOW_SOLVE_SECONDS`. They count from the moment the zone was created. The
zone outlives a reload, so a stop and a start is what empties it.

Restrict the location that serves them: the ratio of challenges to accepted
says how much of the traffic is being challenged.

## Logging

The module writes one line per challenge served, carrying the client address
and `$request_uri`, the URI the client requested, at the level
`CHALLENGE_LOG_LEVEL` names. One challenge is served for every request that
arrives without a cookie. Each solve report writes one line at the same
level, carrying the address, the solver and the rate.

[`error_log`](https://nginx.org/en/docs/ngx_core_module.html#error_log) writes
a line only at or above the level it is set to, and defaults to `error`. At the
default `CHALLENGE_LOG_LEVEL` of `info`, keeping the line means setting
`error_log` to `info`, which also keeps every `info` line nginx writes itself.
Raising `CHALLENGE_LOG_LEVEL` to `warn` or `error` keeps the line at an
`error_log` level that admits less. `off` writes nothing.

A misconfigured secret is written at `error` under the same rule.

Addresses and URIs are encoded before they are logged: bytes outside printable
ASCII become `\xNN` and characters above U+00FF become `\uNNNN`, so each entry
occupies one line.
