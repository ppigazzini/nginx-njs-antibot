# Security model

`ANTIBOT_SECRET` is the only secret. The challenge page ships the algorithm,
the difficulty, the challenge string and the solver to every visitor, so none
of those can be secret.

Publishing the solver does not assist a scraper. An attacker is not confined
to a browser and is not spending a visitor's patience, and the two advantages
that follow need none of this code.

The first is instructions. x86 since Goldmont and ARMv8 with the crypto
extensions carry SHA-256 in hardware, where `SHA256RNDS2` retires two rounds
per instruction. WebAssembly exposes no such instruction and no proposal adds
one, so the solver in the page cannot reach them at any difficulty. The second
is scale: an attacker runs as many cores as the work is worth, while a visitor
runs one tab and waits.

## Solver rates

Measured on one Intel i7-3770K core, a 2012 part without those instructions.
The wasm is the clang 18.1.3 build CI makes. Under node 26.4.0 the harness is
`test/bench/rate.mjs`, pinned to the core, three runs, on 2026-11-18, and for
OpenSSL 3.0.13's `openssl speed` over 64-byte inputs on 2026-11-22; in
headless Chromium 156.0.8078.4 it is `test/browser/rate.mjs`, pinned to the
core and its hyperthread, two runs, and one run with the JIT off. Each figure
is the median of 15 calls, in M hashes/sec, as the range over the runs:

| Solver | node | Chromium |
|---|---|---|
| wasm SIMD, this solver | 8.64 to 8.65 | 8.56 |
| pure JS fallback, this solver | 3.76 to 3.78 | 3.62 to 3.63 |
| pure JS fallback, `--js-flags=--jitless` | | 0.019 |
| OpenSSL 3.0.13 `sha256`, 64-byte inputs | 1.82 to 1.88 | |

With the JIT off Chromium has no WebAssembly, so the page runs the JS solver
in its interpreter. `test/solver.test.mjs` prints the first two rates for the
machine it runs on. A phone figure is absent. A figure for a core with the
SHA-256 instructions is absent too: published throughput for those cores is
given for large inputs, and this workload is one 64-byte block per candidate,
which the two do not convert between.

## Identity

A client is identified by its IPv4 address or IPv6 /64, its User-Agent and its
Accept-Language. An IPv4-mapped address and an address under the translation
prefix `64:ff9b::/96` are reduced to the IPv4 address they carry. An address
under the local-use translation prefix `64:ff9b:1::/48` or in Teredo's
`2001::/32` is kept whole, because each holds one IPv4 client per address
rather than one host per /64. An address that does not parse is kept whole,
so no two addresses are folded together.

The key is those three fields joined by `|`, each cut to its first 256
characters, because the whole identity is hashed on every request and an
unbounded one would let a large header buy a large HMAC.

Two clients share an identity when their keys match, which happens two ways.
Every component agrees to 256 characters, and real values are far shorter. Or
the join is ambiguous: the fields are not escaped, so for one address
`User-Agent: X|Y` with `Accept-Language: Z` and `User-Agent: X` with
`Accept-Language: Y|Z` give the same key. Both require the same address, which
is the same client, and a cookie remains bound to the identity that solved it
either way.

Two consequences follow. A cookie stops working when any of the three change,
so a browser update re-challenges the client once. And a client that varies a
header holds as many identities as it cares to solve for.

The identity is only as good as the address nginx reports, which behind a CDN
takes configuration: [installation](installation.md) carries the
requirement.

## Cost per request

A request carrying a cookie whose slot is current costs one HMAC-SHA256 and
one SHA-256, whether or not the proof holds. Slot numbers are public, so an
attacker can spend that at will.

A request answered 401 goes through `error_page 401` to the challenge page,
so its cost is `check()` and the page build. A request with no cookie takes
that path, and a client sending one request per address takes it every time.

Under nginx the module runs in njs, which runs its top-level code again for
every request ([decisions](decisions.md#the-build)). Measured with
`test/bench/njs-cost.mjs` under nginx 1.24.0 and njs 0.8.2 on the core above
and its hyperthread, one worker, as each handler's median latency less that
of a location njs does not run, seven rounds of 500 requests, three runs on
2026-11-22:

| Handler | Cost |
|---|---|
| `check()`, no cookie | 129 to 137 us |
| `check()`, a valid cookie | 138 to 145 us |
| `check()`, one junk cookie | 137 to 153 us |
| `serve_challenge()` | 225 to 240 us |

A challenged request runs `check()` and then `serve_challenge()`, about
370 us, so one core serves about 2,700 of them a second. A request with a
valid cookie costs about 140 us before nginx passes it on, about 7,000 a
second.

The module's own work is a small part of that. Measured with
`test/bench/cost.mjs` under node 26.4.0 on the core above, where the module
is evaluated once, as the median of seven runs of 5,000 requests, two runs on
2026-11-22:

| Request | `check()` | the request |
|---|---|---|
| no cookie | 0.13 to 0.14 us | 8.24 to 8.45 us |
| a valid cookie | 11.62 to 11.99 us | 11.90 to 12.07 us |
| one junk cookie, current slot | 11.60 to 11.61 us | 19.51 to 20.18 us |
| four junk cookies, two slots | 26.93 to 27.06 us | 35.52 to 37.01 us |
| 256 junk cookies | 19.93 to 20.36 us | 29.32 to 30.07 us |

The challenge page is 20,573 bytes, 9,611 gzipped, measured on the clang 18
build CI makes, which is the one a release ships. It carries a per-identity
challenge under `Cache-Control: no-store`, so each one is built and sent
whole:

| Challenges | Raw | Gzipped |
|---|---|---|
| 80,000 per hour | 1.65 GB/hour | 0.77 GB/hour |
| per day | 40 GB | 18 GB |

A request of 400 bytes draws an answer 51 times its size, so a fleet that
ignores the page still costs the link that much for every address it uses.
Bandwidth is the larger of the two costs at this traffic.

Most of the page is the embedded solver, so its size follows the compiler.
The figure is for the clang 18 build, and the test that guards it allows a
kilobyte either way.

Each identity component is truncated to 256 characters before hashing, so an
oversized User-Agent or Accept-Language does not buy a larger HMAC.

At most `MAX_COOKIE_CANDIDATES` cookies sent under the name are collected and
verified, so a header full of them multiplies the module's work for a request
by at most 4.2 to 4.5, which four junk cookies over two slots reach: each slot costs an
HMAC-SHA256 and each cookie a SHA-256. 256 junk cookies cost less than four,
because only four are verified and they share one slot.

`test/module.test.mjs` fails if the page size moves more than a kilobyte from
the figure above.

## What the gate does not buy

The gate stops clients that do not execute JavaScript and puts a cost of one
solve per identity and slot on clients that do. It does not price out a
determined operator: at any difficulty a visitor tolerates, an attacker's
compute cost stays small next to what a large IP pool already costs.

Two properties bound what it can achieve:

- A solved cookie admits unlimited requests until its slot expires, so a
  client that reuses cookies amortises the cost.
- Difficulty is symmetric. Raising `POW_BITS` multiplies the cost for
  visitors and attackers alike, and the visitor runs the slower hardware.

Rate limiting on a key that is not per-IP bounds a widely distributed fleet.
That belongs in `limit_req`, not in this module.
