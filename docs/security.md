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

Measured here, on one Intel i7-3770K core, a 2012 part without those
instructions, under node 26:

| Solver | Rate |
|---|---|
| wasm SIMD, this solver | 8.4M hashes/sec |
| pure JS fallback, this solver | 3.7M hashes/sec |
| OpenSSL 3.0 `sha256`, 64-byte blocks | 2.0M hashes/sec |

`test/solver.test.mjs` prints the first two for the machine it runs on. A
figure for a core with the SHA-256 instructions is absent: published
throughput for those cores is given for large inputs, and this workload is one
64-byte block per candidate, which the two do not convert between.

## Identity

A client is identified by its IPv4 address or IPv6 /64, its User-Agent and its
Accept-Language. An IPv4-mapped address is reduced to the IPv4 address it
carries, and an address that does not parse is kept whole, so no two addresses
are folded together.

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

A request with no cookie is answered 401, and `error_page 401` turns that into
a challenge page, so its cost is both calls. That is the path a client sending
one request per address takes every time.

Measured under node, median of three:

| Request | Cost | Ceiling |
|---|---|---|
| no cookie, `check()` alone | 0.12 us | 8,000,000 req/s per core |
| no cookie, `check()` and the challenge | 20 us | 50,000 req/s per core |
| valid slot, junk nonce | 12 us | 80,000 req/s per core |

The challenge page is 20,153 bytes, 9,340 gzipped, measured on the artifact CI
builds, which is the one a release ships. It carries a per-identity challenge
under `Cache-Control: no-store`, so each one is built and sent whole:

| Challenges | Raw | Gzipped |
|---|---|---|
| 80,000 per hour | 1.61 GB/hour | 0.75 GB/hour |
| per day | 39 GB | 18 GB |

A request of 400 bytes draws an answer 50 times its size, so a fleet that
ignores the page still costs the link that much for every address it uses.
Bandwidth is the larger of the two costs at this traffic.

Most of the page is the embedded solver, so its size follows the compiler. A
local clang builds it 576 bytes smaller than the one CI uses, and the test
that guards this figure allows a kilobyte either way.

Each identity component is truncated to 256 characters before hashing, so an
oversized User-Agent or Accept-Language does not buy a larger HMAC. Without
that cap an 8 KB header, which nginx's default `large_client_header_buffers`
permits, doubled the cost and a 32 KB header raised it fivefold.

At most `MAX_COOKIE_CANDIDATES` cookies sent under the name are collected and
verified, so a header full of them cannot multiply the work either. Without
that bound, 256 duplicates cost 2,316 us against 26 us for one.

The gate is accepted at these figures: 50,000 requests per second per core is
above the traffic any deployment of this size serves, and a prefilter would
add state to a module that has none. njs uses its own crypto bindings, so
these figures set the order of magnitude, not the exact number.
`test/module.test.mjs` fails if the page size moves more than a kilobyte from
the figure above.

## What the gate does not buy

The gate stops clients that do not execute JavaScript and puts a per-request
cost on clients that do. It does not price out a determined operator: at any
difficulty a visitor tolerates, an attacker's compute cost stays small next to
what a large IP pool already costs.

Two properties bound what it can achieve:

- A solved cookie admits unlimited requests until its slot expires, so a
  client that reuses cookies amortises the cost.
  [Re-screening](configuration.md#re-screening) applies a per-request toll
  against that.
- Difficulty is symmetric. Raising `POW_BITS` multiplies the cost for
  visitors and attackers alike, and the visitor runs the slower hardware.

Rate limiting on a key that is not per-IP bounds a widely distributed fleet.
That belongs in `limit_req`, not in this module.
