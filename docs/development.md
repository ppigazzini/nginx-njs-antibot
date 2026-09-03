# Development

## Build

```sh
./build.sh            # compile, assemble and test; needs clang with wasm32 and lld
./build.sh --no-test  # compile and assemble only
./build.sh --strict   # treat compiler warnings as errors
npm test              # the three suites, after a build
```

No binary is committed. `build.sh` assembles `dist/antibot.js` from five
files, and modifies none of them:

| Source | Becomes | Checked by |
|---|---|---|
| `src/antibot.js` | the module | `node --check` |
| `src/pow_solver.c` | `dist/pow_solver.wasm`, embedded as base64 | clang, then the native checks |
| `src/solver.js` | `POW_JS_SOLVER` | `node --check` |
| `src/worker.js` | `WORKER_TEMPLATE` | `node --check` |
| `src/page.html` | `PAGE_TEMPLATE` | `node --check` on its script block |

Each is parsed before it is written in, so a syntax error stops the build
rather than reaching a browser. `dist/` is ignored by git.

The page is a template. `build_challenge()` splits it once at load on its
`__ANTIBOT_*` tokens and joins the parts per request, so serving a page costs
a concatenation rather than a substitution over its whole length. A token with
no value is left in the page as itself, where the module suite fails on it,
rather than rendered as `undefined`. A token the module does not know is
reported in the error log when it loads.

`POW_WASM_SIMD_B64` is empty in `src/antibot.js`. An unassembled module still
gates correctly: `WebAssembly.compile` rejects the empty payload and every
worker falls back to the pure-JS solver, at roughly half the rate.

Warnings are not errors by default, so a compiler at a different version
cannot stop the deliverable from building. CI runs `--strict` as its own step.

## Tests

The three suites use
[`node:test`](https://nodejs.org/api/test.html). Each block is a named test,
so a throw fails that one and the rest still run, and the exit code comes from
the tests. `check()` counts within a test, so a test reports all of its
failures rather than stopping at the first, and a final test fails if any
check ran outside one.

```sh
node test/module.test.mjs                       # every test
node --test-name-pattern 'slot boundary' test/module.test.mjs
```

Each suite takes the module to grade as its first argument and defaults to
`dist/antibot.js`. A suite that ignored the argument would report on `dist/`
whatever it was given, which is how `test/mutants.mjs` drives them.

```sh
node test/module.test.mjs dist/antibot.js
```

`test/solver.test.mjs` checks both solvers against node's SHA-256: full digest
vectors, index agreement with brute force, the digit-carry boundaries at
powers of ten where the block is rebuilt, and throughput. It reads the wasm
from the directory holding the module it was given. The pure-JS solver is
lifted out of the built module and evaluated, so what is checked is the source
that ships.

`test/module.test.mjs` solves through real worker threads on both solver
paths and feeds each cookie back to `check()`. It also covers the rejection
cases, the slot boundary from both sides, settings read from the environment,
the constants that are validated at load, the identity invariant in both
directions, the cookie-candidate bound, the escaping of `SITE_NAME`, the page
template's tokens, and the cost of the inputs a request controls.

`test/mutants.mjs` grades the suites rather than the module. It holds a fixed
list of defects, each naming the suite that must notice it, writes each into
the built module and runs that suite against it. A mutation the suite lets
through is a failure. Run it with `node test/mutants.mjs [module]`.

The list is fixed because a generated set has a different survivor list on
every run. Two defects are left out because the nginx lane is what catches
them: dropping the `nosniff` header and dropping `no-store`.

`test/module-fuzz.mjs` throws random and deliberately awkward cookies,
addresses and headers at `check()` and `serve_challenge()`. It asserts that
neither throws, that the status is always 204, 401 or 500, and that a 204 is
only ever returned for a nonce whose digest meets the difficulty, verified
against the challenge the module issues for the same identity.

Reaching that last assertion needs a solved cookie, which costs 2^22 tries at
the shipped difficulty. The suite runs three passes: the built module at its
own difficulty, a variant at 14 bits where it solves cookies itself and
mutates them, and a copy loaded with no secret. It fails if the accept pass
verifies no acceptance, so the assertion cannot go quiet.

A cookie is accepted for its own slot and the one before it, so the check
collects every candidate under the name and a 204 is justified when one of
them meets the difficulty against the challenge for the slot it carries. The
challenge for the earlier slot comes from the module with the clock moved
back, rather than a second derivation here, which would make the oracle the
thing most likely to be wrong. A mutation moves a solved cookie onto the
earlier slot often enough that checking only the current one reports the gate
as broken.

Cookie-acceptance assertions use `Sec-Fetch-Dest: empty`. A navigation is
re-screened at `RESCREEN_RATE` and returns 401 for a valid cookie, so
asserting 204 on one would be flaky rather than strict.

## Under nginx

```sh
./test/nginx/check.sh                  # dist/antibot.js on port 8443
./test/nginx/check.sh dist/antibot.js 8443
```

Serves `examples/nginx.conf.example` under a real nginx and drives the module
through njs, which is the only place it runs outside node. The config,
certificate and module go under a temporary prefix that is removed on exit, so
it needs no privilege and touches nothing outside it. It asserts the gate, the
status and headers, the documented policy, a setting arriving from the
environment, the error log, the accept path, cookie handling as nginx merges
it, and the routes.

## Native checks

```sh
./test/native/check.sh        # fuzz for 60 seconds
./test/native/check.sh 300    # fuzz for 300 seconds
```

`test/native/include/wasm_simd128.h` stands in for clang's wasm header, so
`src/pow_solver.c` compiles natively unmodified and AddressSanitizer,
UndefinedBehaviorSanitizer, libFuzzer and valgrind see the real source. Lanes
are held as `uint32_t` so arithmetic wraps as it does in wasm.

`test/native/fuzz_pow.c` checks two properties against OpenSSL's SHA-256:
`digest_word` returns the digest of `challenge || ":" || decimal(nonce)`, and
`solve` returns the offset of the first nonce in the range whose digest has
`bits` leading zero bits. Inputs are biased toward the decimal-width
boundaries where the block is rebuilt.

## Continuous integration

| Workflow | Trigger | Purpose |
|---|---|---|
| `build.yml` | `workflow_call` | four jobs: `build`, `mutants`, `example`, `sanitize` |
| `ci.yml` | push, pull request | calls `build.yml` |
| `release.yml` | manual, tag required | calls `build.yml`, then publishes |

`ci` and `release` share one reusable workflow, so a release runs exactly the
checks CI runs.

`release.yml` refuses to publish unless the tag is `v` and a version, the tag
is new or already points at the commit being released, and the tag matches the
version stamped into the artifact. It pushes the tag before creating the
release, so the commit it names stays reachable. The guards are functions in
`test/release/guards.sh`, and `test/release/check.sh` runs them over a table
of tags on every push, because they otherwise run once per release.

The `example` job serves `examples/nginx.conf.example` under a real nginx and
asserts that a gated route returns the challenge page with status 200, that
the page carries both solvers and the exact wasm that was built, that a
settings change reaches the page through the environment, that the documented
`Content-Security-Policy` is served and the page still solves under it, that a
solved cookie reaches the backend and does not travel to another identity, and
that a non-browser route reaches the backend. It is the only place the module
runs in njs, not node.

The `mutants` job runs `test/mutants.mjs` against the artifact the `build` job
uploaded. It is separate because it runs a suite per mutation.

The `build` job compiles the solver, assembles the module, repeats the build
with warnings as errors, runs the three suites and `npm test`, and uploads the
artifact the other jobs take. The `sanitize` job runs `test/native/check.sh`.

Actions are pinned to a commit SHA with the release in a trailing comment: a
tag can be moved to point at different code after review, and a bare SHA says
nothing about age.

The wasm is not byte-reproducible across clang versions, so CI records the
compiler version and the SHA-256 of what it built alongside the artifact.

## Releases

Set `version` in `package.json` to the version being released. `build.sh`
stamps it into `ANTIBOT_VERSION`, and the workflow refuses a tag that does not
match it.

Run the `release` workflow from the Actions tab with the tag, such as
`v0.1.0`. `package.json` holds `0.1.0`: the version has no prefix and the tag
for it does.
It builds, tests and runs the module under nginx, then attaches `antibot.js`
and nothing else: the solver is embedded in it. The SHA-256 is in the notes.
