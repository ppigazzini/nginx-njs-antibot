# Development

## Build

```sh
./build.sh            # compile, assemble and test; needs clang with wasm32 and lld
./build.sh --no-test  # compile and assemble only
./build.sh --strict   # treat compiler warnings as errors
npm test              # the three suites, after a build
CLANG=clang-18 CLANG_MAJOR=18 ./build.sh   # the compiler CI and releases use
```

`CLANG` names the compiler, `clang` by default. With `CLANG_MAJOR` set the
build fails unless the compiler reports that major. The solver's rate follows
the compiler: one source gives a different `solve()` under each clang major.
CI and releases build with `clang-18` 1:18.1.3-1ubuntu1 from the Ubuntu 24.04
archive, which rebuilds the v0.0.2 release wasm byte for byte from its source.

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
powers of ten where the block is rebuilt, and throughput. It fails when the
SIMD solver runs below 1.4 times the JS solver in the same process; the
machine's speed cancels in that ratio. It reads the wasm
from the directory holding the module it was given. The pure-JS solver is
lifted out of the built module and evaluated, so what is checked is the source
that ships.

`test/module.test.mjs` solves through real worker threads on both solver
paths and feeds each cookie back to `check()`. It also covers the rejection
cases, the slot boundary from both sides, the iteration cap from both sides,
settings read from the environment and from the source with every malformed
number it refuses, the identity invariant in both directions including
translated addresses, the cookie-candidate bound, the difficulty the page
ships against the one the server enforces, the level the challenge line is
written at, the URI it names, the escaping of `SITE_NAME`, the page template's
tokens, the solve report the page sends and `report()` takes, the counters,
and the growth in cost with every input a request controls.

`test/mutants.mjs` grades the suites rather than the module. It holds a fixed
list of defects, each naming the suite that must notice it, writes each into
the built module and runs that suite against it. A mutation the suite lets
through is a failure. Run it with `node test/mutants.mjs [module]`.

The list is fixed because a generated set has a different survivor list on
every run. Two defects are left out because the nginx lane is what catches
them: dropping the `nosniff` header and dropping `no-store`.

`test/module-fuzz.mjs` throws random and deliberately awkward cookies,
addresses, headers and report arguments at `check()`, `serve_challenge()` and
`report()`. It asserts that none throws, that `check()` answers 204, 401 or
500 and `report()` 204 or 400, and that a 204 from `check()` is only ever
returned for a nonce whose digest meets the difficulty, verified against the
challenge the module issues for the same identity. It reads the window from
`status()`, so it runs under any `ANTIBOT_WINDOW_SIZE`.

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

## Under nginx

```sh
./test/nginx/check.sh                  # dist/antibot.js on port 8443
./test/nginx/check.sh dist/antibot.js 8443
NGINX_MODULES=/path/to/modules ./test/nginx/check.sh   # njs outside the system paths
```

Serves `examples/nginx.conf.example` under a real nginx and drives the module
through njs, which is the only place it runs outside node. The config,
certificate and module go under a temporary prefix that is removed on exit, so
it needs no privilege and touches nothing outside it. It asserts the gate, the
status and headers, the documented policy, a setting arriving from the
environment, the error log and the URI it names, the accept path, the solve
report, cookie handling as nginx merges it, the routes, the counters, and
what a reload changes: the secret, the counters, and an `env NAME=value;`
line.

## Measurements

Every rate and cost in `docs/` comes from one of these, pinned with
`taskset` to one core, or to one core and its hyperthread for a browser:

```sh
taskset -c 2 node test/bench/rate.mjs                 # both solvers under node
taskset -c 2 node test/bench/rate.mjs a=x.wasm b=y.wasm
taskset -c 2 node test/bench/cost.mjs                 # server cost per request
taskset -c 2,6 node test/browser/rate.mjs <chromium>  # both solvers in a worker
node test/browser/page.mjs <chromium> --bits 18 --js-flags=--jitless
```

`test/browser/` drives a headless Chromium over the DevTools protocol through
node's own WebSocket and HTTP, with no dependency. `page.mjs` serves the page a
built module emits under the policy the example sets, solves it in the
browser, and exits non-zero unless the cookie is accepted and the report is
taken.

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
| `build.yml` | `workflow_call` | five jobs: `build`, `mutants`, `example`, `sanitize`, `workflows` |
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

The `example` job runs `test/nginx/check.sh`, the [nginx lane](#under-nginx).
It is the only place the module runs in njs, not node. It then runs
`test/browser/page.mjs` in the runner's Chrome, once on the wasm solver and
once with the JIT off, so the page solves, sends its report and is accepted
under the documented policy in a real browser.

The `mutants` job runs `test/mutants.mjs` against the artifact the `build` job
uploaded. It is separate because it runs a suite per mutation.

The `build` job runs on `ubuntu-24.04` with `clang-18` and `CLANG_MAJOR=18`.
It compiles the solver, assembles the module, repeats the build with warnings
as errors, runs the three suites and `npm test`, records the SHA-256 of what it
built, and uploads the artifact the other jobs take. The `sanitize` job runs
`test/native/check.sh`.

The `workflows` job runs [zizmor](https://docs.zizmor.sh/audits/) over the
workflows and `.github/dependabot.yml` and fails on any finding. It then runs
`gh actions-lock --verify`, which fails when `.github/workflows/actions.lock`
disagrees with a `uses:` line or a locked commit no longer verifies upstream.

A `uses:` line names an exact tag, such as `actions/checkout@v7.0.1`.
[`actions.lock`](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles)
records the commit each tag resolved to, and the commits of the actions those
call, and the runner executes the recorded commit even after the tag moves.
After changing a `uses:` line, run
[`gh actions-lock`](https://github.com/github/gh-actions-lock) and commit the
lockfile with it. Dependabot proposes an action release once it is 7 days old
and regenerates the lockfile entry in the same pull request.

`ACTIONS_LOCK_VERSION` in `build.yml` is the version of `gh actions-lock` the
job installs, and Dependabot does not update it. The job writes a warning when
a newer release has been out for the cooldown `dependabot.yml` sets; raise the
version by hand and rerun `gh actions-lock`.


## Releases

Set `version` in `package.json` to the version being released. `build.sh`
stamps it into `ANTIBOT_VERSION`, and the workflow refuses a tag that does not
match it.

Run the `release` workflow from the Actions tab with the tag: for version
`0.1.0` in `package.json` the tag is `v0.1.0`. The version has no prefix and
the tag for it does. It builds, tests and runs the module under nginx, then attaches `antibot.js`
and nothing else: the solver is embedded in it. The SHA-256 is in the notes.

Before it publishes, the `publish` job signs a
[SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation for
`antibot.js` with
[`actions/attest`](https://github.com/actions/attest). The signing certificate
is a short-lived one that [Sigstore](https://www.sigstore.dev/) issues to the
workflow run. The job then runs the provenance check that
[installation](installation.md#the-module) gives, and publishes only if it
passes. After publishing it runs the release check from the same page, which
fails unless the repository has immutable releases enabled. Releases run one
at a time, and a started one is never cancelled.
