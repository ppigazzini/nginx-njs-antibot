# Development

## Build

```sh
./build.sh            # compile, assemble and test; needs clang with wasm32 and lld
./build.sh --no-test  # compile and assemble only
./build.sh --strict   # treat compiler warnings as errors
npm test              # the three suites, after a build
CLANG=clang-18 CLANG_MAJOR=18 ./build.sh  # the compiler CI and releases use
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

The page is a template. The module splits it on its `__ANTIBOT_*` tokens and
`build_challenge()` joins the parts with their values, so serving a page costs
a concatenation rather than a substitution over its whole length. A token with
no value is left in the page as itself, where the module suite fails on it,
rather than rendered as `undefined`. A token the module does not know is
reported in the error log.

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
SIMD solver runs no faster than the JS solver, measured in interleaved
batches in one process. It reads the wasm from the directory holding the
module it was given. The pure-JS solver is
lifted out of the built module and evaluated, so what is checked is the source
that ships.

`test/module.test.mjs` solves through real worker threads on both solver
paths, checks that one worker finds the same nonce on either, and feeds each
cookie back to `check()`. It runs the built worker against a recording
solver, so the workers' blocks cover every nonce below the cap once. It also
covers the rejection cases, the slot boundary with cookies solved one and two
slots back, the iteration cap from both sides, settings read from the
environment and from the source with every malformed value it refuses, the
identity invariant in both directions including translated addresses, the
cookie-candidate bound, the difficulty the page ships against the one the
server enforces, the level the challenge line is written at, the URI it
names, the escaping of `SITE_NAME`, the page template's tokens, the solve
report the page sends and `report()` takes, the counters, a configuration
warning written once per set, and the growth in cost with the identity
headers, the address, the cookie count and the URI. It reads the window from
`status()`, so it runs under any `ANTIBOT_WINDOW_SIZE`.

`test/mutants.mjs` grades the suites rather than the module. It holds a fixed
list of defects, each naming the suite that must notice it, writes each into
the built module and runs that suite against it. A mutation the suite lets
through is a failure. Run it with `node test/mutants.mjs [module]`.

The list is fixed because a generated set has a different survivor list on
every run. Three defects are left out because the nginx lane is what catches
them: dropping the `nosniff` header, dropping `no-store`, and checking a
value with an anchored pattern, which only njs lets match before a final
newline.

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

Serves `examples/nginx.conf.example` under a real nginx with two workers and
drives the module through njs, which is the only place it runs outside node.
The config, certificate and module go under a temporary prefix that is
removed on exit, so it needs no privilege and touches nothing outside it. It
asserts the gate, the status and headers, the documented policy, a setting
arriving from the environment, the error log and the URI it names, the
accept path, the solve report, cookie handling as nginx merges it, the
routes, the counters, that a reload keeps both the secret and the counters,
that a reload onto a bad source constant writes its warning once, and that a
setting or report argument ending in a newline is refused. njs's `$` matches
before a final newline and node's does not, so that last case runs only
here.

## Measurements

Every rate and cost in `docs/` comes from one of these. Each prints the CPU
model and the CPUs it runs on first. A per-core figure is pinned with
`taskset` to one core, or to one core and its hyperthread for a browser; the
worker scaling runs on every core:

```sh
taskset -c 2 node test/bench/rate.mjs                 # wasm, JS and OpenSSL
taskset -c 2 node test/bench/rate.mjs a=x.wasm b=y.wasm
taskset -c 2 node test/bench/cost.mjs                 # the module's work, node
taskset -c 2,6 node test/bench/njs-cost.mjs           # a request under nginx
taskset -c 2,6 node test/browser/rate.mjs <chromium>  # both solvers in a worker
node test/browser/rate.mjs <chromium> --workers 4     # four workers at once
node test/browser/page.mjs <chromium> --bits 18 --js-flags=--jitless
```

`njs-cost.mjs` starts nginx from `PATH` under a temporary prefix, with the
modules directory found as the [nginx lane](#under-nginx) finds it, and times
each handler through its own location against one njs does not run.

`test/bench/rederive.patch` is the solver without its in-place decimal
increment, the variant `docs/design.md` measures against. Build it in a
second worktree and compare the two there:

```sh
here=$(pwd)
git worktree add ../rederive && cd ../rederive
git apply test/bench/rederive.patch && CLANG=clang-18 ./build.sh --no-test
taskset -c 2 node test/bench/rate.mjs in-place="$here/dist/pow_solver.wasm" \
    rederive=dist/pow_solver.wasm
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

## The site

```sh
uv sync --locked --group docs       # the site's toolchain, from uv.lock
uv run zensical serve               # the site on localhost, rebuilt on save
uv run zensical build --strict      # what CI runs; writes ./site
```

[Zensical](https://zensical.org/) builds the pages in `docs/` into the site
from `mkdocs.yml`, which names the nav, the checks and the `llmstxt` export.
`--strict` fails on a dead link, a dead anchor, or a page in `docs/` the nav
does not list. Every page is one file directly under `docs/` and links to the
others by name, so a link reads the same on GitHub and on the site; the
sections exist only in the nav.

The build writes [`llms.txt`](https://llmstxt.org/), a manifest of the pages
in nav order with a line on each, and `llms-full.txt`, every page in full, and
serves each page as Markdown at its address followed by `index.md`. The lines
in `llms.txt` are the ones `docs/index.md` gives, set again in `mkdocs.yml`.

`pyproject.toml` declares the `docs` group and nothing else, and `uv.lock`
pins every package in it by hash. It takes a release once it is 7 days old,
as Dependabot does, which proposes updates to the lock monthly.

## Continuous integration

| Workflow | Trigger | Purpose |
|---|---|---|
| `build.yml` | `workflow_call` | six jobs: `build`, `mutants`, `example`, `sanitize`, `docs`, `workflows` |
| `ci.yml` | push, pull request | calls `build.yml` |
| `release.yml` | manual, tag required | calls `build.yml`, then publishes |
| `docs.yml` | push to `main`, manual | builds the site and publishes it to GitHub Pages |

`ci` and `release` share one reusable workflow, so a release runs exactly the
checks CI runs.

`release.yml` refuses to publish unless it runs on `main`, the tag is `v` and
a version, the tag is new or already points at the commit being released, the
tag matches the version stamped into the artifact, and the file it downloaded
has the SHA-256 the `build` job recorded. It creates the tag before creating
the release, so the commit it names stays reachable. The guards are functions
in `test/release/guards.sh`, and `test/release/check.sh` runs them over a
table of cases on every push, because they otherwise run once per release.

The `example` job runs `test/nginx/check.sh`, the [nginx lane](#under-nginx),
on `ubuntu-24.04` and `ubuntu-26.04`, under the njs each ships. It is the only
place the module runs in njs, not node. It then runs
`test/browser/page.mjs` in the runner's Chrome, once on the wasm solver and
once with the JIT off, so the page solves, sends its report and is accepted
under the documented policy in a real browser.

The `mutants` job runs `test/mutants.mjs` against the artifact the `build` job
uploaded. It is separate because it runs a suite per mutation.

The `build` job runs on `ubuntu-24.04` with `clang-18` and `CLANG_MAJOR=18`,
and fails unless the `clang-18` package is the version in `CLANG_PACKAGE`,
1:18.1.3-1ubuntu1, the one the rates in `docs/` were measured on. It compiles
the solver, assembles the module, repeats the build with warnings as errors,
runs the three suites and `npm test`, records the SHA-256 of what it built as
an output of `build.yml`, and uploads the artifact the other jobs take. The
`sanitize` job runs `test/native/check.sh`.

The `docs` job builds [the site](#the-site) with `--strict` on every push,
so a broken link fails before `docs.yml` publishes it from `main`. `docs.yml`
uploads the built site as a Pages artifact and deploys it through the
`github-pages` environment, with the token `deploy-pages` presents over OIDC;
there is no `gh-pages` branch.

The `workflows` job runs [zizmor](https://docs.zizmor.sh/audits/) over the
workflows and `.github/dependabot.yml` and fails on any finding. It then runs
`gh actions-lock --verify`, which fails when `.github/workflows/actions.lock`
disagrees with a `uses:` line or a locked commit no longer verifies upstream.

A `uses:` line names an exact tag, such as `actions/checkout@v7.0.1`.
[`actions.lock`](https://docs.github.com/en/actions/concepts/security/workflow-dependency-lockfiles)
records the commit each tag resolved to, and the commits of the actions those
call. The runner executes the recorded commit after the tag moves, while that
commit is still reachable from the tag, and rejects the run otherwise.
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
the tag for it does. Run it from `main`; it refuses any other branch. It
builds, tests and runs the module under nginx, then attaches `antibot.js` and
nothing else: the solver is embedded in it. The SHA-256 is in the notes.

Before it publishes, the `publish` job signs a
[SLSA build provenance](https://slsa.dev/spec/v1.0/provenance) attestation for
`antibot.js` with
[`actions/attest`](https://github.com/actions/attest). The signing certificate
is a short-lived one that [Sigstore](https://www.sigstore.dev/) issues to the
workflow run. The job then runs the provenance check that
[installation](installation.md#the-module) gives, and publishes only if it
passes. Releases run one at a time, and a started one is never cancelled.
