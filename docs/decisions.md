# Decisions

Questions that have been settled, and the ground they were settled on. Each
entry exists because the question was raised more than once, or is the kind
that will be. A decision here is not permanent: it is a record of what was
known when it was taken.

## Identity

**The three identity fields are joined by `|` and not escaped.** For one
address, `User-Agent: X|Y` with `Accept-Language: Z` and `User-Agent: X` with
`Accept-Language: Y|Z` produce the same key. The collision needs the same
address, so it is one client colliding with itself, which wins it nothing.
Escaping the separator would change every key and invalidate every outstanding
cookie. [Security model](security.md) states the ambiguity.

**An empty address and an absent address are the same identity.** Neither
parses, both are kept whole, and nothing distinguishes a client that sent no
address from one that sent an empty one.

**Each field is cut to 256 characters, and that is a collision the invariant
allows.** Two clients whose fields agree to 256 characters share an identity.
Real values are far shorter, and the alternative is letting a large header buy
a large HMAC.

**A translated address is not folded to its /64.** `64:ff9b::/96`,
`64:ff9b:1::/48` and Teredo's `2001::/32` hold one IPv4 client per address. Two
IPv4 clients of one translator, with one User-Agent and Accept-Language,
shared a challenge, and a cookie solved by one was accepted for the other. The
well-known prefix is reduced to the IPv4 address it carries, so a client
reaching the site over IPv4 and through the translator keeps one identity.
The local-use prefix embeds the address where the operator's prefix length
puts it, which the module cannot know, so it and Teredo are kept whole.

## The cookie

**A cookie is accepted for its own slot and the one after it.** That is what
makes `COOKIE_TTL` twice `WINDOW_SIZE`. Shortening the lifetime further is
tidiness, not security: it changes nothing an attacker can do.

**At most `MAX_COOKIE_CANDIDATES` cookies under the name are verified, and the
rest are not read.** Capping the number tried cannot lock a visitor out: the
`__Host-` prefix forces `Path=/`, so a browser holds one cookie under the
name, and only something else sends more. Raising the cap to accommodate a
browser with many stale cookies would be accommodating a case that cannot
happen.

**There is no re-screening.** A re-screen answered a valid cookie with 401
for a fraction of navigations. It was optional for the client, which chooses
`Sec-Fetch-Dest`, and it revoked nothing: the page it served carried the
challenge the cookie already answered, because the challenge is a function of
the identity and the slot. At a rate of 0.5 over 2,000 navigations, a client
that resent its cookie made 2.02 requests per navigation and computed no hash
after its first solve, while a browser that ran the page solved the same
challenge again. Binding a re-screened cookie needs per-identity state in the
zone, and the zone is per host, so a client that reaches another host escapes
it. The cost of reusing a cookie is the rate limit, which belongs in
`limit_req`.

**The challenge page is never cached.** It carries a per-identity challenge,
so a shared cache entry would hand one identity's challenge to another.

## The gate

**The difficulty in the page is advisory, and the server verifies with its
own.** `pow_valid` reads `POW_BITS_EFFECTIVE`, and a cookie carries a slot and
a nonce and no field for a difficulty, so nothing a request sends selects the
bar it is judged against. A client that solves at fewer bits than the server
enforces produces a nonce the server refuses. One that solves at more produces
a nonce the server accepts, for more work than it needs, unless the nonce is
at or above the server's cap: lowering `POW_BITS` by k bits refuses about
`e^(-64/2^k)` of the cookies solved before, 1.8% at k=4, 13.5% at 5 and 36.8%
at 6, and each of those visitors solves once at the new difficulty.

The page ships the value because `solve(start, count, bits)` has no other
stopping condition, and `cap` and `expected` state the same number again.
Withholding it buys nothing: the [security model](security.md) rests on the
HMAC key being the only secret, and the page ships the algorithm, the
challenge and the solver in any case.

**No prefilter runs before verification.** A prefilter needs state per
client, and the module's only state is its counters. Verification is a small
part of what a request costs under njs, where a core serves about 2,700
challenged requests a second ([cost per request](security.md#cost-per-request)),
and limiting a client's rate belongs to `limit_req`.

**A challenged request answers 200, not 401.** `error_page 401 = /...` takes
the status from the location it forwards to. A browser renders the page either
way; the cost is that a health check reading the status line cannot tell a
serving deployment from a challenged one.
[Configuration](configuration.md) says so and says what to do instead.

**The module sends no `Content-Security-Policy` of its own.** The page it
serves needs `'unsafe-inline'`, `'unsafe-eval'`, `'wasm-unsafe-eval'` and
`blob:` to run at all, so a policy tight enough to be worth sending would have
to permit what it exists to forbid. A site that sets one must relax it at the
challenge location, which [installation](installation.md) states and the
example carries.

**`SITE_NAME` is escaped for `&`, `<`, `>` and `"`, and not for `'`.** It is
inserted as element text, never into an attribute.

## The solvers

**Difficulty is not the lever against a distributed fleet.** Raising
`POW_BITS` multiplies the cost for visitors and attackers alike, and the
visitor runs the slower hardware. Rate limiting on a key that is not per-IP is
the lever, and it belongs in `limit_req`.

**`POW_MAX_ITERATIONS` is 64 times the expected work at every difficulty.** It
is derived from `POW_BITS`, not fixed, so no difficulty makes the cap
unreachable. A correct client exhausts it with probability `e^-64`.

**`pow_solve` takes the nonce base as a `double` and is not guarded against a
negative or a NaN.** Its only caller is the page this module emits, which
walks a non-negative integer range it computes itself, and wasm traps rather
than corrupting memory.

**The JS fallback is a second implementation, not a scalar wasm build.** A
module containing SIMD instructions fails validation as a whole on an engine
without SIMD, even where those functions are never called.

**An invalid setting falls back and is never kept.** A setting is the first
valid value among the environment, the constant in the source and the
built-in value. A source constant was once kept however wrong:
`WINDOW_SIZE = 0` put `slot=Infinity` in the page and locked out every
visitor. `Number()` read whitespace as 0, accepted `0x18` as 24 unreported,
and turned `22.5` into a difficulty of 16, 64 times easier than the default.
A number is now decimal digits and nothing else.

**A value is checked by the characters it holds, never by an anchored
pattern.** njs compiles a RegExp with PCRE2 and without
`PCRE2_DOLLAR_ENDONLY`, so `$` also matches before a final newline. Under
nginx 1.24.0 and njs 0.8.2, `/^[0-9]{1,12}$/` took `"123\n"`, and node, where
the module suites run, refuses it. A cookie name ending in a newline passed,
wrote no warning, and ended the page script's string literal, so the page
failed for every visitor without a cookie; `?rate=123%0A` split a log line. A
Kubernetes ConfigMap written with a `|` block ends a value that way. Only the
nginx lane can show such a check refusing, so it carries the cases.

**`COOKIE_TTL` defaults to twice the window in effect.** The constant was
`2 * WINDOW_SIZE`, which follows the source window and not the environment's,
so `ANTIBOT_WINDOW_SIZE=86400` alone was reported as a lifetime below twice
the window. `null` means twice the window the module runs with.

**A configuration warning is written once per set, through the shared
zone.** njs runs the module's top-level code again for every request: under
njs 0.8.2 a constant computed there held a new value on each request, on each
worker and after a reload. Anything a request writes to a module variable is
gone before the next one reads it, so draining a list of warnings repeats
them on every request, at `error`, which is nginx's default level. The zone
records a digest of the warnings written. A flag recorded only that some
warning had been written, and the zone outlives a reload, so a bad value a
reload brought in was used silently until a stop and a start. With the
digest, a reload that changes the warnings writes them, and the same warnings
after a reload are not written again.

## The build

**No binary is committed.** `dist/` is a build product. A committed wasm could
not be checked against the source that claims to produce it, and a reader
would have to trust it. The release attaches the artifact CI built, with its
SHA-256 in the notes and a signed build provenance attestation.

**The page, the worker and the JS solver are files, not string literals.**
`node --check` validates a file and cannot validate a string inside one, so a
quote or a brace wrong in the page reached a browser rather than the build.
`build.sh` parses each before writing it in.

**The page is a template split into parts, not substituted into.** The
template is `src/page.html`, 4.6 KB, and the solver goes in as a value, so
the split scans the template and never the 20 KB page. Substituting into the
assembled page would put its length, which is mostly the embedded solver,
into the cost of serving one. node splits once; njs runs the module for every
request, so there the split runs per request.

**The template is split with `indexOf`, not a regular expression.** njs runs
the module's top-level code for every request that reaches it, and node,
where the suites and `test/bench/cost.mjs` run, evaluates it once. With
`PAGE_TEMPLATE.split(/(__ANTIBOT_[A-Z0-9_]+__)/)` at the top, `check()` cost
8.7 ms a request under nginx 1.24.0 and njs 0.8.2, where node measured
0.13 us; with the `indexOf` scan, which gives the same parts for the
template, it costs 129 to 137 us (`test/bench/njs-cost.mjs`).

**The tag is `v` and the version.** For version `0.1.0` in `package.json` the
tag is `v0.1.0`.
[SemVer 2.0.0](https://semver.org/#is-v123-a-semantic-version) states that
`v1.2.3` is not a semantic version and illustrates its tag as
`git tag v1.2.3`. Go modules require the prefix on tags and release tooling
defaults to it, so the tag carries it and the manifest does not.

**The release creates its tag before it creates the release.** A release
created with `--target` names a commit by hash. A push that lands while the
run is in flight can leave that commit on no branch, and GitHub answers 403
for a target it cannot reach. Creating the tag first makes the commit
reachable, so the release is made against a ref rather than a hash. The tag is
created through the API with the job's token, so checkout keeps no
credential.

**A release is refused rather than corrected.** The tag, the commit and the
version stamped into the artifact must already agree. Publishing onto a tag
that names another commit would attach this build to that one, because
`gh release create --target` applies only when the tag is new.

**CI builds with clang 18 from the Ubuntu 24.04 archive.** One source gives a
different `solve()` under each clang major, and an unpinned `clang` follows
the runner image. With the gather written as explicit lane loads, the three
compilers measured run within a few percent of each other: medians of 8.96,
9.00 and 9.13M hashes/sec for clang 18, 8.87 to 9.04 for clang 20 and 9.01 to
9.06 for clang 23, interleaved on one core under node 26.4.0. Rates on that
machine move by a few percent between sessions, so builds are compared within
one run. clang 18 is the
compiler every release has shipped, its archive package is signed by Ubuntu
and installed on the runner without another source, and it rebuilds the
v0.0.2 wasm byte for byte. apt.llvm.org packages carry a snapshot date and
change within a major.

**Provenance is signed in the `publish` job, not in `build`.** `build` runs
for every push and pull request. Signing there needs `ci.yml` to grant
`id-token: write` to every run, and signs builds that are never released. The
`publish` job signs the one file it attaches, after the guards pass, and one
guard compares that file with the SHA-256 `build` recorded: every job in the
run holds a token that can replace an artifact.

**A release is made from `main` and verified against `main` exactly.**
`--signer-workflow` names a workflow and no ref, so a certificate from a run
on any branch matched it, and gh before 2.102.0 matched it as a prefix, so
`release.yml.x.yml` matched too. The repository has no branch protection, so
any branch could have published. `--cert-identity` with the workflow and
`refs/heads/main` is an exact match on every gh version, and `publish`
refuses another ref.

**Releases are not immutable.** An immutable release cannot be corrected: its
file and tag stay, and a deleted release's tag name cannot be used again. The
release steps that sign and verify have not run yet, so the first release
would be permanent before they are proven. The provenance attestation binds
`antibot.js` to the run on `main` that built it either way; immutability
would add that the file under a tag never changes for a reader who does not
verify.

## The site

**The site is flat.** Its eight pages sit directly under `docs/` under their
own names, and the sections exist only in the nav. A link between two pages
is then the file's name, which GitHub and the site resolve alike, and moving
a page between sections changes no link. valgebra puts its 26 pages in a
folder per section; valgebra-jsonschema keeps its nine flat.

**The home page is `docs/index.md`, not `docs/README.md`.** The site serves
`index.md` as its home. GitHub shows a folder's `README.md` beside the file
list, which a reader of `docs/` loses, and keeps the index one click away.

**Zensical builds the site, from a lock.** Zensical, the successor the
Material for MkDocs team maintains, reads `mkdocs.yml` as written and has
search and the `llms.txt` export built in, so the site needs one package and
no plugin. `uv.lock` pins it and its dependencies by hash, and a group in
`pyproject.toml` declares it without making the repository a Python package.

**The site is published by the Actions deployment, not a `gh-pages`
branch.** The built site is an artifact of the run that built it and is
deployed over OIDC through the `github-pages` environment, so no branch holds
build output and no token can push one. It deploys from `main` alone.

## Workflows

**A `uses:` line names an exact tag, and `actions.lock` holds the commit.** A
commit SHA in a `uses:` line fixes that action and not the actions it calls.
The lockfile records both, and the runner executes the recorded commit after
a tag moves. The tag is exact, `v7.0.1` and not `v7`, because
`gh actions-lock` does not detect a lockfile change that moves a floating ref
back to an older commit in its history.

**A newer `gh actions-lock` release warns and does not fail.** Dependabot has
no ecosystem for a gh extension, and the extension ships no action a `uses:`
line could name. A failure would stop every push and pull request for a
release none of them made.

**zizmor fails the job and uploads nothing to code scanning.** Every other
check in CI is a job that fails. In code scanning mode zizmor-action does not
fail on a finding, and the upload needs `security-events: write` from both
callers of `build.yml`.

## Reporting

**The page reports through a beacon to a gated location, not a second
cookie.** `location.reload()` cannot carry a header. A second cookie travels
on every request to the site, so it puts another attacker-controlled input on
the gated path, and counting it once per solve needs state. The beacon is one
request per solve and reaches `report()` only with a valid cookie. Where the
location is missing, it reaches the gated catch-all and the backend, one
request per solve.

**A solve counts as slow by the visitor's wait, not by a rate.** The page
first reported the winning nonce over the time since its workers started.
That time includes the workers' start, so a fast visitor whose nonce came
early read as slow, in a share of about start-up over `SLOW_SOLVE_SECONDS`
whatever the difficulty: 0.19% of solves with the 18 ms start measured in
Chromium 156 on the reference machine, and 1.08% with a 100 ms start, over
400,000 modelled solves. The winning nonce also counts the blocks other
workers own, so below 22 bits the figure was not a rate. The wait from
navigation is what the visitor sat through, and `performance.now()` never
runs backwards.

**A visitor with no JIT is served at the default difficulty.** Chromium with
the JIT off has no WebAssembly and runs the JS solver, where a mean solve at
22 bits takes about a minute ([difficulty](configuration.md#difficulty)).
Lowering the default for that visitor lowers it for every client. The solve
report counts the visitors on that path, `solved_js` and `solved_slow`, which
is what a change of default would rest on.

## Tests

**The SIMD solver's lead is asserted as a ratio, with a floor of 1.0.** Both
rates come from one process over interleaved batches of 4,000,000 nonces, and
the JS solver is compiled by the engine rather than by clang, so the
machine's clock and its load cancel; the ratio is not taken against a small
input. Measured one solver after the other, a CPU hog during the wasm phase
read 1.19x and failed a good build. The microarchitecture does not cancel:
CI measured 1.73 to 2.64 over 32 runs of the clang 18 build, and 1.20 on a
runner type where the JS solver ran at 8.14M hashes/sec against the 5.76M
of the others, which failed the floor of 1.4 it was first given. An `-O0`
build measures 0.15. The floor fails a SIMD solver no faster than the
fallback; a loss of a few percent is the compiler pin's to prevent, not this
check's to catch.

**The fuzz corpus cache key rotates with the run id.** GitHub states that a
cache entry cannot be changed, and a save against an existing key is skipped,
so a stable key would freeze the corpus at its first save and stop the
coverage the lane exists to accumulate. Growth is bounded by GitHub's own
eviction.

**The wasm binary is not fuzzed; the C is, through a SIMD shim.** A wasm
fuzzing harness is more new test surface than the finding justifies, and the
differential test already covers the same code against a known-good oracle.
Raised and rejected three times.

**`check()` is not fuzzed against a second implementation of the verifier.**
There is none, and writing one to fuzz against makes the oracle the thing most
likely to be wrong.

**Guards that run once are tested on every push.** A check that only executes
at release time is unproven until a release needs it, which is the worst
moment to find it inverted. `test/release/check.sh` runs the release guards
over a table of tags.

**The mutation list is fixed, not generated.** A generated set has a different
survivor list on every run, which fails at random and teaches nothing.

**Cost assertions compare growth with input size, not a ratio against a small
input.** A fixed residual reads as a large ratio on a fast machine: the same
5 us residual is 1.29x against a 19 us baseline and 2.10x against a 4.9 us
one.

**A test reads a documented number from the document rather than from the
module.** A test that takes the value it checks from the code it grades adapts
to a change instead of failing on one. The challenge page size and
`MAX_COOKIE_CANDIDATES` are read from `docs/`.

**The counters are graded by mutation, not only by assertion.** A counter that
stops counting still returns a number, so the mutation list holds defects that
stop each one and names the suite that must notice.
