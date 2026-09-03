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

**The challenge page is never cached.** It carries a per-identity challenge,
so a shared cache entry would hand one identity's challenge to another.

## The gate

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

## The build

**No binary is committed.** `dist/` is a build product. A committed wasm could
not be checked against the source that claims to produce it, and a reader
would have to trust it. The release attaches the artifact CI built, with its
SHA-256 in the notes.

**The page, the worker and the JS solver are files, not string literals.**
`node --check` validates a file and cannot validate a string inside one, so a
quote or a brace wrong in the page reached a browser rather than the build.
`build.sh` parses each before writing it in.

**The page is a template split once at load, not substituted per request.**
Substituting into it on every request would put the length of the page, which
is mostly the embedded solver, into the cost of serving one.

**The tag is `v` and the version.** `package.json` holds `0.1.0` and the tag
is `v0.1.0`.
[SemVer 2.0.0](https://semver.org/#is-v123-a-semantic-version) states that
`v1.2.3` is not a semantic version and illustrates its tag as
`git tag v1.2.3`. Go modules require the prefix on tags and release tooling
defaults to it, so the tag carries it and the manifest does not.

**The release pushes its tag before it creates the release.** A release
created with `--target` names a commit by hash. A push that lands while the
run is in flight can leave that commit on no branch, and GitHub answers 403
for a target it cannot reach. Pushing the tag first makes the commit
reachable, so the release is made against a ref rather than a hash.

**A release is refused rather than corrected.** The tag, the commit and the
version stamped into the artifact must already agree. Publishing onto a tag
that names another commit would attach this build to that one, because
`gh release create --target` applies only when the tag is new.

## Tests

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
