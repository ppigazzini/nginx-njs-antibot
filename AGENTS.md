# AGENTS.md

## References

Read `docs/README.md` for the documentation index and `docs/references.md`
for the sources it relies on.

Use these upstream sources:

- njs: [documentation](https://nginx.org/en/docs/njs/),
  [reference](https://nginx.org/en/docs/njs/reference.html)
- SHA-256: [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- Multi-buffer SIMD hashing:
  [Gueron and Krasnov, IACR 2012/371](https://eprint.iacr.org/2012/371.pdf)
- Fast JavaScript:
  [V8 performance tips](https://web.dev/articles/speed-v8)
- Technical writing:
  [Google developer documentation style guide](https://developers.google.com/style),
  [Microsoft Writing Style Guide](https://learn.microsoft.com/en-us/style-guide/welcome/)
- Commit messages:
  [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)

## Writing

These rules cover documentation, code comments and commit messages.

- State facts. Give the measured number where one exists.
- Use the present tense, the imperative mood and the positive form.
- State the contract first.
- Delete every sentence that carries no fact.
- Use ASCII.

Describe what the code does. Omit alternatives it does not use, history,
changelogs, migration notes, meta commentary, and instructions that assume a
layout the reader may not have.

`docs/decisions.md` is the exception, and the only one. A question that has
been settled goes there with the ground it was settled on, so it is answered
once rather than argued again. Nothing else carries alternatives.

## Documentation

Keep the description and the links in `README.md`. Keep prose in `docs/`.
Link nginx and njs upstream. Record a settled question in
`docs/decisions.md`.

Each fact has one home. Where another page needs it, link rather than restate:
a fact written twice drifts.

## Code comments

State what the code does and why.

## Tests

- An assertion is finished when a normal run shows it executing against the
  case it is written for. Fault injection shows the harness reports a failure;
  it does not show the branch is reachable. Where a run can report that a
  property never executed, make it fail.
- A bound on one attacker-controlled input applies to every input its function
  reads.
- A finding about the test harness is a cleanup unless it hides a defect in
  `src/`.
- Assert on cost growth with input size, not on a ratio against a small input:
  a fixed residual reads as a large ratio on a fast machine.

## Commits

Follow Conventional Commits. Credit the author only: add no LLM co-authorship
or attribution trailers.
