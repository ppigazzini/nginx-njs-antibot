# Security policy

## Reporting

Report a suspected vulnerability through
[private vulnerability reporting](https://github.com/ppigazzini/nginx-njs-antibot/security/advisories/new).

Include the version from the `ANTIBOT_VERSION` line of the module, the
configuration values that differ from the defaults, and a request that
reproduces the behaviour.

## Scope

A report is in scope when it shows one of:

- A request that `check()` answers with 204 without a nonce whose digest meets
  the difficulty for the identity and slot of the request.
- A challenge that is predictable, or reusable across identities or beyond the
  slot after the one it was issued for.
- Input that makes `check()` or `serve_challenge()` throw, or that costs the
  server work out of proportion to its size.
- A solver that returns a nonce the verifier rejects, or reads or writes
  outside the memory it exports.

[docs/security.md](docs/security.md) states the properties the gate holds and
the two that bound it: a solved cookie admits unlimited requests until its
slot expires, and difficulty applies equally to visitors and attackers.

## Supported versions

Fixes land on `main`. Build from there, or take the next
[release](https://github.com/ppigazzini/nginx-njs-antibot/releases).
