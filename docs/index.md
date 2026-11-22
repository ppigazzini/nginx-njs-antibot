# Documentation

A proof-of-work gate for nginx, written as an njs module. Browser-facing
routes sit behind `auth_request`, and a request without a valid cookie is
answered with a page that solves a challenge and stores one.

Get started:

- [Installation](installation.md): requirements, getting and verifying
  `antibot.js`, and wiring it into nginx

Reference:

- [Configuration](configuration.md): the contract, every setting and its
  validation, difficulty and solve times, the solve report, the counters and
  logging
- [Sources](references.md): the standards, upstream documentation and sources
  the pages rely on

Explanation:

- [Design](design.md): the algorithm, both solvers, the worker pool and the
  progress readout
- [Security model](security.md): what is secret, the solver rates, how a
  client is identified, what a request costs, and what the gate does not buy
- [Decisions](decisions.md): questions that are settled, and the ground each
  was settled on

Contributing:

- [Development](development.md): building, the test suites, the nginx lane,
  measurements, continuous integration, releases and this site

nginx and njs are documented upstream, in the
[njs documentation](https://nginx.org/en/docs/njs/).
