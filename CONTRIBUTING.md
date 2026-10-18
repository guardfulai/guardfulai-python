# Contributing

Install Python 3.11 or newer and uv, then run `uv sync --frozen` explicitly.
Run `make check package-check` from this repository. On Windows, run the individual
`uv run --frozen --no-sync` commands listed in the Makefile in your shell.
Build tools and dependencies must be cached by setup before offline package checks.

Tests use synthetic fixtures and HTTPX MockTransport; outbound sockets are disabled.
Do not use real credentials or a production account. Preserve public API signatures,
error privacy, strict results and retry identities. Add regression cases for behavior
changes. `uv.lock` pins development tooling; runtime users retain compatible ranges.

The sdist includes the portable test suite. Artifact acceptance installs both wheel
and sdist into fresh environments and runs that suite outside the source checkout.
Package tooling tests are tested in the source checkout. `dist/` is ignored; move
old local artifacts out of that directory before accepting intentionally changed bytes.
Never replace a published release; choose a new version for changed published code.

See [release instructions](docs/releasing.md) and [SDK conventions](docs/sdk-conventions.md).
