# SDK repository conventions

Each language owns one `guardfulai-<language>` repository, with independent native
packaging, tests, dependency locks, versioning, changelog and registry releases.
Language libraries consume the public HTTP contract; they do not share a runtime,
require sibling checkouts or import another language's client implementation.

The JSON cases in `tests/fixtures` describe synthetic public wire behavior.
`contracts.json` records their format, stable case names and SHA-256 digests.
Other language clients may adopt reviewed snapshots as test data. Changes require
explicit fixture updates and compatibility tests; never fetch mutable fixtures at
runtime or silently accept malformed responses. These fixtures specify outcomes,
not backend implementation. SDK version and HTTP schema versions remain separate.

Each SDK maintains a clean source archive, minimal runtime artifact, safe examples,
least-privilege registry publishing workflow and independent security reporting.
Release source and artifacts must be public-safe, with no machine-local state.
