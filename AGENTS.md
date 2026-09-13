# AccessOnce engineering rules

- Keep request-time authorization pure and synchronous. `can()` must never perform I/O.
- Spend complexity on catalog validation and snapshot compilation so the hot path stays boring.
- Storage, transport, databases, relationship graphs, and query builders are adapters. Core must not import them.
- Adapter conformance is a contract: once an adapter claims it emits AccessOnce data, core does not repeatedly revalidate it on every check.
- High-cardinality per-object ACLs stay in relationship adapters, not actor snapshots.
- Do not add steady-state legacy compatibility branches to the core. Migration belongs in adapters or one-shot migration code.
- Every named type, interface, enum, class, and function gets a `/** ... */` purpose comment.
- Weird branches and fail-closed behavior get short `//` comments where the decision happens.
- Avoid one-use tiny helpers that only hide a few obvious lines.
- Hot evaluator code must not use `map`, `filter`, `sort`, `includes`, `some`, or `every` pipelines.
- Performance regressions are correctness regressions for this package. Run `pnpm perf` when evaluator behavior changes.
- Publication changes must preserve the fail-closed TLA+ invariant: a saved runtime snapshot is never broader than the currently saved authority source.
- Treat retained-memory regressions as performance regressions. `pnpm perf` must cover throughput and memory/WeakMap release behavior.
- Keep the three integration planes distinct: backend source publication/materialization, client effective-snapshot transport, and remote PDP decisions. Do not conflate snapshot transport with AuthZEN.
- Frontend snapshot clients fail closed while loading/erroring and must suppress responses from a previous subject/session even when a transport ignores abort.
- The recommended client transport is a BYO `read`/optional invalidation contract over the versioned effective snapshot; do not import Parse, REST clients, Electron IPC, or other app transports into core.
- AuthZEN stays isolated under the `authzen` subpath. Importing the core/client evaluator must never pull HTTP/fetch behavior into local authorization checks.
