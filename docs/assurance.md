# Assurance

Run `pnpm assurance` on Node 22 or newer. The command performs TypeScript/source-quality checks, executable tests, TLC, source/model binding checks, ESM+CJS builds, throughput benchmarks, and retained-memory/WeakMap-release benchmarks.

The pinned official TLA+ tools release is `v1.7.4`, SHA-256 `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`. Set `TLA2TOOLS_JAR` or place that jar at ignored `.artifacts/tla2tools.jar` locally. CI downloads the official GitHub release and verifies this digest before running formal checks.

`formal/Publication.tla` models deny-before-source publication, crashes, and recovery. `PublicationUnsafe.tla` deliberately replaces the authority source without first publishing deny-all; the formal runner requires TLC to produce the exact safety-invariant counterexample so the invariant cannot silently become vacuous. `formal/TemporalEvaluation.tla` models arbitrary forward/backward requested times over half-open temporal boundaries and checks that cursor movement, active authority, and the cached validity interval never disagree.

`test/publication.test.ts` injects crashes at the durable write boundaries. `test/query-plan-conformance.test.ts` exhaustively compares direct `can()` decisions with the generic OR-of-AND query plan over a bounded location/resource/provider domain, including correlated pairs and subject-relative scope. `test/temporal-conformance.test.ts` compares forward and backward `evaluateAt()` decisions/projections against an independent naive recompile-at-time oracle.

The formal/implementation manifest binds both publication and temporal-evaluation implementation declarations to their complete TLA models. A bound body/model change makes `pnpm assurance` fail until the pair is reviewed together and `pnpm assurance:update` records the new binding. Comments and ordinary TypeScript formatting do not change the source declaration digest.

The throughput benchmark keeps the original timeless `can()` gate and separately measures a snapshot-bound temporal decision plus the intentionally redundant `evaluateAt(snapshot, sameTime).can()` path. This guards the architectural promise that temporal support does not insert clock or interval work into the existing hot evaluator.


## Runtime memory gate

`pnpm perf:memory` creates thousands of representative eight-grant snapshots, measures serialized size, retained JS heap before and after runtime indexing, peak RSS/allocator observations, and retained heap after all snapshot references are released. RSS is reported rather than used as the primary leak signal because V8 intentionally keeps reserved heap pages after GC. The enforced gates cover wire size, retained compiled/index heap, and post-release retention.
