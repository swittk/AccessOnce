# AccessOnce

AccessOnce is a small authorization kernel for applications that want fine-grained access control without putting a policy interpreter, database lookup, or framework dependency on every request.

The whole mental model is four things:

1. **Catalog** — permission names, parent shortcuts, implications, and which scope dimensions each leaf can use.
2. **Grant** — editable authority such as “read records in site A”.
3. **Snapshot** — the immutable result of compiling all grants for one actor.
4. **Decision** — `can()`, `allowedValues()`, or `queryPlan()` over that snapshot.

The rule is **compile cold, evaluate hot**. Normal decisions are synchronous in-memory lookups.

## The normal path

Most applications with dotted permission names can define everything in one place:

```ts
import { createHierarchicalAccess } from "@accessonce/core";

const access = createHierarchicalAccess({
  catalogId: "my-app",
  catalogVersion: 1,
  compilerVersion: 1,
  wildcard: "*",
  permissions: ["*", "record", "record.read", "record.write"],
  leaves: ["record.read", "record.write"],
  scopeDimensions: {
    "record.read": ["location", "resource"],
    "record.write": ["location", "resource"],
  },
  implies: {
    "record.write": ["record.read"],
  },
});
```

Compile editable authority once:

```ts
const snapshot = access.compile({
  grants: [
    {
      permission: "record.read",
      scope: {
        location: { kind: "ids", ids: ["site-a"] },
      },
    },
  ],
});
```

Then application code reads plainly:

```ts
access.can(snapshot, "record.read", { location: "site-a" }); // true
access.can(snapshot, "record.read", { location: "site-b" }); // false
```

That is the common case. Storage, SQL, REST, IPC, React state, and relationship graphs are not part of that decision.

## Temporal grants without a timed hot path

A grant may be timeless or active in one or several half-open windows. `startsAtEpochMs` is inclusive and `endsAtEpochMs` is exclusive:

```ts
const snapshot = access.compile({
  grants: [{
    permission: "record.read",
    scope: { location: { kind: "ids", ids: ["site-a"] } },
    validity: [
      { startsAtEpochMs: january1, endsAtEpochMs: february1 },
      { startsAtEpochMs: march1 },
    ],
  }],
});

const evaluation = access.evaluateAt(snapshot, requestTime);
evaluation.can("record.read", { location: "site-a" });
```

Compilation stores timeless grants separately from a compact unique temporal-grant table and transition deltas. `evaluateAt()` keeps a per-snapshot transition cursor in a `WeakMap`. Calls inside the same interval reuse the already-materialized evaluator; crossing a boundary applies only the crossed deltas and materializes the next effective state once. Historical/test callers may move backwards and the deltas are reversed.

`access.can(snapshot, ...)` and `access.evaluate(snapshot)` remain deliberately timeless: they never read a clock, inspect the timeline, or pay a temporal branch. Use `evaluateAt()` whenever timed grants should contribute authority. The returned evaluation exposes `validFromEpochMs` / `validUntilEpochMs` for callers that want to cache one request/session evaluation explicitly. No scheduler is required for snapshot correctness.

## Query and UI projections

Sometimes the application does not have a particular row yet. It needs to ask what scope is safe to expose or put into a database predicate:

```ts
access.allowedValues(snapshot, "record.read", "location");
// { kind: "some", values: ["site-a"] }
```

Projection options say what the backend representation can actually express:

```ts
access.allowedValues(snapshot, "record.read", "location", {
  requireUnrestricted: ["resource"],
});
```

`context` filters by row facts that are already known. `requireUnrestricted` means a matching grant must not depend on that dimension. `requireRestricted` selects grants that explicitly depend on it. Direct `can()` remains fail-closed when required context is missing.

For database adapters, `queryPlan()` returns correlated OR-of-AND clauses rather than flattening scopes into unsafe cross-products:

```ts
const plan = access.queryPlan(snapshot, "record.read");
```

The database adapter decides how that becomes SQL, a query builder, a document store, or something else.

## Custom permission graphs

If permission hierarchy is not string-prefix based, use `createAccess()` and provide an explicit `includes(granted, requested)` rule. The runtime and snapshot model stay the same.

## Code map for new contributors

If you are new to AccessOnce, the source has a deliberately boring reading order:

- `src/access.ts` — start here; this is the small application-facing facade.
- `src/catalog.ts` — validates permission definitions once at startup.
- `src/compiler.ts` — turns editable grants into immutable actor snapshots and compact temporal transitions.
- `src/evaluation.ts` — binds snapshots and advances/rewinds temporal transition cursors outside the timeless hot evaluator.
- `src/sources.ts` — additive role/profile/direct-source composition plus cold-path provenance.
- `src/runtime.ts` — the performance-critical in-memory evaluator and projection logic.
- `src/client.ts` — frontend/session snapshot lifecycle over any transport.
- `src/control-wire.ts` — reusable optimistic-concurrency read/mutation wire for admin editors.
- `src/control.ts`, `adapters.ts`, `relationship.ts`, `publication.ts` — optional backend/query/object-ACL/durability boundaries.
- `src/react.ts` and `src/authzen/` — optional React and standard remote-decision integrations.

Application developers normally need `createHierarchicalAccess()` plus `access.compile()` / `access.can()`. The lower-level constructors remain public for unusual graphs and existing persisted formats, but they are not the recommended starting point.

## Additive sources and explanations

Roles, profiles, groups, and direct grants are usually application-owned names for **additive grant sources**. AccessOnce does not impose a role/profile schema; `compileSources()` composes any named source sets with exactly the same authorization semantics as a flat union and returns provenance separately for admin/editor explanations:

```ts
const preview = access.compileSources({
  sources: [
    { id: "profile:reviewer", grants: reviewerGrants },
    { id: "profile:site-a", grants: siteAGrants },
    { id: "direct", grants: userGrants },
  ],
});

access.can(preview.snapshot, "record.read", { location: "site-a" });

for (const contribution of preview.contributions) {
  console.log(contribution.grant, contribution.sourceIds);
}
```

The runtime snapshot does **not** store profile/role names or origin metadata. Provenance is cold-path editor/audit data, so normal request checks keep the same compact snapshot and hot evaluator. Composition is a union: one restricted source never narrows authority granted by another unrestricted source. Resource-specific restrictions belong in scopes, relationship ACLs, or domain policy rather than negative-profile precedence.

## Application integration planes

AccessOnce deliberately separates three different kinds of integration instead of pretending they are one transport:

### 1. Backend authority/control plane

`createAccessControlPlane()` wraps the deny-first publication protocol around any versioned application source. The source can be assignments + profiles, roles, tenant policy, or another app-owned model; AccessOnce does not require a database schema.

```ts
const control = createAccessControlPlane({
  access,
  adapter: myDurableStore,
  compileSource(source) {
    return { grants: source.grants };
  },
});

await control.replace({
  subjectId: "alice",
  expectedRevision: "41",
  source: nextAssignment,
});
```

Applications that already persist their own runtime snapshot shape use the lower-level `createAccessPublicationControlPlane()`. It keeps the same lock → deny → source CAS → final snapshot protocol while the application owns how its deny/final snapshots are built:

```ts
const control = createAccessPublicationControlPlane({
  adapter: myDurableStore,
  publication: {
    deny({ current }) {
      return makeDeniedSnapshot(`pending:${current.revision}`);
    },
    compile({ subjectId, source, sourceRevision }) {
      return compileMyExistingSnapshot(subjectId, source, sourceRevision);
    },
  },
});

const published = await control.replace({ subjectId, expectedRevision, source });
console.log(published.revision, published.snapshot);
```

The control plane returns the committed revision separately from the snapshot, so application-owned snapshot formats do not need to embed AccessOnce metadata. This is the publication-side equivalent of `access.adapt(...)`: existing snapshot formats do not need to be replaced just to reuse AccessOnce's durability protocol.

Shared-profile fan-out, occupational-role migration, and infrastructure gateway roles are application concerns: identify the affected subjects and rematerialize them through the app's efficient storage path rather than making AccessOnce understand that backend.

### Frontend authority editing

The recommended admin/editor wire is `@accessonce/core/control`. It is transport-neutral like the snapshot client: REST, RPC, IPC, or another application transport only has to carry the JSON DTO. The backend remains authoritative and validates every permission/scope against the catalog before mutating durable source rows.

Direct grants have a built-in batch protocol:

```ts
import { createAccessGrantControlClient } from "@accessonce/core/control";

const grants = createAccessGrantControlClient({
  transport: {
    read(request, signal) {
      return myRpc.getUserAccess(request, { signal });
    },
    mutate(request, signal) {
      return myRpc.mutateUserAccess(request, { signal });
    },
  },
});

const current = await grants.read({ subjectId: "alice" });

// One exact scoped grant.
await grants.add({
  subjectId: "alice",
  expectedRevision: current.revision,
  values: {
    permission: "record.read",
    scope: { location: { kind: "ids", ids: ["site-a"] } },
  },
});

// Several grants in the same operation.
await grants.add({
  subjectId: "alice",
  expectedRevision: "42",
  values: [grantA, grantB, grantC],
});

// Remove all direct assignments for several permission nodes.
await grants.removePermissions({
  subjectId: "alice",
  expectedRevision: "43",
  values: ["record.read", "record.write"],
});
```

`read()` returns the editable direct grants plus the optimistic-concurrency revision. `add` and exact `remove` accept either one grant or an array. `removePermissions` accepts one permission or many. `replace` replaces the whole direct-grant set. `mutate()` can send several different mutations in one ordered atomic request, all guarded by the same `expectedRevision`. Exact removal compares normalized permission+scope meaning, so `{location: ["a", "b"]}` and `{location: ["b", "a"]}` identify the same grant.

Applications may extend the generic `AccessControlMutationRequest<Mutation>` / `AccessControlMutationTransport<Mutation, Response>` envelope with app-specific mutations such as profile IDs or tenant memberships. AccessOnce deliberately does not invent a universal `profile` or `role` database schema. The built-in direct-grant service can map its grant list into any larger application source through `AccessGrantSourceAdapter`.

High-cardinality explicit object ACLs use `AccessRelationshipAdapter` for checks and the optional `AccessRelationshipMutationAdapter` for batched `add`/`remove` mutations. They do not inflate actor snapshots.

### 2. Effective-snapshot client transport

`@accessonce/core/client` owns frontend/bootstrap lifecycle without choosing REST, RPC, IPC, or push technology:

```ts
const accessClient = createAccessSnapshotClient({
  transport: {
    async read(userId, signal) {
      return myRpc.getEffectiveAccess(userId, { signal });
    },
  },
});

await accessClient.setSubject(currentUserId);
```

The client clears authority while loading, suppresses late responses from a prior login/session, retains bootstrap errors for diagnostics, and can subscribe to transport invalidations. It is also structurally compatible with the React external-store binding. A backend may obtain the same snapshot from a user field, database query, Cloud function, REST endpoint, or IPC call—the lifecycle contract is unchanged.

The compiled snapshot itself is the recommended snapshot wire DTO; AccessOnce does **not** invent a second proprietary HTTP authorization protocol around it. Server-side authorization must still use a trusted server-owned snapshot rather than trusting the UI copy.

### 3. Remote authorization decisions

When the enforcement point should ask a remote PDP rather than receive a local snapshot, use the standard AuthZEN adapter below.

## Standard wire interoperability: AuthZEN

AccessOnce ships the recommended remote authorization boundary under `@accessonce/core/authzen`. It implements the final **OpenID AuthZEN Authorization API 1.0** wire shapes without putting HTTP into the local evaluator.

A server can expose an existing AccessOnce evaluator as a framework-neutral PDP:

```ts
import { createAccessOnceAuthZenPdp } from "@accessonce/core/authzen";

const pdp = createAccessOnceAuthZenPdp({
  evaluator: access,
  loadSnapshot: ({ id }) => loadCompiledAccessForUser(id),
  mapEvaluation(request) {
    if (request.action.name !== "record.read") return undefined;
    const location = request.resource.properties?.location;
    if (typeof location !== "string") return undefined;
    return { permission: "record.read", context: { location } };
  },
});

const decision = await pdp.evaluate(jsonBody);
```

For the PEP/client side, `createAuthZenHttpClient()` uses the standard `/access/v1/...` HTTPS+JSON paths. `discoverAuthZenHttpClient()` resolves `/.well-known/authzen-configuration`, honors advertised endpoints, supports single and boxcar evaluation plus subject/resource/action search, and validates `X-Request-ID` echo when the caller supplies one. Authentication remains application-owned through ordinary request headers.

The AuthZEN adapter is deliberately a subpath: importing `@accessonce/core` never imports fetch, HTTP code, or remote-policy machinery. Local `can()` stays the primary zero-I/O path.

## What the core owns

- explicit permission catalogs and assignment-only parent nodes;
- implication expansion on the cold path;
- deterministic versioned effective snapshots;
- arbitrary scope dimensions;
- fixed-id scopes and subject-relative scopes such as `own assignee`;
- synchronous in-memory `can`, `hasAny`, allowed-value, and query-plan evaluation;
- correlated OR-of-AND query plans so `(location A, resource X)` never broadens into `(A|B) × (X|Y)`;
- fail-closed source/snapshot publication helpers;
- optional explicit-object relationship checks;
- adapters for an existing compiled snapshot shape;
- SSR-safe React bindings under `@accessonce/core/react`; apps may keep their own Zustand/Redux/etc. facade when it is already more ergonomic.

## What the core deliberately does not own

AccessOnce does not know a database, ORM, application transport, relationship graph, or an application's occupational roles. Those are adapters or application policy.

High-cardinality ACLs also do **not** belong in actor snapshots. A confidential record may require `reader`, `group-member`, a named user, a group, or a role relationship through `AccessRelationshipAdapter`. Normal records still use only the cheap compiled check and perform no adapter I/O. `authorizeAccessMany` filters locally first and uses `checkMany` when a remote relationship adapter provides it, so one page does not require one wire round-trip per record.

### High-cardinality object ACL composition

Relationship support is deliberately capability-based rather than a required resource framework:

- `check` / `checkMany` authorize objects already in hand;
- `constrainQuery` is an optional **database-pushdown** capability for large collections;
- `listSubjects` is an optional object-centered read for ACL editors;
- `mutate` applies exact `add`, `remove`, and `set-unrestricted` changes;
- `createAccessRelationshipControlClient()` and `createAccessRelationshipChanges()` provide transport-neutral controlled-editor ergonomics under `@accessonce/core/control`.

`constrainQuery` intentionally has **no fallback** to “list every accessible resource id” or “fetch rows and filter in JavaScript.” At million-row scale that fallback can turn an authorization abstraction into a scan. Backends should implement the strategy they are good at: SQL `EXISTS`/joins, native database/object ACL predicates, a materialized authorization index, or another index/search-native filter. A relationship graph service can still use `checkMany` for bounded pages; wide object enumeration is a backend-specific choice, not a hidden AccessOnce behavior.

An ACL editor has an explicit `unrestricted` flag in addition to its principal list. This distinguishes an ordinary/open resource from a deliberately restricted resource whose current reader set is empty. The generic model therefore stays composable without inventing document fields, profile semantics, or a universal relationship database.

## Bring your own storage and query layer

`AccessQueryPlan` is an OR of correlated AND clauses. A database adapter translates that plan into its own query builder. AccessOnce never imports the database SDK.

Applications that already have a compact materialized snapshot can use `createAdaptedAccessEvaluator`. The adapter is consulted once per snapshot object to build the generic runtime index; repeated hot checks stay in memory. Snapshot objects are identity-immutable: if grants, generation metadata, or subject attributes change, publish a new object rather than mutating one that has already been checked. AccessOnce captures fixed-id Sets and subject-relative values together when the object first enters the cache.

Catalog scope metadata is for assignment editors and adapter validation. The compiler trusts strongly typed/adapted grants instead of revalidating that metadata on every compile. An unexpected extra scope only narrows a grant; boundary adapters remain responsible for rejecting bad administrative input.

## Security boundary

AccessOnce decides over a **trusted, server-owned compiled snapshot**. A client UI may receive that snapshot for rendering guards, but client-side checks are never backend authority. Do not accept a snapshot authored or modified by the requesting client and then use it to authorize server work.

Catalog callbacks (`includes`, dynamic `scopeDimensions`) are startup policy and must be pure/stable. `defineAccessCatalog` snapshots caller-owned arrays so later array mutation cannot silently change a live catalog.

## Publication safety

`publishAccessChange` writes deny-all before mutating the durable authority source:

```text
old source + old snapshot
        ↓
old source + deny snapshot
        ↓
new source + deny snapshot
        ↓
new source + compiled new snapshot
```

A crash may temporarily deny a user. It must never preserve authority that the durable source has already removed. `recoverAccessSnapshot` repairs a deny/stale snapshot from the current source. The protocol is model-checked in `formal/Publication.tla` and covered by crash-injection tests.

## Performance

Canonical compiler output is frozen and the runtime index is WeakMap-cached by snapshot identity. BYO adapters must likewise replace snapshot objects instead of mutating an already-indexed object. Fixed-id selectors become Sets once. When one permission has several scoped grants, AccessOnce also builds a cold candidate bucket on the most selective scope dimension so `can()` skips unrelated grants without allocating. `can()` performs a permission Map lookup followed by straight loops and Set membership checks. It performs no I/O, policy parsing, parent walking, sorting, or array-pipeline work.

`pnpm perf` runs a repeatable hot-check gate. Performance regressions are treated as package regressions.

## Assurance

`pnpm assurance` runs TypeScript checks, source/JSDoc guards, unit/crash tests, TLC, formal-to-implementation binding checks, ESM/CJS builds, and the hot-path benchmark.
