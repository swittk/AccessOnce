import type { AccessContext, AccessValidity } from "./types.js";
import type { AccessEvaluator } from "./runtime.js";

/** Principal passed to a high-cardinality relationship/ACL store. */
export type AccessPrincipal = {
  /** Application-defined principal kind such as user, team, service, or role. */
  type: string;
  /** Stable principal id inside that kind. */
  id: string;
};

/** Resource passed to a high-cardinality relationship/ACL store. */
export type AccessRelationshipResource = {
  /** Application-defined resource kind such as record or encounter. */
  type: string;
  /** Stable resource id inside that kind. */
  id: string;
};

/** One explicit principal relationship source entry, optionally active only during bounded windows. */
export type AccessRelationshipSubject = {
  /** Principal that satisfies the relation while this source entry is active. */
  principal: AccessPrincipal;
  /** Optional half-open validity windows; omitted means timeless. */
  validity?: AccessValidity | readonly AccessValidity[];
};

/** Canonical source for one resource/relation projection. */
export type AccessRelationshipSource = {
  /** True means this relation imposes no extra principal restriction. */
  unrestricted: boolean;
  /** Explicit principal source entries, including future and expired temporal entries. */
  subjects: readonly AccessRelationshipSubject[];
};

/** Effective relationship state at one instant plus the next instant at which it can change. */
export type MaterializedAccessRelationship = {
  /** Effective open/restricted state copied from the source. */
  unrestricted: boolean;
  /** Unique principals whose source entries are active at the requested instant. */
  principals: readonly AccessPrincipal[];
  /** Earliest future source boundary; omitted means this materialization is time-stable indefinitely. */
  nextTransitionAtEpochMs?: number;
};

/** Extra object-level relationship required after the cheap compiled permission check passes. */
export type AccessRelationshipRequirement = {
  /** Particular object carrying the narrow ACL. */
  resource: AccessRelationshipResource;
  /** Application-defined relationship such as reader, editor, group-member, or approver. */
  relation: string;
};

/** One relationship check sent to a bring-your-own ACL graph/store. */
export type AccessRelationshipCheck = {
  /** Actor being checked against the object relation. */
  principal: AccessPrincipal;
  /** Particular object carrying the relation. */
  resource: AccessRelationshipResource;
  /** Relationship the principal must satisfy. */
  relation: string;
  /** Optional evaluation instant for stores that enforce temporal relationships directly. */
  atEpochMs?: number;
};

/** Adapter for explicit people/groups/roles/object ACLs that are too high-cardinality for actor snapshots. */
export type AccessRelationshipAdapter = {
  /** Check one object relation. */
  check(request: AccessRelationshipCheck): Promise<boolean>;
  /** Optional bulk check used by pages that need several object-level decisions at once. */
  checkMany?(
    requests: readonly AccessRelationshipCheck[]
  ): Promise<readonly boolean[]>;
};

/** One database/query pushdown request for a relationship-governed resource collection. */
export type AccessRelationshipQueryRequest<Query> = {
  /** Existing application query to constrain in place or replace with an equivalent constrained query. */
  query: Query;
  /** Actor whose visible resource set is being requested. */
  principal: AccessPrincipal;
  /** Resource namespace represented by the query, for example document or encounter. */
  resourceType: string;
  /** Relationship required by restricted resources, for example reader or editor. */
  relation: string;
  /** Optional evaluation instant for databases that can push temporal validity into the query itself. */
  atEpochMs?: number;
};

/**
 * Optional million-row query capability for relationship backends.
 *
 * Implementations MUST push authorization into the backing query/index (SQL EXISTS/JOIN, native object ACL,
 * materialized authorization index, search filter, etc.). This contract intentionally has no fallback to
 * enumerating every accessible resource id or fetching rows and post-filtering them in JavaScript.
 */
export type AccessRelationshipQueryAdapter<Query> = {
  /** Return a query that can only yield resources visible to the principal under this relationship policy. */
  constrainQuery(
    request: AccessRelationshipQueryRequest<Query>
  ): Query | Promise<Query>;
};

/** Request for subjects explicitly represented by one resource relationship. */
export type AccessRelationshipSubjectsRequest = {
  /** Resource whose ACL/relationship membership is being edited or inspected. */
  resource: AccessRelationshipResource;
  /** Relationship to inspect, such as reader or editor. */
  relation: string;
  /** Opaque backend cursor from a previous page. */
  cursor?: string;
  /** Caller-requested page bound; adapters may impose a smaller limit. */
  limit?: number;
};

/** One bounded page of explicit relationship source entries. */
export type AccessRelationshipSubjectsPage = {
  /** True when this relation imposes no extra principal restriction on the resource. */
  unrestricted: boolean;
  /** Explicit source entries represented by this page; inherited/effective subjects need not be expanded. */
  subjects: readonly AccessRelationshipSubject[];
  /** Opaque cursor when another page exists. */
  cursor?: string;
};

/** Optional object-centered read side used by ACL editors without scanning a resource namespace. */
export type AccessRelationshipSubjectsAdapter = {
  /** List a bounded page of explicit source entries attached to one resource relation. */
  listSubjects(
    request: AccessRelationshipSubjectsRequest
  ): Promise<AccessRelationshipSubjectsPage>;
};

/** Add or remove one explicit principal source entry from an application-owned resource relation. */
export type AccessRelationshipPrincipalMutation = {
  /** Add creates the source entry; remove revokes matching source entries. */
  operation: "add" | "remove";
  /** Principal whose explicit/group/role relationship is changing. */
  principal: AccessPrincipal;
  /** Resource whose ACL/relationship set is changing. */
  resource: AccessRelationshipResource;
  /** Application-defined relation such as reader, editor, group-member, or approver. */
  relation: string;
  /** Optional exact temporal contribution. A remove without validity removes every source entry for the principal. */
  validity?: AccessValidity | readonly AccessValidity[];
};

/** Toggle whether one resource relation is satisfied without any explicit principal membership. */
export type AccessRelationshipVisibilityMutation = {
  /** Explicitly switch between open/inherited visibility and relationship-restricted visibility. */
  operation: "set-unrestricted";
  /** Resource whose relationship policy is changing. */
  resource: AccessRelationshipResource;
  /** Relation whose open/restricted mode is changing. */
  relation: string;
  /** True means this relation does not impose an extra principal restriction. */
  unrestricted: boolean;
};

/** One exact high-cardinality relationship or visibility mutation. */
export type AccessRelationshipMutation =
  | AccessRelationshipPrincipalMutation
  | AccessRelationshipVisibilityMutation;

/** BYO write side for relationship stores; kept separate so read-only PDP integrations stay minimal. */
export type AccessRelationshipMutationAdapter = {
  /** Atomically or transactionally apply the supplied application relationship mutations when supported. */
  mutate(mutations: readonly AccessRelationshipMutation[]): Promise<void>;
};

/** One resource/relation whose physical ACL projection is due for reconciliation. */
export type AccessRelationshipProjectionTarget = {
  /** Resource whose physical authorization projection may be stale. */
  resource: AccessRelationshipResource;
  /** Relation being projected for this resource. */
  relation: string;
};

/**
 * Optional projection capability for storage engines whose native ACL cannot encode time directly.
 *
 * `reconcileAt` owns the backend's transaction/lock discipline. It must acquire the backend's per-resource
 * serialization primitive, re-read current source inside that protection, and reconcile current truth rather
 * than replaying a stale transition event.
 */
export type AccessRelationshipProjectionAdapter = {
  /** Return at most `limit` unique resource/relation projections due at or before the supplied instant. */
  listDue(atEpochMs: number, limit: number): Promise<readonly AccessRelationshipProjectionTarget[]>;
  /** Reconcile one target against current source at the supplied instant. */
  reconcileAt(
    target: AccessRelationshipProjectionTarget,
    atEpochMs: number
  ): Promise<void>;
};

/** Bounds controlling one host-invoked temporal relationship projection sweep. */
export type AccessRelationshipProjectionSweepOptions = {
  /** Maximum due projections considered in this invocation; defaults to 256. */
  limit?: number;
  /** Maximum reconciliations in flight at once; defaults to 16. */
  concurrency?: number;
};

/** Convenience shape for a relationship backend that supports both authorization checks and writes. */
export type AccessRelationshipStore = AccessRelationshipAdapter &
  AccessRelationshipMutationAdapter;

/** Relationship backend that can push object visibility directly into an application query. */
export type AccessQueryableRelationshipStore<Query> = AccessRelationshipStore &
  AccessRelationshipQueryAdapter<Query>;

/** Relationship backend suitable for a direct ACL editor as well as authorization checks and writes. */
export type AccessEditableRelationshipStore = AccessRelationshipStore &
  AccessRelationshipSubjectsAdapter;

/** Return one stable principal identity key without delimiter collision. */
function relationshipPrincipalKey(principal: AccessPrincipal): string {
  return JSON.stringify([principal.type, principal.id]);
}

/** Validate one temporal boundary accepted by relationship materialization. */
function relationshipBoundary(value: number | undefined, label: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value)) throw new RangeError(`${label} must be a safe integer`);
  return value;
}

/** Canonicalize one validity value for stable relationship-source identity. */
function relationshipValidityKey(
  validity: AccessValidity | readonly AccessValidity[] | undefined
): readonly (readonly [number | null, number | null])[] | null {
  if (validity === undefined) return null;
  const input = Array.isArray(validity) ? validity : [validity];
  const windows: Array<[number | null, number | null]> = [];
  for (const window of input) {
    const start = relationshipBoundary(window.startsAtEpochMs, "startsAtEpochMs") ?? null;
    const end = relationshipBoundary(window.endsAtEpochMs, "endsAtEpochMs") ?? null;
    if (start !== null && end !== null && start > end) {
      throw new RangeError("startsAtEpochMs must not be after endsAtEpochMs");
    }
    if (start !== null && start === end) continue;
    if (start === null && end === null) return null;
    windows.push([start, end]);
  }
  windows.sort((left, right) => {
    const leftStart = left[0] ?? Number.NEGATIVE_INFINITY;
    const rightStart = right[0] ?? Number.NEGATIVE_INFINITY;
    if (leftStart !== rightStart) return leftStart - rightStart;
    return (left[1] ?? Number.POSITIVE_INFINITY) - (right[1] ?? Number.POSITIVE_INFINITY);
  });
  const merged: Array<[number | null, number | null]> = [];
  for (const window of windows) {
    const previous = merged[merged.length - 1];
    if (!previous) {
      merged.push(window);
      continue;
    }
    const previousEnd = previous[1];
    const nextStart = window[0];
    if (previousEnd !== null && nextStart !== null && nextStart > previousEnd) {
      merged.push(window);
      continue;
    }
    previous[1] = previousEnd === null || window[1] === null
      ? null
      : Math.max(previousEnd, window[1]);
  }
  return merged;
}

/** Stable semantic identity for one explicit relationship source entry. */
export function accessRelationshipSubjectKey(subject: AccessRelationshipSubject): string {
  return JSON.stringify([
    subject.principal.type,
    subject.principal.id,
    relationshipValidityKey(subject.validity),
  ]);
}

/** Cold result of evaluating one relationship source entry at one instant. */
type RelationshipSubjectEvaluation = {
  /** Whether this source entry contributes authority at the requested instant. */
  active: boolean;
  /** Earliest future boundary carried by this entry, when one exists. */
  nextTransitionAtEpochMs?: number;
};

/** Evaluate one source entry and return whether it is active plus its earliest future boundary. */
function relationshipSubjectAt(
  subject: AccessRelationshipSubject,
  atEpochMs: number
): RelationshipSubjectEvaluation {
  const windows = relationshipValidityKey(subject.validity);
  if (windows === null) return { active: true };
  for (const [start, end] of windows) {
    if (start !== null && atEpochMs < start) {
      return { active: false, nextTransitionAtEpochMs: start };
    }
    if (end === null || atEpochMs < end) {
      return {
        active: true,
        ...(end === null ? {} : { nextTransitionAtEpochMs: end }),
      };
    }
  }
  return { active: false };
}

/**
 * Materialize one resource/relation source at an explicit instant.
 *
 * This is a cold reconciliation primitive, not a query hot path. It deduplicates principals whose overlapping
 * source entries are simultaneously active and reports the next known boundary so projected backends can index
 * only genuinely due work.
 */
export function materializeAccessRelationshipAt(
  source: AccessRelationshipSource,
  atEpochMs: number
): MaterializedAccessRelationship {
  if (!Number.isSafeInteger(atEpochMs)) throw new RangeError("atEpochMs must be a safe integer");

  const grouped = new Map<
    string,
    {
      /** First source principal retained for this stable identity. */
      principal: AccessPrincipal;
      /** Combined temporal contributions; undefined means at least one timeless source exists. */
      validity: AccessValidity[] | undefined;
    }
  >();
  for (const subject of source.subjects) {
    // Validate every source entry even when another timeless entry makes its temporal contribution redundant.
    relationshipValidityKey(subject.validity);
    const key = relationshipPrincipalKey(subject.principal);
    const current = grouped.get(key);
    if (!current) {
      const normalized = relationshipValidityKey(subject.validity);
      grouped.set(key, {
        principal: subject.principal,
        validity: normalized === null
          ? undefined
          : normalized.map(([start, end]) => ({
              ...(start === null ? {} : { startsAtEpochMs: start }),
              ...(end === null ? {} : { endsAtEpochMs: end }),
            })),
      });
      continue;
    }

    // One timeless source keeps this principal continuously effective regardless of other temporal entries.
    if (current.validity === undefined) continue;
    const normalized = relationshipValidityKey(subject.validity);
    if (normalized === null) {
      current.validity = undefined;
      continue;
    }
    for (const [start, end] of normalized) {
      current.validity.push({
        ...(start === null ? {} : { startsAtEpochMs: start }),
        ...(end === null ? {} : { endsAtEpochMs: end }),
      });
    }
  }

  const principals: AccessPrincipal[] = [];
  let nextTransitionAtEpochMs: number | undefined;
  for (const { principal, validity } of grouped.values()) {
    const evaluated = relationshipSubjectAt(
      validity === undefined ? { principal } : { principal, validity },
      atEpochMs,
    );
    if (evaluated.active) principals.push(principal);
    const next = evaluated.nextTransitionAtEpochMs;
    if (next !== undefined &&
        (nextTransitionAtEpochMs === undefined || next < nextTransitionAtEpochMs)) {
      nextTransitionAtEpochMs = next;
    }
  }
  return Object.freeze({
    unrestricted: source.unrestricted,
    principals: Object.freeze(principals),
    ...(nextTransitionAtEpochMs === undefined ? {} : { nextTransitionAtEpochMs }),
  });
}

/**
 * Reconcile one bounded page of due physical ACL projections.
 *
 * Hosts own cadence (`setInterval`, cron, request maintenance, dedicated worker, etc.). AccessOnce only performs
 * one bounded sweep so framework/process lifecycle never leaks into the core package.
 */
export async function sweepAccessRelationshipProjections(
  adapter: AccessRelationshipProjectionAdapter,
  atEpochMs: number,
  options: AccessRelationshipProjectionSweepOptions = {}
): Promise<number> {
  if (!Number.isSafeInteger(atEpochMs)) throw new RangeError("atEpochMs must be a safe integer");
  const limit = options.limit ?? 256;
  const concurrency = options.concurrency ?? 16;
  if (!Number.isInteger(limit) || limit < 1) throw new RangeError("limit must be a positive integer");
  if (!Number.isInteger(concurrency) || concurrency < 1) {
    throw new RangeError("concurrency must be a positive integer");
  }
  const due = await adapter.listDue(atEpochMs, limit);
  if (due.length > limit) throw new Error("Relationship projection adapter returned more rows than requested");
  let nextIndex = 0;
  const worker = async () => {
    while (nextIndex < due.length) {
      const index = nextIndex;
      nextIndex += 1;
      await adapter.reconcileAt(due[index]!, atEpochMs);
    }
  };
  const workers: Promise<void>[] = [];
  const workerCount = Math.min(concurrency, due.length);
  for (let index = 0; index < workerCount; index += 1) workers.push(worker());
  await Promise.all(workers);
  return due.length;
}

/** Complete authorization request with an optional narrow object relationship. */
export type AccessAuthorizationRequest<
  Leaf extends string,
  Dimension extends string
> = {
  /** Concrete application permission checked first in memory. */
  permission: Leaf;
  /** Trusted row/operation context for compiled scopes. */
  context?: AccessContext<Dimension>;
  /** Current principal; required only when an object relationship is requested. */
  principal?: AccessPrincipal;
  /** Optional object-level ACL/relationship requirement. */
  relationship?: AccessRelationshipRequirement;
  /** Optional evaluation instant forwarded to relationship stores that enforce time natively. */
  atEpochMs?: number;
};

/** Keep the normal path synchronous/cheap and consult an ACL adapter only for an object that asks for it. */
export async function authorizeAccess<
  Snapshot,
  Leaf extends string,
  Dimension extends string
>(
  evaluator: AccessEvaluator<Snapshot, Leaf, Dimension>,
  snapshot: Snapshot,
  request: AccessAuthorizationRequest<Leaf, Dimension>,
  relationshipAdapter?: AccessRelationshipAdapter
): Promise<boolean> {
  if (!evaluator.can(snapshot, request.permission, request.context))
    return false;
  if (!request.relationship) return true;

  // A record that declares an extra ACL fails closed when no relationship backend was configured.
  if (!request.principal || !relationshipAdapter) return false;
  return relationshipAdapter.check({
    principal: request.principal,
    resource: request.relationship.resource,
    relation: request.relationship.relation,
    ...(request.atEpochMs === undefined ? {} : { atEpochMs: request.atEpochMs }),
  });
}

/** Authorize several rows/actions while batching only the object relationships that survive local checks. */
export async function authorizeAccessMany<
  Snapshot,
  Leaf extends string,
  Dimension extends string
>(
  evaluator: AccessEvaluator<Snapshot, Leaf, Dimension>,
  snapshot: Snapshot,
  requests: readonly AccessAuthorizationRequest<Leaf, Dimension>[],
  relationshipAdapter?: AccessRelationshipAdapter
): Promise<readonly boolean[]> {
  const results = new Array<boolean>(requests.length).fill(false);
  const relationshipChecks: AccessRelationshipCheck[] = [];
  const relationshipResultIndexes: number[] = [];

  for (let index = 0; index < requests.length; index += 1) {
    const request = requests[index]!;
    if (!evaluator.can(snapshot, request.permission, request.context)) continue;
    if (!request.relationship) {
      results[index] = true;
      continue;
    }

    // Object-level ACLs fail closed when the caller has no principal or relationship backend.
    if (!request.principal || !relationshipAdapter) continue;
    relationshipChecks.push({
      principal: request.principal,
      resource: request.relationship.resource,
      relation: request.relationship.relation,
      ...(request.atEpochMs === undefined ? {} : { atEpochMs: request.atEpochMs }),
    });
    relationshipResultIndexes.push(index);
  }

  if (relationshipChecks.length === 0 || !relationshipAdapter) return results;

  let relationshipResults: readonly boolean[];
  if (relationshipAdapter.checkMany) {
    relationshipResults = await relationshipAdapter.checkMany(
      relationshipChecks
    );
    if (relationshipResults.length !== relationshipChecks.length) {
      throw new Error(
        "Relationship adapter returned the wrong number of bulk decisions"
      );
    }
  } else {
    // Keep the convenience fallback parallel without allowing one large page to fan out unbounded backend I/O.
    const fallbackResults = new Array<boolean>(relationshipChecks.length);
    let nextIndex = 0;
    const worker = async () => {
      while (nextIndex < relationshipChecks.length) {
        const index = nextIndex;
        nextIndex += 1;
        fallbackResults[index] = await relationshipAdapter.check(relationshipChecks[index]!);
      }
    };
    const workers: Promise<void>[] = [];
    const workerCount = Math.min(32, relationshipChecks.length);
    for (let index = 0; index < workerCount; index += 1) workers.push(worker());
    await Promise.all(workers);
    relationshipResults = fallbackResults;
  }

  for (let index = 0; index < relationshipResults.length; index += 1) {
    results[relationshipResultIndexes[index]!] = relationshipResults[index]!;
  }
  return results;
}

/**
 * Apply one backend-native relationship visibility filter to an existing query.
 *
 * This helper deliberately does not fall back to `checkMany` or resource-id lookup: callers using this path
 * are declaring that their backend can push authorization into the query efficiently at collection scale.
 */
export async function constrainRelationshipQuery<Query>(
  adapter: AccessRelationshipQueryAdapter<Query>,
  request: AccessRelationshipQueryRequest<Query>
): Promise<Query> {
  return adapter.constrainQuery(request);
}
