import type { AccessContext } from "./types.js";
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

/** Request for principals explicitly represented by one resource relationship. */
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

/** One bounded page of explicit principals for a resource relationship. */
export type AccessRelationshipSubjectsPage = {
  /** True when this relation imposes no extra principal restriction on the resource. */
  unrestricted: boolean;
  /** Explicit principals represented by this page; inherited/effective subjects need not be expanded. */
  principals: readonly AccessPrincipal[];
  /** Opaque cursor when another page exists. */
  cursor?: string;
};

/** Optional object-centered read side used by ACL editors without scanning a resource namespace. */
export type AccessRelationshipSubjectsAdapter = {
  /** List a bounded page of explicit principals attached to one resource relation. */
  listSubjects(
    request: AccessRelationshipSubjectsRequest
  ): Promise<AccessRelationshipSubjectsPage>;
};

/** Add or remove one explicit principal from an application-owned resource relation. */
export type AccessRelationshipPrincipalMutation = {
  /** Add creates the relationship; remove revokes that exact relationship. */
  operation: "add" | "remove";
  /** Principal whose explicit/group/role relationship is changing. */
  principal: AccessPrincipal;
  /** Resource whose ACL/relationship set is changing. */
  resource: AccessRelationshipResource;
  /** Application-defined relation such as reader, editor, group-member, or approver. */
  relation: string;
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

/** Convenience shape for a relationship backend that supports both authorization checks and writes. */
export type AccessRelationshipStore = AccessRelationshipAdapter &
  AccessRelationshipMutationAdapter;

/** Relationship backend that can push object visibility directly into an application query. */
export type AccessQueryableRelationshipStore<Query> = AccessRelationshipStore &
  AccessRelationshipQueryAdapter<Query>;

/** Relationship backend suitable for a direct ACL editor as well as authorization checks and writes. */
export type AccessEditableRelationshipStore = AccessRelationshipStore &
  AccessRelationshipSubjectsAdapter;

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
