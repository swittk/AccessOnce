import type { AccessCatalog } from "./catalog.js";
import type {
  AccessContext,
  AccessQueryClause,
  AccessQueryPlan,
  AllowedAccessValues,
  CompiledAccessConstraint,
  CompiledAccessGrant,
  EffectiveAccessSnapshot,
} from "./types.js";

/** Set-backed ids used only inside one process for fast repeated authorization checks. */
type IndexedIdsConstraint<Dimension extends string> = {
  /** Scope dimension this constraint restricts. */
  dimension: Dimension;
  /** Runtime discriminator for a fixed-id restriction. */
  kind: "ids";
  /** Set-backed ids for constant-time membership tests. */
  ids: ReadonlySet<string>;
};

/** Subject-relative constraint retained without allocation in the runtime index. */
type IndexedSubjectConstraint<Dimension extends string> = {
  /** Scope dimension this constraint restricts. */
  dimension: Dimension;
  /** Runtime discriminator for a subject-relative restriction. */
  kind: "subject";
  /** Subject value captured when this snapshot object first enters the cache. */
  value: string | undefined;
};

/** Runtime constraint after one-time Set indexing. */
type IndexedConstraint<Dimension extends string> =
  | IndexedIdsConstraint<Dimension>
  | IndexedSubjectConstraint<Dimension>;

/** Runtime grant after one-time indexing of fixed ids. */
type IndexedGrant<Dimension extends string> = {
  /** Constraints that must all pass for this grant. */
  constraints: readonly IndexedConstraint<Dimension>[];
};

/** One candidate bucket stays scalar until multiple grants truly share the same indexed value. */
type IndexedPermissionBucket<Dimension extends string> =
  | IndexedGrant<Dimension>
  | IndexedGrant<Dimension>[];

/** Cold-built candidate buckets that skip unrelated grants on the hot path. */
type IndexedPermissionFilter<Dimension extends string> = {
  /** Scope dimension used to choose the smallest relevant candidate bucket. */
  dimension: Dimension;
  /** Grants keyed by one allowed value on the selected dimension. */
  byValue: ReadonlyMap<string, IndexedPermissionBucket<Dimension>>;
  /** Grants with no constraint on the selected dimension; absent when every grant is restricted. */
  unrestricted?: readonly IndexedGrant<Dimension>[];
};

/** All runtime grants for one permission plus an optional cold-built candidate filter. */
type IndexedPermission<Dimension extends string> = {
  /** Complete grants retained for hasAny, allowedValues, and queryPlan. */
  grants: readonly IndexedGrant<Dimension>[];
  /** Candidate filter used only when it provably reduces the worst hot-path scan. */
  filter?: IndexedPermissionFilter<Dimension>;
};

/** One cached external/canonical snapshot after its adapter has been accepted and indexed. */
type IndexedSnapshot<
  Leaf extends string,
  Dimension extends string,
> = {
  /** False means the adapter rejected this snapshot generation and every check must deny. */
  accepted: boolean;
  /** Concrete permission lookup table built once from the snapshot grants. */
  permissions: ReadonlyMap<Leaf, IndexedPermission<Dimension>>;
};

/** Shared immutable empty context used when a caller has no scoped runtime values. */
const EMPTY_ACCESS_CONTEXT: AccessContext<string> = {};

/** Declarative filters used when projecting values or query clauses from compiled grants. */
export type AccessProjectionOptions<Dimension extends string> = {
  /** Known trusted row/operation values used to discard incompatible scoped grants. */
  context?: AccessContext<Dimension>;
  /** Keep only grants that leave every listed dimension unrestricted. */
  requireUnrestricted?: readonly Dimension[];
  /** Keep only grants that explicitly restrict every listed dimension. */
  requireRestricted?: readonly Dimension[];
};

/** Public evaluator surface shared by canonical snapshots and BYO snapshot adapters. */
export type AccessEvaluator<
  Snapshot,
  Leaf extends string,
  Dimension extends string,
> = {
  /** Decide one concrete permission entirely in memory. */
  can(snapshot: Snapshot, permission: Leaf, context?: AccessContext<Dimension>): boolean;
  /** Return whether any grant for this permission exists, ignoring whether its scope matches a row yet. */
  hasAny(snapshot: Snapshot, permission: Leaf): boolean;
  /** Find the values available for one dimension after any supplied other-dimension context is fixed. */
  allowedValues(
    snapshot: Snapshot,
    permission: Leaf,
    dimension: Dimension,
    options?: AccessProjectionOptions<Dimension>,
  ): AllowedAccessValues;
  /** Return an OR-of-AND scope plan that a database adapter can translate without cross-product bugs. */
  queryPlan(
    snapshot: Snapshot,
    permission: Leaf,
    options?: AccessProjectionOptions<Dimension>,
  ): AccessQueryPlan<Dimension>;
};

/** Adapter for an application that already has a compact compiled snapshot shape it wants to keep. */
export type CompiledSnapshotAdapter<
  Snapshot extends object,
  Grant,
  Leaf extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Reject a stale snapshot generation once before its grants enter the runtime cache. */
  accepts(snapshot: Snapshot): boolean;
  /** Return the already-compiled concrete grants stored by the application. */
  grants(snapshot: Snapshot): readonly Grant[];
  /** Return the concrete permission leaf stored on one application grant. */
  permission(grant: Grant): Leaf;
  /** Translate one application's compact grant into runtime constraints once per snapshot object. */
  constraints(grant: Grant): readonly CompiledAccessConstraint<Dimension, Attribute>[];
  /** Return one subject attribute used by a subject-relative constraint. */
  subjectValue(snapshot: Snapshot, attribute: Attribute): string | undefined;
};

/** Build the best one-dimension candidate bucket only when it reduces every indexed value's scan. */
function createIndexedPermission<Dimension extends string>(
  grants: readonly IndexedGrant<Dimension>[],
): IndexedPermission<Dimension> {
  if (grants.length < 2) return { grants };

  /** Dimensions seen across these grants; candidate filters are evaluated only on this cold path. */
  const dimensions = new Set<Dimension>();
  for (const grant of grants) {
    for (const constraint of grant.constraints) dimensions.add(constraint.dimension);
  }

  let bestFilter: IndexedPermissionFilter<Dimension> | undefined;
  let bestWorstCandidateCount = grants.length;
  for (const dimension of dimensions) {
    const byValue = new Map<string, IndexedPermissionBucket<Dimension>>();
    let unrestricted: IndexedGrant<Dimension>[] | undefined;

    /** Add one candidate without allocating an array until the value actually has multiple grants. */
    function addCandidate(value: string, grant: IndexedGrant<Dimension>) {
      const existing = byValue.get(value);
      if (!existing) {
        byValue.set(value, grant);
      } else if (Array.isArray(existing)) {
        existing.push(grant);
      } else {
        byValue.set(value, [existing, grant]);
      }
    }

    for (const grant of grants) {
      let dimensionConstraint: IndexedConstraint<Dimension> | undefined;
      for (const constraint of grant.constraints) {
        if (constraint.dimension === dimension) {
          dimensionConstraint = constraint;
          break;
        }
      }
      if (!dimensionConstraint) {
        unrestricted ??= [];
        unrestricted.push(grant);
        continue;
      }

      if (dimensionConstraint.kind === "ids") {
        for (const value of dimensionConstraint.ids) addCandidate(value, grant);
      } else if (dimensionConstraint.value !== undefined) {
        addCandidate(dimensionConstraint.value, grant);
      }
    }

    if (byValue.size === 0) continue;
    const unrestrictedCount = unrestricted?.length ?? 0;
    let worstCandidateCount = unrestrictedCount;
    for (const bucket of byValue.values()) {
      const bucketCount = Array.isArray(bucket) ? bucket.length : 1;
      const count = bucketCount + unrestrictedCount;
      if (count > worstCandidateCount) worstCandidateCount = count;
    }
    if (worstCandidateCount >= bestWorstCandidateCount) continue;

    bestWorstCandidateCount = worstCandidateCount;
    bestFilter = {
      dimension,
      byValue,
      ...(unrestricted ? { unrestricted } : {}),
    };
  }

  return bestFilter ? { grants, filter: bestFilter } : { grants };
}

/**
 * Create the hot evaluator directly over any already-compiled snapshot shape.
 * The adapter runs only while a new snapshot object is indexed; repeated checks use one WeakMap lookup.
 */
export function createAdaptedAccessEvaluator<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Snapshot extends object,
  Grant,
>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  adapter: CompiledSnapshotAdapter<Snapshot, Grant, Leaf, Dimension, Attribute>,
): AccessEvaluator<Snapshot, Leaf, Dimension> {
  /** Per-evaluator cache prevents one snapshot object being interpreted under a different catalog adapter. */
  const indexCache = new WeakMap<
    Snapshot,
    IndexedSnapshot<Leaf, Dimension>
  >();

  /** Build a permission/Set index once; adapter rejection is cached as an empty deny-all index. */
  function indexedSnapshot(
    snapshot: Snapshot,
  ): IndexedSnapshot<Leaf, Dimension> {
    const cached = indexCache.get(snapshot);
    if (cached) return cached;

    /** Mutable grant lists are filled first, then converted to optimized per-permission indexes. */
    const grantLists = new Map<Leaf, IndexedGrant<Dimension>[]>();
    const permissions = new Map<Leaf, IndexedPermission<Dimension>>();
    if (!adapter.accepts(snapshot)) {
      const rejected = { accepted: false, permissions };
      indexCache.set(snapshot, rejected);
      return rejected;
    }

    for (const grant of adapter.grants(snapshot)) {
      const permission = adapter.permission(grant);
      // BYO snapshots may come from durable/wire data; an unknown leaf rejects the whole snapshot.
      // This check happens only while the snapshot object is first indexed, never per authorization call.
      if (!catalog.isLeaf(permission)) {
        const rejected = {
          accepted: false,
          permissions: new Map<Leaf, IndexedPermission<Dimension>>(),
        };
        indexCache.set(snapshot, rejected);
        return rejected;
      }
      let candidates = grantLists.get(permission);
      if (!candidates) {
        candidates = [];
        grantLists.set(permission, candidates);
      }

      /** Fixed ids become Sets once here; each dimension must appear at most once in one AND grant. */
      const constraints: IndexedConstraint<Dimension>[] = [];
      const seenDimensions = new Set<Dimension>();
      let usable = true;
      for (const constraint of adapter.constraints(grant)) {
        // Duplicate dimensions cannot be represented faithfully by allowedValues/queryPlan, so reject
        // malformed BYO wire data instead of letting direct checks and query projection disagree.
        if (seenDimensions.has(constraint.dimension)) {
          const rejected = {
            accepted: false,
            permissions: new Map<Leaf, IndexedPermission<Dimension>>(),
          };
          indexCache.set(snapshot, rejected);
          return rejected;
        }
        seenDimensions.add(constraint.dimension);
        if (constraint.kind === "ids") {
          /** Canonical compilation never emits empty ids; reject malformed BYO compiled data too. */
          const ids = new Set<string>();
          let malformed = false;
          for (const id of constraint.ids) {
            if (!id) {
              malformed = true;
              break;
            }
            ids.add(id);
          }
          if (malformed || ids.size === 0) {
            const rejected = {
              accepted: false,
              permissions: new Map<Leaf, IndexedPermission<Dimension>>(),
            };
            indexCache.set(snapshot, rejected);
            return rejected;
          }
          constraints.push({
            dimension: constraint.dimension,
            kind: "ids",
            ids,
          });
        } else {
          const value = adapter.subjectValue(snapshot, constraint.attribute);
          if (value === undefined) usable = false;
          constraints.push({
            dimension: constraint.dimension,
            kind: "subject",
            value,
          });
        }
      }
      if (usable) candidates.push({ constraints });
    }

    for (const [permission, grants] of grantLists) {
      permissions.set(permission, createIndexedPermission(grants));
    }

    const indexed = { accepted: true, permissions };
    indexCache.set(snapshot, indexed);
    return indexed;
  }

  /** Check one indexed constraint against trusted runtime context. Missing restricted context fails closed. */
  function constraintAllows(
    constraint: IndexedConstraint<Dimension>,
    context: AccessContext<Dimension>,
  ): boolean {
    const requested = context[constraint.dimension];
    if (requested === undefined) return false;
    if (constraint.kind === "ids") return constraint.ids.has(requested);
    return constraint.value !== undefined && constraint.value === requested;
  }

  /** Check every constraint attached to one candidate grant. */
  function grantAllows(
    grant: IndexedGrant<Dimension>,
    context: AccessContext<Dimension>,
    skipDimension?: Dimension,
  ): boolean {
    for (const constraint of grant.constraints) {
      // Bucket membership already proves the selected dimension, so do not check it twice.
      if (constraint.dimension === skipDimension) continue;
      if (!constraintAllows(constraint, context)) return false;
    }
    return true;
  }

  /** Apply declarative projection filters without exposing grant representation to applications. */
  function grantMatchesProjection(
    grant: IndexedGrant<Dimension>,
    targetDimension: Dimension | undefined,
    options: AccessProjectionOptions<Dimension> | undefined,
  ): boolean {
    if (options?.requireUnrestricted) {
      for (const dimension of options.requireUnrestricted) {
        for (const constraint of grant.constraints) {
          if (constraint.dimension === dimension) return false;
        }
      }
    }
    if (options?.requireRestricted) {
      for (const dimension of options.requireRestricted) {
        let found = false;
        for (const constraint of grant.constraints) {
          if (constraint.dimension === dimension) {
            found = true;
            break;
          }
        }
        if (!found) return false;
      }
    }

    const context = options?.context;
    if (!context) return true;
    for (const constraint of grant.constraints) {
      if (constraint.dimension === targetDimension) continue;
      const requested = context[constraint.dimension];
      // Missing context is not a filter; requireUnrestricted expresses that stricter intent explicitly.
      if (requested === undefined) continue;
      if (constraint.kind === "ids") {
        if (!constraint.ids.has(requested)) return false;
      } else if (constraint.value === undefined || constraint.value !== requested) {
        return false;
      }
    }
    return true;
  }

  return {
    can(snapshot, permission, context) {
      const indexed = indexedSnapshot(snapshot);
      if (!indexed.accepted) return false;
      const permissionIndex = indexed.permissions.get(permission);
      if (!permissionIndex) return false;
      const activeContext = context ?? EMPTY_ACCESS_CONTEXT;
      const filter = permissionIndex.filter;
      if (filter) {
        const requested = activeContext[filter.dimension];
        if (requested !== undefined) {
          const bucket = filter.byValue.get(requested);
          if (bucket) {
            if (Array.isArray(bucket)) {
              for (const grant of bucket) {
                if (grantAllows(grant, activeContext, filter.dimension)) return true;
              }
            } else if (grantAllows(bucket, activeContext, filter.dimension)) {
              return true;
            }
          }
        }
        if (filter.unrestricted) {
          for (const grant of filter.unrestricted) {
            if (grantAllows(grant, activeContext)) return true;
          }
        }
        return false;
      }
      for (const grant of permissionIndex.grants) {
        if (grantAllows(grant, activeContext)) return true;
      }
      return false;
    },
    hasAny(snapshot, permission) {
      const indexed = indexedSnapshot(snapshot);
      return indexed.accepted && (indexed.permissions.get(permission)?.grants.length ?? 0) > 0;
    },
    allowedValues(snapshot, permission, dimension, options) {
      const indexed = indexedSnapshot(snapshot);
      if (!indexed.accepted) return { kind: "none" };
      const permissionIndex = indexed.permissions.get(permission);
      if (!permissionIndex) return { kind: "none" };
      const values = new Set<string>();
      for (const grant of permissionIndex.grants) {
        if (!grantMatchesProjection(grant, dimension, options)) continue;
        let targetConstraint: IndexedConstraint<Dimension> | undefined;
        let usable = true;
        for (const constraint of grant.constraints) {
          if (constraint.kind === "subject" && constraint.value === undefined) {
            usable = false;
            break;
          }
          if (constraint.dimension === dimension) targetConstraint = constraint;
        }
        if (!usable) continue;

        // One matching grant without a target-dimension constraint makes that dimension fully open.
        if (!targetConstraint) return { kind: "all" };
        if (targetConstraint.kind === "ids") {
          for (const value of targetConstraint.ids) values.add(value);
        } else if (targetConstraint.value !== undefined) {
          values.add(targetConstraint.value);
        }
      }
      if (values.size === 0) return { kind: "none" };
      return { kind: "some", values: [...values] };
    },
    queryPlan(snapshot, permission, options) {
      const indexed = indexedSnapshot(snapshot);
      if (!indexed.accepted) return { kind: "none" };
      const permissionIndex = indexed.permissions.get(permission);
      if (!permissionIndex) return { kind: "none" };
      const clauses: AccessQueryClause<Dimension>[] = [];
      for (const grant of permissionIndex.grants) {
        if (!grantMatchesProjection(grant, undefined, options)) continue;
        if (grant.constraints.length === 0) return { kind: "all" };
        const clause: Partial<Record<Dimension, readonly string[]>> = {};
        let usable = true;
        for (const constraint of grant.constraints) {
          if (constraint.kind === "ids") {
            clause[constraint.dimension] = [...constraint.ids];
            continue;
          }
          const value = constraint.value;
          if (value === undefined) {
            usable = false;
            break;
          }
          clause[constraint.dimension] = [value];
        }
        if (usable) clauses.push(clause);
      }
      return clauses.length === 0
        ? { kind: "none" }
        : { kind: "some", clauses };
    },
  };
}

/** Create the canonical AccessOnce evaluator using the same one-cache adapter runtime. */
export function createAccessEvaluator<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string = string,
>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
): AccessEvaluator<EffectiveAccessSnapshot<Leaf, Dimension, Attribute>, Leaf, Dimension> {
  return createAdaptedAccessEvaluator<
    Permission,
    Leaf,
    Dimension,
    Attribute,
    EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
    CompiledAccessGrant<Leaf, Dimension, Attribute>
  >(catalog, {
    accepts(snapshot) {
      if (
        snapshot.schemaVersion !== 1 ||
        snapshot.catalogId !== catalog.catalogId ||
        snapshot.catalogVersion !== catalog.catalogVersion ||
        snapshot.compilerVersion !== catalog.compilerVersion ||
        !Array.isArray(snapshot.grants)
      ) {
        return false;
      }
      for (const grant of snapshot.grants as readonly unknown[]) {
        if (
          !grant ||
          typeof grant !== "object" ||
          Array.isArray(grant) ||
          !Array.isArray((grant as Readonly<Record<"constraints", unknown>>).constraints)
        ) {
          return false;
        }
      }
      return true;
    },
    grants(snapshot) {
      return snapshot.grants;
    },
    permission(grant) {
      return grant.permission;
    },
    constraints(grant) {
      return grant.constraints;
    },
    subjectValue(snapshot, attribute) {
      return snapshot.subject?.[attribute];
    },
  });
}
