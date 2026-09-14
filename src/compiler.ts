import type { AccessCatalog } from "./catalog.js";
import type {
  AccessGrant,
  AccessValidity,
  CompiledAccessConstraint,
  CompiledAccessGrant,
  CompiledAccessTimeline,
  CompiledAccessTransition,
  EffectiveAccessSnapshot,
} from "./types.js";

/** Inputs accepted by the cold-path access compiler. */
export type CompileAccessArgs<
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Source grants from profiles, roles, direct assignments, or any other application source. */
  grants: readonly AccessGrant<Permission, Dimension, Attribute>[];
  /** Small subject values used by subject-relative scopes such as `own assignee`. */
  subject?: Readonly<Partial<Record<Attribute, string>>>;
  /** Optional revision copied into the runtime snapshot for publication recovery and diagnostics. */
  sourceRevision?: string;
};

/** Cold normalized half-open validity interval. Missing bounds represent infinity. */
type NormalizedValidityWindow = {
  /** Inclusive lower bound when present. */
  startsAtEpochMs?: number;
  /** Exclusive upper bound when present. */
  endsAtEpochMs?: number;
};

/** One unique compiled grant plus all temporal windows that contribute it. */
type CompiledGrantAccumulator<
  Leaf extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Deterministic identity used for sorting and deduplication. */
  key: string;
  /** Canonical permission/scope clause. */
  grant: CompiledAccessGrant<Leaf, Dimension, Attribute>;
  /** A timeless contribution dominates every temporal contribution for the same clause. */
  timeless: boolean;
  /** Temporal windows collected across duplicate source grants. */
  windows: NormalizedValidityWindow[];
};

/** Mutable cold-path transition bucket before the snapshot arrays are frozen. */
type MutableCompiledTransition = {
  /** Temporal grant indexes activated at this instant. */
  addGrantIndexes: number[];
  /** Temporal grant indexes deactivated at this instant. */
  removeGrantIndexes: number[];
};

/** Stable key for deterministic deduplication of one compiled grant. */
function compiledGrantKey<Leaf extends string, Dimension extends string, Attribute extends string>(
  grant: CompiledAccessGrant<Leaf, Dimension, Attribute>,
): string {
  return JSON.stringify([grant.permission, grant.constraints]);
}

/** Normalize one source grant's scope without doing work again on every authorization check. */
function normalizeConstraints<Dimension extends string, Attribute extends string>(
  scope: Readonly<Partial<Record<Dimension, import("./types.js").AccessScopeSource<Attribute>>>> | undefined,
): readonly CompiledAccessConstraint<Dimension, Attribute>[] | undefined {
  if (!scope) return [];
  const constraints: CompiledAccessConstraint<Dimension, Attribute>[] = [];
  const dimensions = Object.keys(scope) as Dimension[];
  dimensions.sort();
  for (const dimension of dimensions) {
    const source = scope[dimension];
    if (!source) continue;
    if (source.kind === "subject") {
      if (!source.attribute) throw new Error(`Subject scope ${dimension} has an empty attribute`);
      constraints.push(Object.freeze({ dimension, kind: "subject", attribute: source.attribute }));
      continue;
    }

    /** Empty ids intentionally mean nowhere, so the whole AND grant contributes no authority. */
    const ids = new Set<string>();
    for (const id of source.ids) if (id) ids.add(id);
    if (ids.size === 0) return undefined;
    const sortedIds = [...ids];
    sortedIds.sort();
    constraints.push(Object.freeze({
      dimension,
      kind: "ids",
      ids: Object.freeze(sortedIds),
    }));
  }
  return Object.freeze(constraints);
}

/** Normalize, merge, and validate source validity once on the cold compiler path. */
function normalizeValidity(
  validity: AccessValidity | readonly AccessValidity[] | undefined,
): readonly NormalizedValidityWindow[] | undefined {
  if (validity === undefined) return undefined;
  const input = Array.isArray(validity) ? validity : [validity];
  if (input.length === 0) return Object.freeze([]);

  const windows: NormalizedValidityWindow[] = [];
  for (const window of input) {
    const start = window.startsAtEpochMs;
    const end = window.endsAtEpochMs;
    if (start !== undefined && !Number.isSafeInteger(start)) {
      throw new Error("startsAtEpochMs must be a safe integer");
    }
    if (end !== undefined && !Number.isSafeInteger(end)) {
      throw new Error("endsAtEpochMs must be a safe integer");
    }
    if (start !== undefined && end !== undefined) {
      if (start > end) throw new Error("startsAtEpochMs must not be after endsAtEpochMs");
      if (start === end) continue;
    }
    if (start === undefined && end === undefined) return undefined;
    windows.push(Object.freeze({
      ...(start === undefined ? {} : { startsAtEpochMs: start }),
      ...(end === undefined ? {} : { endsAtEpochMs: end }),
    }));
  }
  if (windows.length === 0) return Object.freeze([]);

  windows.sort((left, right) => {
    const leftStart = left.startsAtEpochMs ?? Number.NEGATIVE_INFINITY;
    const rightStart = right.startsAtEpochMs ?? Number.NEGATIVE_INFINITY;
    if (leftStart !== rightStart) return leftStart - rightStart;
    return (left.endsAtEpochMs ?? Number.POSITIVE_INFINITY) -
      (right.endsAtEpochMs ?? Number.POSITIVE_INFINITY);
  });

  const merged: NormalizedValidityWindow[] = [];
  for (const window of windows) {
    const previous = merged[merged.length - 1];
    if (!previous) {
      merged.push(window);
      continue;
    }
    const previousEnd = previous.endsAtEpochMs;
    const nextStart = window.startsAtEpochMs;
    if (previousEnd !== undefined && nextStart !== undefined && nextStart > previousEnd) {
      merged.push(window);
      continue;
    }

    const nextEnd = window.endsAtEpochMs;
    const end = previousEnd === undefined || nextEnd === undefined
      ? undefined
      : Math.max(previousEnd, nextEnd);
    merged[merged.length - 1] = Object.freeze({
      ...(previous.startsAtEpochMs === undefined
        ? {}
        : { startsAtEpochMs: previous.startsAtEpochMs }),
      ...(end === undefined ? {} : { endsAtEpochMs: end }),
    });
  }

  const only = merged.length === 1 ? merged[0] : undefined;
  if (only && only.startsAtEpochMs === undefined && only.endsAtEpochMs === undefined) return undefined;
  return Object.freeze(merged);
}

/** Expand assignment parents and implications into deterministic concrete runtime grants. */
export function compileAccessSnapshot<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string = string,
>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  args: CompileAccessArgs<Permission, Dimension, Attribute>,
): EffectiveAccessSnapshot<Leaf, Dimension, Attribute> {
  const pending = [...args.grants];
  const visited = new Set<string>();
  const compiled = new Map<string, CompiledGrantAccumulator<Leaf, Dimension, Attribute>>();

  for (let index = 0; index < pending.length; index += 1) {
    const sourceGrant = pending[index]!;
    if (!catalog.isPermission(sourceGrant.permission)) {
      throw new Error(`Unknown permission ${String(sourceGrant.permission)}`);
    }

    const normalized = normalizeConstraints(sourceGrant.scope);
    if (normalized === undefined) continue;
    const validity = normalizeValidity(sourceGrant.validity);
    if (validity && validity.length === 0) continue;

    // Scope-support metadata is an editor/adapter contract. Rechecking typed grants here would
    // duplicate every application's boundary validation; an extra scope can only narrow access.
    const sourceKey = JSON.stringify([sourceGrant.permission, normalized, validity ?? null]);
    if (visited.has(sourceKey)) continue;
    visited.add(sourceKey);

    // Parent nodes are assignment shorthand only; runtime snapshots contain concrete leaves.
    for (const leaf of catalog.leaves) {
      if (!catalog.includes(sourceGrant.permission, leaf)) continue;
      const grant: CompiledAccessGrant<Leaf, Dimension, Attribute> = Object.freeze({
        permission: leaf,
        constraints: normalized,
      });
      const key = compiledGrantKey(grant);
      let accumulator = compiled.get(key);
      if (!accumulator) {
        accumulator = { key, grant, timeless: false, windows: [] };
        compiled.set(key, accumulator);
      }
      if (validity === undefined) {
        accumulator.timeless = true;
        accumulator.windows.length = 0;
      } else if (!accumulator.timeless) {
        for (const window of validity) accumulator.windows.push(window);
      }

      // A parent inherits dependencies owned by every child it grants, including dependencies
      // outside the parent's own subtree. Those implied permissions keep the exact same validity and scope.
      const impliedByLeaf = leaf === sourceGrant.permission ? undefined : catalog.implies?.[leaf];
      if (impliedByLeaf) {
        for (const permission of impliedByLeaf) {
          pending.push({
            permission,
            ...(sourceGrant.scope ? { scope: sourceGrant.scope } : {}),
            ...(sourceGrant.validity === undefined ? {} : { validity: sourceGrant.validity }),
          });
        }
      }
    }

    const implied = catalog.implies?.[sourceGrant.permission];
    if (implied) {
      for (const permission of implied) {
        pending.push({
          permission,
          ...(sourceGrant.scope ? { scope: sourceGrant.scope } : {}),
          ...(sourceGrant.validity === undefined ? {} : { validity: sourceGrant.validity }),
        });
      }
    }
  }

  const ordered = [...compiled.values()];
  ordered.sort((left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0);
  const grants: CompiledAccessGrant<Leaf, Dimension, Attribute>[] = [];
  const temporalGrants: CompiledAccessGrant<Leaf, Dimension, Attribute>[] = [];
  const temporalGrantPositions: number[] = [];
  const initialGrantIndexes: number[] = [];
  const transitions = new Map<number, MutableCompiledTransition>();

  for (let orderedIndex = 0; orderedIndex < ordered.length; orderedIndex += 1) {
    const accumulator = ordered[orderedIndex]!;
    const windows = accumulator.timeless ? undefined : normalizeValidity(accumulator.windows);
    if (accumulator.timeless || windows === undefined) {
      grants.push(accumulator.grant);
      continue;
    }
    if (windows.length === 0) continue;

    const grantIndex = temporalGrants.length;
    temporalGrants.push(accumulator.grant);
    temporalGrantPositions.push(orderedIndex);
    for (const window of windows) {
      const start = window.startsAtEpochMs;
      const end = window.endsAtEpochMs;
      if (start === undefined) {
        initialGrantIndexes.push(grantIndex);
      } else {
        let transition = transitions.get(start);
        if (!transition) {
          transition = { addGrantIndexes: [], removeGrantIndexes: [] };
          transitions.set(start, transition);
        }
        transition.addGrantIndexes.push(grantIndex);
      }
      if (end !== undefined) {
        let transition = transitions.get(end);
        if (!transition) {
          transition = { addGrantIndexes: [], removeGrantIndexes: [] };
          transitions.set(end, transition);
        }
        transition.removeGrantIndexes.push(grantIndex);
      }
    }
  }

  Object.freeze(grants);
  let temporal: CompiledAccessTimeline<Leaf, Dimension, Attribute> | undefined;
  if (temporalGrants.length > 0) {
    const compiledTransitions: CompiledAccessTransition[] = [];
    const times = [...transitions.keys()];
    times.sort((left, right) => left - right);
    for (const atEpochMs of times) {
      const transition = transitions.get(atEpochMs)!;
      transition.addGrantIndexes.sort((left, right) => left - right);
      transition.removeGrantIndexes.sort((left, right) => left - right);
      compiledTransitions.push(Object.freeze({
        atEpochMs,
        addGrantIndexes: Object.freeze(transition.addGrantIndexes),
        removeGrantIndexes: Object.freeze(transition.removeGrantIndexes),
      }));
    }
    temporal = Object.freeze({
      grants: Object.freeze(temporalGrants),
      grantPositions: Object.freeze(temporalGrantPositions),
      initialGrantIndexes: Object.freeze(initialGrantIndexes),
      transitions: Object.freeze(compiledTransitions),
    });
  }

  /** Copy subject values into a plain deterministic object so snapshots are transport-safe. */
  let subject: Partial<Record<Attribute, string>> | undefined;
  if (args.subject) {
    const keys = Object.keys(args.subject) as Attribute[];
    keys.sort();
    for (const key of keys) {
      const value = args.subject[key];
      if (!value) continue;
      if (!subject) subject = {};
      subject[key] = value;
    }
  }

  if (subject) Object.freeze(subject);
  return Object.freeze({
    schemaVersion: 1,
    catalogId: catalog.catalogId,
    catalogVersion: catalog.catalogVersion,
    compilerVersion: catalog.compilerVersion,
    ...(args.sourceRevision !== undefined ? { sourceRevision: args.sourceRevision } : {}),
    ...(subject ? { subject } : {}),
    grants,
    ...(temporal ? { temporal } : {}),
  });
}

/** Create the same versioned snapshot shape with no grants for fail-closed publication. */
export function createDenyAllSnapshot<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string = string,
>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  sourceRevision?: string,
): EffectiveAccessSnapshot<Leaf, Dimension, Attribute> {
  return Object.freeze({
    schemaVersion: 1,
    catalogId: catalog.catalogId,
    catalogVersion: catalog.catalogVersion,
    compilerVersion: catalog.compilerVersion,
    ...(sourceRevision !== undefined ? { sourceRevision } : {}),
    grants: Object.freeze([]) as readonly CompiledAccessGrant<Leaf, Dimension, Attribute>[],
  });
}
