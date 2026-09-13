import type { AccessCatalog } from "./catalog.js";
import type {
  AccessGrant,
  CompiledAccessConstraint,
  CompiledAccessGrant,
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
  const compiled = new Map<string, CompiledAccessGrant<Leaf, Dimension, Attribute>>();

  for (let index = 0; index < pending.length; index += 1) {
    const sourceGrant = pending[index]!;
    if (!catalog.isPermission(sourceGrant.permission)) {
      throw new Error(`Unknown permission ${String(sourceGrant.permission)}`);
    }

    const normalized = normalizeConstraints(sourceGrant.scope);
    if (normalized === undefined) continue;

    // Scope-support metadata is an editor/adapter contract. Rechecking typed grants here would
    // duplicate every application's boundary validation; an extra scope can only narrow access.
    const sourceKey = JSON.stringify([sourceGrant.permission, normalized]);
    if (visited.has(sourceKey)) continue;
    visited.add(sourceKey);

    // Parent nodes are assignment shorthand only; runtime snapshots contain concrete leaves.
    for (const leaf of catalog.leaves) {
      if (!catalog.includes(sourceGrant.permission, leaf)) continue;
      const grant: CompiledAccessGrant<Leaf, Dimension, Attribute> = Object.freeze({
        permission: leaf,
        constraints: normalized,
      });
      compiled.set(compiledGrantKey(grant), grant);

      // A parent inherits dependencies owned by every child it grants, including dependencies
      // outside the parent's own subtree. Those implied permissions keep the same scope.
      const impliedByLeaf = leaf === sourceGrant.permission ? undefined : catalog.implies?.[leaf];
      if (impliedByLeaf) {
        for (const permission of impliedByLeaf) {
          pending.push({
            permission,
            ...(sourceGrant.scope ? { scope: sourceGrant.scope } : {}),
          });
        }
      }
    }

    const implied = catalog.implies?.[sourceGrant.permission];
    if (implied) {
      for (const permission of implied) {
        pending.push({ permission, ...(sourceGrant.scope ? { scope: sourceGrant.scope } : {}) });
      }
    }
  }

  const grants = [...compiled.values()];
  grants.sort((left, right) => compiledGrantKey(left).localeCompare(compiledGrantKey(right)));
  Object.freeze(grants);

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
    ...(args.sourceRevision ? { sourceRevision: args.sourceRevision } : {}),
    ...(subject ? { subject } : {}),
    grants,
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
    ...(sourceRevision ? { sourceRevision } : {}),
    grants: Object.freeze([]) as readonly CompiledAccessGrant<Leaf, Dimension, Attribute>[],
  });
}
