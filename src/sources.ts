import type { AccessCatalog } from "./catalog.js";
import { compileAccessSnapshot, type CompileAccessArgs } from "./compiler.js";
import type { AccessGrant, CompiledAccessGrant, EffectiveAccessSnapshot } from "./types.js";

/** One named bundle selected by the application, such as a profile, role, or direct assignment. */
export type AccessGrantSource<Permission extends string, Dimension extends string, Attribute extends string, SourceId extends string = string> = {
  /** Application identity used only to explain where authority came from. */
  id: SourceId;
  /** Additive grants from this source; source selection is application policy. */
  grants: readonly AccessGrant<Permission, Dimension, Attribute>[];
};

/** Compile several additive sources and retain their origins separately from the runtime snapshot. */
export type CompileAccessSourcesArgs<Permission extends string, Dimension extends string, Attribute extends string, SourceId extends string = string> =
  Omit<CompileAccessArgs<Permission, Dimension, Attribute>, "grants"> & {
    /** Bundles to union; a scoped bundle never restricts a broader grant from another bundle. */
    sources: readonly AccessGrantSource<Permission, Dimension, Attribute, SourceId>[];
  };

/** A compiled grant and the exact sources that contributed that permission/scope clause. */
export type AccessGrantContribution<Leaf extends string, Dimension extends string, Attribute extends string, SourceId extends string = string> = {
  /** Frozen concrete grant; it may be timeless or referenced by the compiled temporal timeline. */
  grant: CompiledAccessGrant<Leaf, Dimension, Attribute>;
  /** Source identities contributing this exact clause, including through parents or implications. */
  sourceIds: readonly SourceId[];
};

/** Cold-path inspection result; provenance never inflates the actor's hot snapshot. */
export type CompiledAccessSources<Leaf extends string, Dimension extends string, Attribute extends string, SourceId extends string = string> = {
  /** The same authority as compiling the concatenated input grants. */
  snapshot: EffectiveAccessSnapshot<Leaf, Dimension, Attribute>;
  /** Read-only origins for unique compiled clauses, kept outside the persisted snapshot. */
  contributions: readonly AccessGrantContribution<Leaf, Dimension, Attribute, SourceId>[];
};

/** Compile each bundle for provenance, then compile the complete union once so temporal windows merge correctly. */
export function compileAccessSources<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string, SourceId extends string>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  args: CompileAccessSourcesArgs<Permission, Dimension, Attribute, SourceId>,
): CompiledAccessSources<Leaf, Dimension, Attribute, SourceId> {
  /** Exact compiled clause -> contributing source ids. Repeated source entries do not repeat origin labels. */
  const origins = new Map<string, Set<SourceId>>();
  const grantsByKey = new Map<string, CompiledAccessGrant<Leaf, Dimension, Attribute>>();
  const combined: AccessGrant<Permission, Dimension, Attribute>[] = [];
  for (const source of args.sources) {
    for (const grant of source.grants) combined.push(grant);
    const compiled = compileAccessSnapshot(catalog, { grants: source.grants });
    for (const grant of compiled.grants) {
      const key = JSON.stringify([grant.permission, grant.constraints]);
      let sourceIds = origins.get(key);
      if (!sourceIds) {
        sourceIds = new Set<SourceId>();
        origins.set(key, sourceIds);
        grantsByKey.set(key, grant);
      }
      sourceIds.add(source.id);
    }
    if (compiled.temporal) {
      for (const grant of compiled.temporal.grants) {
        const key = JSON.stringify([grant.permission, grant.constraints]);
        let sourceIds = origins.get(key);
        if (!sourceIds) {
          sourceIds = new Set<SourceId>();
          origins.set(key, sourceIds);
          grantsByKey.set(key, grant);
        }
        sourceIds.add(source.id);
      }
    }
  }

  const snapshot = compileAccessSnapshot<Permission, Leaf, Dimension, Attribute>(catalog, {
    grants: combined,
    ...(args.subject ? { subject: args.subject } : {}),
    ...(args.sourceRevision !== undefined ? { sourceRevision: args.sourceRevision } : {}),
  });
  const keys = [...grantsByKey.keys()];
  keys.sort((left, right) => left < right ? -1 : left > right ? 1 : 0);
  const contributions: AccessGrantContribution<Leaf, Dimension, Attribute, SourceId>[] = [];
  for (const key of keys) {
    contributions.push(Object.freeze({
      grant: grantsByKey.get(key)!,
      sourceIds: Object.freeze([...origins.get(key)!]),
    }));
  }
  return Object.freeze({ snapshot, contributions: Object.freeze(contributions) });
}
