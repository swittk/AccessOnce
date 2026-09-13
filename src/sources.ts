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
  /** Frozen concrete grant; also present in the compiled snapshot. */
  grant: CompiledAccessGrant<Leaf, Dimension, Attribute>;
  /** Source identities contributing this exact clause, including through parents or implications. */
  sourceIds: readonly SourceId[];
};

/** Cold-path inspection result; provenance never inflates the actor's hot snapshot. */
export type CompiledAccessSources<Leaf extends string, Dimension extends string, Attribute extends string, SourceId extends string = string> = {
  /** The same authority as compiling the concatenated input grants. */
  snapshot: EffectiveAccessSnapshot<Leaf, Dimension, Attribute>;
  /** Read-only origins, ordered like the snapshot grants and kept outside the persisted snapshot. */
  contributions: readonly AccessGrantContribution<Leaf, Dimension, Attribute, SourceId>[];
};

/** Compile each bundle once and union complete scope clauses without inventing cross-source scope combinations. */
export function compileAccessSources<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string, SourceId extends string>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  args: CompileAccessSourcesArgs<Permission, Dimension, Attribute, SourceId>,
): CompiledAccessSources<Leaf, Dimension, Attribute, SourceId> {
  /** Exact compiled clause -> contributing source ids. Repeated source entries do not repeat origin labels. */
  const origins = new Map<string, Set<SourceId>>();
  const grantsByKey = new Map<string, CompiledAccessGrant<Leaf, Dimension, Attribute>>();
  for (const source of args.sources) {
    const compiled = compileAccessSnapshot(catalog, { grants: source.grants });
    for (const grant of compiled.grants) {
      // The compiler already sorted/uniqued every constraint. Whole clauses, not individual dimensions, are unioned.
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

  const keys = [...grantsByKey.keys()].sort((left, right) => left.localeCompare(right));
  const grants: CompiledAccessGrant<Leaf, Dimension, Attribute>[] = [];
  const contributions: AccessGrantContribution<Leaf, Dimension, Attribute, SourceId>[] = [];
  for (const key of keys) {
    const grant = grantsByKey.get(key)!;
    grants.push(grant);
    contributions.push(Object.freeze({ grant, sourceIds: Object.freeze([...origins.get(key)!]) }));
  }
  // Reuse the compiler's metadata/subject rules without expanding the union a second time.
  const metadata = compileAccessSnapshot<Permission, Leaf, Dimension, Attribute>(catalog, {
    grants: [],
    ...(args.subject ? { subject: args.subject } : {}),
    ...(args.sourceRevision !== undefined ? { sourceRevision: args.sourceRevision } : {}),
  });
  const snapshot: EffectiveAccessSnapshot<Leaf, Dimension, Attribute> = Object.freeze({
    ...metadata,
    grants: Object.freeze(grants),
  });
  return Object.freeze({ snapshot, contributions: Object.freeze(contributions) });
}
