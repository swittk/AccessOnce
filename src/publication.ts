import type { AccessCatalog } from "./catalog.js";
import { compileAccessSnapshot, createDenyAllSnapshot, type CompileAccessArgs } from "./compiler.js";
import type { EffectiveAccessSnapshot } from "./types.js";

/** Durable authority source plus its compare-and-set revision. */
export type VersionedAccessSource<Source> = {
  /** Revision used to reject concurrent admin edits. */
  revision: string;
  /** Application-owned profile/assignment/role source data. */
  source: Source;
};

/** Storage contract needed by AccessOnce's fail-closed source/snapshot publication helper. */
export type AccessPublicationAdapter<Source, Snapshot> = {
  /** Serialize changes for one subject without forcing AccessOnce to know the locking backend. */
  withSubjectLock<Result>(subjectId: string, work: () => Promise<Result>): Promise<Result>;
  /** Read the current durable authority source. */
  readSource(subjectId: string): Promise<VersionedAccessSource<Source>>;
  /** Replace the source only when its durable revision still matches the editor's revision. */
  compareAndSetSource(
    subjectId: string,
    expectedRevision: string,
    nextSource: Source,
  ): Promise<VersionedAccessSource<Source>>;
  /** Durably replace the subject's runtime authorization snapshot. */
  writeSnapshot(subjectId: string, snapshot: Snapshot): Promise<void>;
};

/** Inputs for one fail-closed authority-source change. */
export type PublishAccessChangeArgs<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
> = {
  /** Catalog that compiles the resulting source. */
  catalog: AccessCatalog<Permission, Leaf, Dimension>;
  /** Storage adapter providing locking, source CAS, and snapshot writes. */
  adapter: AccessPublicationAdapter<Source, EffectiveAccessSnapshot<Leaf, Dimension, Attribute>>;
  /** Subject whose authority is changing. */
  subjectId: string;
  /** Revision the administrator/editor actually loaded. */
  expectedSourceRevision: string;
  /** Replacement application authority source. */
  nextSource: Source;
  /** Pure conversion from application authority source into AccessOnce source grants/subject attributes. */
  compileSource(source: Source): Omit<CompileAccessArgs<Permission, Dimension, Attribute>, "sourceRevision">;
};

/**
 * Publish deny-all before changing durable authority, then publish the newly compiled snapshot.
 * A crash can leave a user denied, but can never leave removed authority accidentally usable.
 */
export async function publishAccessChange<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
>(
  args: PublishAccessChangeArgs<Permission, Leaf, Dimension, Attribute, Source>,
): Promise<EffectiveAccessSnapshot<Leaf, Dimension, Attribute>> {
  return args.adapter.withSubjectLock(args.subjectId, async () => {
    const current = await args.adapter.readSource(args.subjectId);
    if (current.revision !== args.expectedSourceRevision) {
      throw new Error("Access source changed since this edit loaded");
    }

    // Deny first. If the process dies after this write, stale broader authority is already gone.
    await args.adapter.writeSnapshot(
      args.subjectId,
      createDenyAllSnapshot<Permission, Leaf, Dimension, Attribute>(
        args.catalog,
        `pending:${current.revision}`,
      ),
    );

    const written = await args.adapter.compareAndSetSource(
      args.subjectId,
      current.revision,
      args.nextSource,
    );
    const compiled = compileAccessSnapshot(args.catalog, {
      ...args.compileSource(written.source),
      sourceRevision: written.revision,
    });
    await args.adapter.writeSnapshot(args.subjectId, compiled);
    return compiled;
  });
}

/** Rebuild a denied/stale runtime snapshot from the current durable source after a crash or repair job. */
export async function recoverAccessSnapshot<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  adapter: AccessPublicationAdapter<Source, EffectiveAccessSnapshot<Leaf, Dimension, Attribute>>,
  subjectId: string,
  compileSource: (
    source: Source,
  ) => Omit<CompileAccessArgs<Permission, Dimension, Attribute>, "sourceRevision">,
): Promise<EffectiveAccessSnapshot<Leaf, Dimension, Attribute>> {
  return adapter.withSubjectLock(subjectId, async () => {
    const current = await adapter.readSource(subjectId);
    const compiled = compileAccessSnapshot(catalog, {
      ...compileSource(current.source),
      sourceRevision: current.revision,
    });
    await adapter.writeSnapshot(subjectId, compiled);
    return compiled;
  });
}
