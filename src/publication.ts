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

/** Context supplied while constructing an application's deny-first transition snapshot. */
export type AccessDenySnapshotArgs<Source> = {
  /** Subject whose authority is changing. */
  subjectId: string;
  /** Current durable source and revision observed under the subject lock. */
  current: VersionedAccessSource<Source>;
  /** Complete replacement source requested by the editor. */
  nextSource: Source;
};

/** Context supplied while compiling one app-owned runtime snapshot from the committed source. */
export type AccessCompileSnapshotArgs<Source> = {
  /** Subject whose snapshot is being built. */
  subjectId: string;
  /** Durable source that is now authoritative. */
  source: Source;
  /** Revision of that durable source. */
  sourceRevision: string;
};

/** App-owned snapshot construction used when the persisted runtime shape is not AccessOnce's native snapshot. */
export type AccessSnapshotPublication<Source, Snapshot> = {
  /** Build the restrictive snapshot written before a source replacement can become durable. */
  deny(args: AccessDenySnapshotArgs<Source>): Snapshot | Promise<Snapshot>;
  /** Build the final runtime snapshot from the committed source and its exact revision. */
  compile(args: AccessCompileSnapshotArgs<Source>): Snapshot | Promise<Snapshot>;
};

/** Inputs for one generic fail-closed application-snapshot publication. */
export type PublishAccessSnapshotChangeArgs<Source, Snapshot> = {
  /** Storage adapter providing locking, source CAS, and snapshot writes. */
  adapter: AccessPublicationAdapter<Source, Snapshot>;
  /** App-owned deny/final snapshot builders. */
  publication: AccessSnapshotPublication<Source, Snapshot>;
  /** Subject whose authority is changing. */
  subjectId: string;
  /** Revision the administrator/editor actually loaded. */
  expectedSourceRevision: string;
  /** Replacement application authority source. */
  nextSource: Source;
};

/**
 * Publish an application-owned deny snapshot before changing durable authority, then publish the final snapshot.
 * A crash can leave the subject denied, but the kernel never writes the new source before the deny snapshot.
 */
export async function publishAccessSnapshotChange<Source, Snapshot>(
  args: PublishAccessSnapshotChangeArgs<Source, Snapshot>,
): Promise<Snapshot> {
  return args.adapter.withSubjectLock(args.subjectId, async () => {
    const current = await args.adapter.readSource(args.subjectId);
    if (current.revision !== args.expectedSourceRevision) {
      throw new Error("Access source changed since this edit loaded");
    }

    const denied = await args.publication.deny({
      subjectId: args.subjectId,
      current,
      nextSource: args.nextSource,
    });
    await args.adapter.writeSnapshot(args.subjectId, denied);

    const written = await args.adapter.compareAndSetSource(
      args.subjectId,
      current.revision,
      args.nextSource,
    );
    const compiled = await args.publication.compile({
      subjectId: args.subjectId,
      source: written.source,
      sourceRevision: written.revision,
    });
    await args.adapter.writeSnapshot(args.subjectId, compiled);
    return compiled;
  });
}

/** Rebuild an application-owned runtime snapshot from the current durable source after a crash or repair job. */
export async function recoverPublishedAccessSnapshot<Source, Snapshot>(
  adapter: AccessPublicationAdapter<Source, Snapshot>,
  publication: Pick<AccessSnapshotPublication<Source, Snapshot>, "compile">,
  subjectId: string,
): Promise<Snapshot> {
  return adapter.withSubjectLock(subjectId, async () => {
    const current = await adapter.readSource(subjectId);
    const compiled = await publication.compile({
      subjectId,
      source: current.source,
      sourceRevision: current.revision,
    });
    await adapter.writeSnapshot(subjectId, compiled);
    return compiled;
  });
}

/** Inputs for one native AccessOnce snapshot source change. */
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
  adapter: AccessPublicationAdapter<
    Source,
    EffectiveAccessSnapshot<Leaf, Dimension, Attribute>
  >;
  /** Subject whose authority is changing. */
  subjectId: string;
  /** Revision the administrator/editor actually loaded. */
  expectedSourceRevision: string;
  /** Replacement application authority source. */
  nextSource: Source;
  /** Pure conversion from application authority source into AccessOnce source grants/subject attributes. */
  compileSource(
    source: Source,
  ): Omit<CompileAccessArgs<Permission, Dimension, Attribute>, "sourceRevision">;
};

/** Native-snapshot convenience wrapper around the generic fail-closed publication protocol. */
export async function publishAccessChange<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
>(
  args: PublishAccessChangeArgs<Permission, Leaf, Dimension, Attribute, Source>,
): Promise<EffectiveAccessSnapshot<Leaf, Dimension, Attribute>> {
  return publishAccessSnapshotChange({
    adapter: args.adapter,
    subjectId: args.subjectId,
    expectedSourceRevision: args.expectedSourceRevision,
    nextSource: args.nextSource,
    publication: {
      deny({ current }) {
        return createDenyAllSnapshot<Permission, Leaf, Dimension, Attribute>(
          args.catalog,
          `pending:${current.revision}`,
        );
      },
      compile({ source, sourceRevision }) {
        return compileAccessSnapshot(args.catalog, {
          ...args.compileSource(source),
          sourceRevision,
        });
      },
    },
  });
}

/** Native-snapshot convenience wrapper for rebuilding from the current durable source. */
export async function recoverAccessSnapshot<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  adapter: AccessPublicationAdapter<
    Source,
    EffectiveAccessSnapshot<Leaf, Dimension, Attribute>
  >,
  subjectId: string,
  compileSource: (
    source: Source,
  ) => Omit<CompileAccessArgs<Permission, Dimension, Attribute>, "sourceRevision">,
): Promise<EffectiveAccessSnapshot<Leaf, Dimension, Attribute>> {
  return recoverPublishedAccessSnapshot(
    adapter,
    {
      compile({ source, sourceRevision }) {
        return compileAccessSnapshot(catalog, {
          ...compileSource(source),
          sourceRevision,
        });
      },
    },
    subjectId,
  );
}
