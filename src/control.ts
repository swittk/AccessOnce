import type { Access } from "./access.js";
import type { CompileAccessArgs } from "./compiler.js";
import {
  publishAccessSnapshotChange,
  recoverPublishedAccessSnapshot,
  type AccessPublicationAdapter,
  type AccessSnapshotPublication,
  type VersionedAccessSnapshot,
  type VersionedAccessSource,
} from "./publication.js";
import type { EffectiveAccessSnapshot } from "./types.js";

/** Backend control-plane operations for one versioned application authority source. */
export type AccessControlPlane<Source, Snapshot> = {
  /** Read the current durable assignment/policy source and its compare-and-set revision. */
  read(subjectId: string): Promise<VersionedAccessSource<Source>>;
  /** Safely replace authority: deny first, CAS the source, compile, then publish the new snapshot. */
  replace(args: {
    /** Subject whose authority is being replaced. */
    subjectId: string;
    /** Revision the administrator actually loaded. */
    expectedRevision: string;
    /** Complete replacement application source. */
    source: Source;
  }): Promise<VersionedAccessSnapshot<Snapshot>>;
  /** Recompile/publish the current durable source without changing it, for repair or invalidation. */
  materialize(subjectId: string): Promise<VersionedAccessSnapshot<Snapshot>>;
};

/** Generic control-plane options for applications that persist their own runtime snapshot shape. */
export type AccessPublicationControlPlaneOptions<Source, Snapshot> = {
  /** BYO durable source/snapshot storage with subject locking and source CAS. */
  adapter: AccessPublicationAdapter<Source, Snapshot>;
  /** App-owned deny/final snapshot construction; may be synchronous or asynchronous. */
  publication: AccessSnapshotPublication<Source, Snapshot>;
};

/** Create the fail-closed backend control plane for any application-owned runtime snapshot shape. */
export function createAccessPublicationControlPlane<Source, Snapshot>(
  options: AccessPublicationControlPlaneOptions<Source, Snapshot>,
): AccessControlPlane<Source, Snapshot> {
  return {
    read(subjectId) {
      return options.adapter.readSource(subjectId);
    },
    replace(args) {
      return publishAccessSnapshotChange({
        adapter: options.adapter,
        publication: options.publication,
        subjectId: args.subjectId,
        expectedSourceRevision: args.expectedRevision,
        nextSource: args.source,
      });
    },
    materialize(subjectId) {
      return recoverPublishedAccessSnapshot(
        options.adapter,
        options.publication,
        subjectId,
      );
    },
  };
}

/** Inputs needed to bind one application authority source to AccessOnce's native snapshot compiler. */
export type AccessControlPlaneOptions<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
> = {
  /** Access model whose catalog/compiler semantics produce the runtime snapshot. */
  access: Access<Permission, Leaf, Dimension, Attribute>;
  /** BYO durable source/snapshot storage with subject locking and source CAS. */
  adapter: AccessPublicationAdapter<
    Source,
    EffectiveAccessSnapshot<Leaf, Dimension, Attribute>
  >;
  /** Pure application mapping from assignment/profile/role source into AccessOnce grants and subject data. */
  compileSource(
    source: Source,
  ): Omit<CompileAccessArgs<Permission, Dimension, Attribute>, "sourceRevision">;
};

/** Create the recommended native-snapshot control plane over the generic publication protocol. */
export function createAccessControlPlane<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
>(
  options: AccessControlPlaneOptions<
    Permission,
    Leaf,
    Dimension,
    Attribute,
    Source
  >,
): AccessControlPlane<
  Source,
  EffectiveAccessSnapshot<Leaf, Dimension, Attribute>
> {
  return createAccessPublicationControlPlane({
    adapter: options.adapter,
    publication: {
      deny({ current }) {
        return options.access.deny(`pending:${current.revision}`);
      },
      compile({ source, sourceRevision }) {
        return options.access.compile({
          ...options.compileSource(source),
          sourceRevision,
        });
      },
    },
  });
}
