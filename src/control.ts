import type { Access } from "./access.js";
import type { CompileAccessArgs } from "./compiler.js";
import {
  publishAccessChange,
  recoverAccessSnapshot,
  type AccessPublicationAdapter,
  type VersionedAccessSource,
} from "./publication.js";
import type { EffectiveAccessSnapshot } from "./types.js";

/** Inputs needed to bind one application authority source to AccessOnce's safe publication protocol. */
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

/** Backend control-plane operations for one versioned application authority source. */
export type AccessControlPlane<
  Source,
  Snapshot,
> = {
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
  }): Promise<Snapshot>;
  /** Recompile/publish the current durable source without changing it, for repair or invalidation. */
  materialize(subjectId: string): Promise<Snapshot>;
};

/** Create the recommended backend control-plane facade without prescribing a database or assignment schema. */
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
  return {
    read(subjectId) {
      return options.adapter.readSource(subjectId);
    },
    replace(args) {
      return publishAccessChange({
        catalog: options.access.catalog,
        adapter: options.adapter,
        subjectId: args.subjectId,
        expectedSourceRevision: args.expectedRevision,
        nextSource: args.source,
        compileSource: options.compileSource,
      });
    },
    materialize(subjectId) {
      return recoverAccessSnapshot(
        options.access.catalog,
        options.adapter,
        subjectId,
        options.compileSource,
      );
    },
  };
}
