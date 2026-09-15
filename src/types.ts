/** String key naming one application-defined business permission. */
export type AccessPermission = string;

/** String key naming one application-defined scope dimension such as location or assignee. */
export type AccessScopeDimension = string;

/** String key naming one subject attribute used by a subject-relative scope constraint. */
export type AccessSubjectAttribute = string;

/** Fixed ids accepted by one scope dimension. */
export type AccessIdsScope = {
  /** Discriminator for a fixed-id scope. */
  kind: "ids";
  /** Allowed ids; an explicit empty array intentionally grants nothing. */
  ids: readonly string[];
};

/** Scope that matches a runtime value to one attribute on the current subject. */
export type AccessSubjectScope<Attribute extends string = string> = {
  /** Discriminator for subject-relative scope. */
  kind: "subject";
  /** Subject attribute whose value must equal the runtime scope value. */
  attribute: Attribute;
};

/** One source-grant scope restriction. Omitted dimensions are wildcards. */
export type AccessScopeSource<Attribute extends string = string> =
  | AccessIdsScope
  | AccessSubjectScope<Attribute>;

/** Half-open temporal validity window: `startsAtEpochMs <= t < endsAtEpochMs`. */
export type AccessValidity = {
  /** Optional inclusive activation time; omitted means active from the indefinite past. */
  startsAtEpochMs?: number;
  /** Optional exclusive expiry time; omitted means active indefinitely into the future. */
  endsAtEpochMs?: number;
};

/** Editable grant accepted by the cold compiler. */
export type AccessGrant<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Permission leaf or assignment-only parent node being granted. */
  permission: Permission;
  /** Optional scope restrictions. Missing dimensions are unrestricted. */
  scope?: Readonly<Partial<Record<Dimension, AccessScopeSource<Attribute>>>>;
  /** Optional one-or-many active windows; omitted means the grant is timeless. */
  validity?: AccessValidity | readonly AccessValidity[];
};

/** Normalized fixed-id constraint stored in a compiled snapshot. */
export type CompiledIdsConstraint<Dimension extends string> = {
  /** Scope dimension this constraint restricts. */
  dimension: Dimension;
  /** Discriminator for a fixed-id constraint. */
  kind: "ids";
  /** Sorted, unique ids accepted by this constraint. */
  ids: readonly string[];
};

/** Normalized subject-relative constraint stored in a compiled snapshot. */
export type CompiledSubjectConstraint<
  Dimension extends string,
  Attribute extends string,
> = {
  /** Scope dimension this constraint restricts. */
  dimension: Dimension;
  /** Discriminator for a subject-relative constraint. */
  kind: "subject";
  /** Subject attribute compared against the runtime dimension value. */
  attribute: Attribute;
};

/** One normalized runtime scope constraint. */
export type CompiledAccessConstraint<
  Dimension extends string,
  Attribute extends string = string,
> =
  | CompiledIdsConstraint<Dimension>
  | CompiledSubjectConstraint<Dimension, Attribute>;

/** Concrete leaf grant stored in an effective access snapshot. */
export type CompiledAccessGrant<
  Leaf extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Concrete leaf permission used by runtime lookups. */
  readonly permission: Leaf;
  /** Sorted constraints checked together as one AND clause. */
  readonly constraints: readonly CompiledAccessConstraint<Dimension, Attribute>[];
};

/** One compact temporal state change referencing the snapshot's unique temporal-grant table. */
export type CompiledAccessTransition = {
  /** Instant at which this transition becomes effective. */
  readonly atEpochMs: number;
  /** Temporal grant indexes activated at this instant. */
  readonly addGrantIndexes: readonly number[];
  /** Temporal grant indexes deactivated at this instant. */
  readonly removeGrantIndexes: readonly number[];
};

/** Compact timeline kept outside the timeless hot grant array. */
export type CompiledAccessTimeline<
  Leaf extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Unique temporal grants referenced by numeric indexes from the timeline. */
  readonly grants: readonly CompiledAccessGrant<Leaf, Dimension, Attribute>[];
  /** Global canonical grant position for each temporal grant, preserving deterministic projection order. */
  readonly grantPositions: readonly number[];
  /** Grant indexes active before the first transition, for validity windows without a start. */
  readonly initialGrantIndexes: readonly number[];
  /** Strictly increasing grouped state transitions. */
  readonly transitions: readonly CompiledAccessTransition[];
};

/** Versioned, transport-safe runtime authorization snapshot. */
export type EffectiveAccessSnapshot<
  Leaf extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** AccessOnce snapshot shape version. */
  readonly schemaVersion: 1;
  /** Application catalog id that compiled this snapshot. */
  readonly catalogId: string;
  /** Application-owned catalog version. */
  readonly catalogVersion: number;
  /** Access compiler behavior version chosen by the application. */
  readonly compilerVersion: number;
  /** Optional source revision for diagnostics and publication recovery. */
  readonly sourceRevision?: string;
  /** Small subject attributes needed by subject-relative constraints. */
  readonly subject?: Readonly<Partial<Record<Attribute, string>>>;
  /** Timeless concrete grants; parent permissions never survive here. */
  readonly grants: readonly CompiledAccessGrant<Leaf, Dimension, Attribute>[];
  /** Optional compact temporal authority; normal timeless evaluation ignores this field entirely. */
  readonly temporal?: CompiledAccessTimeline<Leaf, Dimension, Attribute>;
};

/** Trusted runtime values describing the row or operation being authorized. */
export type AccessContext<Dimension extends string> = Readonly<
  Partial<Record<Dimension, string>>
>;

/** Bounded set of ids available for one dimension. */
export type AllowedAccessValues =
  | {
      /** No value in this dimension is authorized. */
      kind: "none";
    }
  | {
      /** This dimension is unrestricted by at least one matching grant. */
      kind: "all";
    }
  | {
      /** Only the returned bounded values are authorized. */
      kind: "some";
      /** Authorized ids for this dimension. */
      values: readonly string[];
    };

/** One AND clause emitted for a database/query adapter. */
export type AccessQueryClause<Dimension extends string> = Readonly<
  Partial<Record<Dimension, readonly string[]>>
>;

/** OR-of-AND query plan preserving correlations between scope dimensions. */
export type AccessQueryPlan<Dimension extends string> =
  | {
      /** Query must match no rows. */
      kind: "none";
    }
  | {
      /** Query needs no authorization predicate. */
      kind: "all";
    }
  | {
      /** Query must OR the supplied correlated AND clauses. */
      kind: "some";
      /** Correlated scope clauses that must not be flattened into independent dimension unions. */
      clauses: readonly AccessQueryClause<Dimension>[];
    };
