import {
  compileAccessSources,
  type CompileAccessSourcesArgs,
  type CompiledAccessSources,
} from "./sources.js";
import {
  defineAccessCatalog,
  defineHierarchicalAccessCatalog,
  type AccessCatalog,
  type AccessCatalogDefinition,
  type HierarchicalAccessCatalogDefinition,
} from "./catalog.js";
import {
  compileAccessSnapshot,
  createDenyAllSnapshot,
  type CompileAccessArgs,
} from "./compiler.js";
import {
  createAccessEvaluationFactory,
  type AccessEvaluationFactory,
} from "./evaluation.js";
import {
  createAdaptedAccessEvaluator,
  createAccessEvaluator,
  type AccessEvaluator,
  type CompiledSnapshotAdapter,
} from "./runtime.js";
import {
  defineAccessRequestRule,
  type AccessRequestRule,
  type AccessRequestRuleDefinition,
} from "./request.js";
import type { EffectiveAccessSnapshot } from "./types.js";

/** Single-object facade that keeps catalog, compiler, and hot evaluator together. */
export type Access<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string = string,
> = AccessEvaluator<
  EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
  Leaf,
  Dimension
> & AccessEvaluationFactory<Leaf, Dimension, Attribute> & {
  /** Validated immutable catalog used by compilation and runtime generation checks. */
  catalog: AccessCatalog<Permission, Leaf, Dimension>;
  /** Compile editable source grants into one immutable runtime snapshot. */
  compile(
    args: CompileAccessArgs<Permission, Dimension, Attribute>,
  ): EffectiveAccessSnapshot<Leaf, Dimension, Attribute>;
  /** Compile an additive union with origins for editors; provenance is kept outside the runtime snapshot. */
  compileSources<SourceId extends string>(
    args: CompileAccessSourcesArgs<Permission, Dimension, Attribute, SourceId>,
  ): CompiledAccessSources<Leaf, Dimension, Attribute, SourceId>;
  /** Create an empty snapshot for explicit fail-closed publication or bootstrap states. */
  deny(sourceRevision?: string): EffectiveAccessSnapshot<Leaf, Dimension, Attribute>;
  /** Define one cold access-request authority ceiling using the same catalog semantics as normal grants. */
  requestRule(
    definition: AccessRequestRuleDefinition<Permission, Dimension, Attribute>,
  ): AccessRequestRule<Permission, Dimension, Attribute>;
  /** Reuse this catalog/evaluator semantics over an application's existing compiled snapshot shape. */
  adapt<Snapshot extends object, Grant>(
    adapter: CompiledSnapshotAdapter<Snapshot, Grant, Leaf, Dimension, Attribute>,
  ): AccessEvaluator<Snapshot, Leaf, Dimension>;
};

/** Build the public facade once from any validated catalog shape. */
function createAccessFromCatalog<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
): Access<Permission, Leaf, Dimension, Attribute> {
  const evaluator = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(catalog);
  const evaluations = createAccessEvaluationFactory(evaluator);
  return Object.freeze({
    catalog,
    compile(args: CompileAccessArgs<Permission, Dimension, Attribute>) {
      return compileAccessSnapshot<Permission, Leaf, Dimension, Attribute>(catalog, args);
    },
    compileSources<SourceId extends string>(
      args: CompileAccessSourcesArgs<Permission, Dimension, Attribute, SourceId>,
    ) {
      return compileAccessSources(catalog, args);
    },
    deny(sourceRevision?: string) {
      return createDenyAllSnapshot<Permission, Leaf, Dimension, Attribute>(
        catalog,
        sourceRevision,
      );
    },
    requestRule(definition: AccessRequestRuleDefinition<Permission, Dimension, Attribute>) {
      return defineAccessRequestRule(catalog, definition);
    },
    adapt<Snapshot extends object, Grant>(
      adapter: CompiledSnapshotAdapter<Snapshot, Grant, Leaf, Dimension, Attribute>,
    ) {
      return createAdaptedAccessEvaluator<
        Permission,
        Leaf,
        Dimension,
        Attribute,
        Snapshot,
        Grant
      >(catalog, adapter);
    },
    ...evaluator,
    ...evaluations,
  });
}

/** Define one access model and return its compiler/evaluator as a single declarative object. */
export function createAccess<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string = string,
>(
  definition: AccessCatalogDefinition<Permission, Leaf, Dimension>,
): Access<Permission, Leaf, Dimension, Attribute> {
  return createAccessFromCatalog<Permission, Leaf, Dimension, Attribute>(
    defineAccessCatalog(definition),
  );
}

/** Define a string-path permission tree and return the same one-object AccessOnce facade. */
export function createHierarchicalAccess<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string = string,
>(
  definition: HierarchicalAccessCatalogDefinition<Permission, Leaf, Dimension>,
): Access<Permission, Leaf, Dimension, Attribute> {
  return createAccessFromCatalog<Permission, Leaf, Dimension, Attribute>(
    defineHierarchicalAccessCatalog(definition),
  );
}
