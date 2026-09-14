import type {
  AccessProjectionOptions,
  AccessEvaluator,
} from "./runtime.js";
import type {
  AccessContext,
  AccessQueryPlan,
  AllowedAccessValues,
  EffectiveAccessSnapshot,
} from "./types.js";

/** Snapshot-bound decision surface used when one request performs several checks at one temporal instant. */
export type AccessEvaluation<Leaf extends string, Dimension extends string> = {
  /** Inclusive lower transition bound for this materialized temporal state, when finite. */
  readonly validFromEpochMs?: number;
  /** Exclusive upper transition bound for this materialized temporal state, when finite. */
  readonly validUntilEpochMs?: number;
  /** Decide one concrete permission against the bound effective snapshot. */
  can(permission: Leaf, context?: AccessContext<Dimension>): boolean;
  /** Return whether any bound grant for this permission exists. */
  hasAny(permission: Leaf): boolean;
  /** Project allowed values from the bound effective snapshot. */
  allowedValues(
    permission: Leaf,
    dimension: Dimension,
    options?: AccessProjectionOptions<Dimension>,
  ): AllowedAccessValues;
  /** Project a correlated query plan from the bound effective snapshot. */
  queryPlan(
    permission: Leaf,
    options?: AccessProjectionOptions<Dimension>,
  ): AccessQueryPlan<Dimension>;
};

/** Canonical snapshot evaluation helpers layered over the unchanged timeless hot evaluator. */
export type AccessEvaluationFactory<
  Leaf extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Bind the snapshot's timeless grants without consulting its temporal timeline. */
  evaluate(
    snapshot: EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
  ): AccessEvaluation<Leaf, Dimension>;
  /** Bind authority effective at one instant, advancing or rewinding cached transitions only when needed. */
  evaluateAt(
    snapshot: EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
    atEpochMs: number,
  ): AccessEvaluation<Leaf, Dimension>;
};

/** Mutable per-snapshot cursor kept only inside one evaluator instance. */
type TemporalRuntimeState<Leaf extends string, Dimension extends string> = {
  /** False permanently fail-closes a malformed timeline. */
  accepted: boolean;
  /** Active bit for each unique temporal grant. */
  active: Uint8Array;
  /** Number of active temporal grants, avoiding a counting scan when materializing. */
  activeCount: number;
  /** Number of transitions already applied to `active`. */
  cursor: number;
  /** Bound evaluation already built for the cursor's current validity interval. */
  evaluation?: AccessEvaluation<Leaf, Dimension>;
};

/** Build snapshot-bound and temporal-aware ergonomics without adding any branch to `can()`. */
export function createAccessEvaluationFactory<
  Leaf extends string,
  Dimension extends string,
  Attribute extends string,
>(
  evaluator: AccessEvaluator<
    EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
    Leaf,
    Dimension
  >,
): AccessEvaluationFactory<Leaf, Dimension, Attribute> {
  /** Bound objects are immutable and reused by snapshot identity. */
  const evaluationCache = new WeakMap<
    EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
    AccessEvaluation<Leaf, Dimension>
  >();
  /** Temporal cursor state is separate so canonical snapshot objects stay immutable. */
  const temporalCache = new WeakMap<
    EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
    TemporalRuntimeState<Leaf, Dimension>
  >();

  /** Bind one already-effective snapshot to the normal evaluator exactly once. */
  function bind(
    snapshot: EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
    validFromEpochMs?: number,
    validUntilEpochMs?: number,
  ): AccessEvaluation<Leaf, Dimension> {
    const cached = evaluationCache.get(snapshot);
    if (cached) return cached;
    const evaluation: AccessEvaluation<Leaf, Dimension> = Object.freeze({
      ...(validFromEpochMs === undefined ? {} : { validFromEpochMs }),
      ...(validUntilEpochMs === undefined ? {} : { validUntilEpochMs }),
      can(permission: Leaf, context?: AccessContext<Dimension>) {
        return evaluator.can(snapshot, permission, context);
      },
      hasAny(permission: Leaf) {
        return evaluator.hasAny(snapshot, permission);
      },
      allowedValues(
        permission: Leaf,
        dimension: Dimension,
        options?: AccessProjectionOptions<Dimension>,
      ) {
        return evaluator.allowedValues(snapshot, permission, dimension, options);
      },
      queryPlan(permission: Leaf, options?: AccessProjectionOptions<Dimension>) {
        return evaluator.queryPlan(snapshot, permission, options);
      },
    });
    evaluationCache.set(snapshot, evaluation);
    return evaluation;
  }

  /** Build and validate the compact transition machine once per canonical snapshot object. */
  function initialTemporalState(
    snapshot: EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
  ): TemporalRuntimeState<Leaf, Dimension> {
    const timeline = snapshot.temporal!;
    const active = new Uint8Array(timeline.grants.length);
    let activeCount = 0;
    const grantPositions = timeline.grantPositions;
    let accepted =
      timeline.grants.length > 0 &&
      Array.isArray(grantPositions) &&
      grantPositions.length === timeline.grants.length;
    if (accepted) {
      let previousPosition = -1;
      const totalGrantCount = snapshot.grants.length + timeline.grants.length;
      for (const position of grantPositions) {
        if (
          !Number.isSafeInteger(position) ||
          position <= previousPosition ||
          position >= totalGrantCount
        ) {
          accepted = false;
          break;
        }
        previousPosition = position;
      }
    }
    for (const grantIndex of timeline.initialGrantIndexes) {
      if (
        !Number.isSafeInteger(grantIndex) ||
        grantIndex < 0 ||
        grantIndex >= active.length ||
        active[grantIndex] !== 0
      ) {
        accepted = false;
        break;
      }
      active[grantIndex] = 1;
      activeCount += 1;
    }

    // Validate all transition indexes and state changes once. No timeline validation occurs in later checks.
    if (accepted) {
      const simulated = active.slice();
      let previousTime: number | undefined;
      for (const transition of timeline.transitions) {
        if (
          !Number.isSafeInteger(transition.atEpochMs) ||
          (previousTime !== undefined && transition.atEpochMs <= previousTime)
        ) {
          accepted = false;
          break;
        }
        previousTime = transition.atEpochMs;
        for (const grantIndex of transition.removeGrantIndexes) {
          if (
            !Number.isSafeInteger(grantIndex) ||
            grantIndex < 0 ||
            grantIndex >= simulated.length ||
            simulated[grantIndex] !== 1
          ) {
            accepted = false;
            break;
          }
          simulated[grantIndex] = 0;
        }
        if (!accepted) break;
        for (const grantIndex of transition.addGrantIndexes) {
          if (
            !Number.isSafeInteger(grantIndex) ||
            grantIndex < 0 ||
            grantIndex >= simulated.length ||
            simulated[grantIndex] !== 0
          ) {
            accepted = false;
            break;
          }
          simulated[grantIndex] = 1;
        }
        if (!accepted) break;
      }
    }

    return { accepted, active, activeCount, cursor: 0 };
  }

  /** Materialize only the current interval after its transition cursor changes. */
  function materialize(
    snapshot: EffectiveAccessSnapshot<Leaf, Dimension, Attribute>,
    state: TemporalRuntimeState<Leaf, Dimension>,
  ): AccessEvaluation<Leaf, Dimension> {
    if (!state.accepted) {
      const denied: EffectiveAccessSnapshot<Leaf, Dimension, Attribute> = Object.freeze({
        schemaVersion: snapshot.schemaVersion,
        catalogId: snapshot.catalogId,
        catalogVersion: snapshot.catalogVersion,
        compilerVersion: snapshot.compilerVersion,
        ...(snapshot.sourceRevision === undefined ? {} : { sourceRevision: snapshot.sourceRevision }),
        grants: Object.freeze([]),
      });
      state.evaluation = bind(denied);
      return state.evaluation;
    }

    const timeline = snapshot.temporal!;
    const grants = new Array(snapshot.grants.length + state.activeCount) as Array<
      (typeof snapshot.grants)[number]
    >;
    let outputIndex = 0;
    let timelessIndex = 0;
    let temporalIndex = 0;
    const totalGrantCount = snapshot.grants.length + timeline.grants.length;
    for (let position = 0; position < totalGrantCount; position += 1) {
      if (
        temporalIndex < timeline.grantPositions.length &&
        timeline.grantPositions[temporalIndex] === position
      ) {
        if (state.active[temporalIndex] !== 0) {
          grants[outputIndex] = timeline.grants[temporalIndex]!;
          outputIndex += 1;
        }
        temporalIndex += 1;
        continue;
      }
      grants[outputIndex] = snapshot.grants[timelessIndex]!;
      outputIndex += 1;
      timelessIndex += 1;
    }
    Object.freeze(grants);

    const previousTransition = state.cursor === 0
      ? undefined
      : timeline.transitions[state.cursor - 1];
    const nextTransition = state.cursor === timeline.transitions.length
      ? undefined
      : timeline.transitions[state.cursor];
    const materialized: EffectiveAccessSnapshot<Leaf, Dimension, Attribute> = Object.freeze({
      schemaVersion: snapshot.schemaVersion,
      catalogId: snapshot.catalogId,
      catalogVersion: snapshot.catalogVersion,
      compilerVersion: snapshot.compilerVersion,
      ...(snapshot.sourceRevision === undefined ? {} : { sourceRevision: snapshot.sourceRevision }),
      ...(snapshot.subject === undefined ? {} : { subject: snapshot.subject }),
      grants,
    });
    state.evaluation = bind(
      materialized,
      previousTransition?.atEpochMs,
      nextTransition?.atEpochMs,
    );
    return state.evaluation;
  }

  return {
    evaluate(snapshot) {
      return bind(snapshot);
    },
    evaluateAt(snapshot, atEpochMs) {
      if (!Number.isSafeInteger(atEpochMs)) {
        throw new RangeError("atEpochMs must be a safe integer");
      }
      const timeline = snapshot.temporal;
      if (!timeline) return bind(snapshot);

      let state = temporalCache.get(snapshot);
      if (!state) {
        state = initialTemporalState(snapshot);
        temporalCache.set(snapshot, state);
      }
      if (!state.accepted) return state.evaluation ?? materialize(snapshot, state);

      const previousTransition = state.cursor === 0
        ? undefined
        : timeline.transitions[state.cursor - 1];
      const nextTransition = state.cursor === timeline.transitions.length
        ? undefined
        : timeline.transitions[state.cursor];
      if (
        state.evaluation &&
        (previousTransition === undefined || atEpochMs >= previousTransition.atEpochMs) &&
        (nextTransition === undefined || atEpochMs < nextTransition.atEpochMs)
      ) {
        return state.evaluation;
      }

      // Ordinary wall-clock use advances through only newly crossed transitions.
      while (
        state.cursor < timeline.transitions.length &&
        timeline.transitions[state.cursor]!.atEpochMs <= atEpochMs
      ) {
        const transition = timeline.transitions[state.cursor]!;
        for (const grantIndex of transition.removeGrantIndexes) {
          state.active[grantIndex] = 0;
          state.activeCount -= 1;
        }
        for (const grantIndex of transition.addGrantIndexes) {
          state.active[grantIndex] = 1;
          state.activeCount += 1;
        }
        state.cursor += 1;
      }

      // Historical/test callers can move backwards by reversing only the boundaries they cross.
      while (
        state.cursor > 0 &&
        timeline.transitions[state.cursor - 1]!.atEpochMs > atEpochMs
      ) {
        state.cursor -= 1;
        const transition = timeline.transitions[state.cursor]!;
        for (const grantIndex of transition.addGrantIndexes) {
          state.active[grantIndex] = 0;
          state.activeCount -= 1;
        }
        for (const grantIndex of transition.removeGrantIndexes) {
          state.active[grantIndex] = 1;
          state.activeCount += 1;
        }
      }

      return materialize(snapshot, state);
    },
  };
}
