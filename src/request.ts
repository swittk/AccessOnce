import type { AccessCatalog } from "./catalog.js";
import { compileAccessSnapshot } from "./compiler.js";
import type {
  AccessGrant,
  AccessScopeSource,
  AccessValidity,
  CompiledAccessConstraint,
  CompiledAccessGrant,
} from "./types.js";

/** Application-owned approval routing decision attached to one request policy. */
export type AccessRequestApproval =
  | {
      /** Automatically commit valid requests without a human approval route. */
      kind: "automatic";
    }
  | {
      /** Resolve a current application approval route identified by this opaque policy id. */
      kind: "policy";
      /** Application-owned identifier used to resolve approvers without embedding users in AccessOnce. */
      policyId: string;
    };

/** Optional policy-wide bounds on temporal authority a requester may ask for. */
export type AccessRequestValidityLimits = {
  /** Whether timeless or one-sided validity may be requested; defaults to true unless duration is bounded. */
  allowUnbounded?: boolean;
  /** Maximum number of validity windows submitted on one request before merging overlaps. */
  maximumWindows?: number;
  /** Maximum total duration after overlapping bounded windows are merged. */
  maximumDurationMs?: number;
};

/** Declarative authority ceiling selected by an application for one request workflow. */
export type AccessRequestPolicyDefinition<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Stable application-owned request policy identifier. */
  policyId: string;
  /** Grants whose compiled authority forms the maximum requestable union. */
  ceilings: readonly AccessGrant<Permission, Dimension, Attribute>[];
  /** Automatic or application-routed approval behavior. */
  approval: AccessRequestApproval;
  /** Optional temporal limits applied in addition to grant-ceiling validity. */
  validity?: AccessRequestValidityLimits;
};

/** Coarse fail-closed reason returned when a requested authority is outside its selected policy. */
export type AccessRequestDenialReason =
  | "invalid-request"
  | "empty-request"
  | "permission-not-requestable"
  | "scope-not-requestable"
  | "validity-not-requestable";

/** Result of checking one exact requested grant against an application-selected request policy. */
export type AccessRequestEvaluation =
  | {
      /** True when every compiled permission/scope/time clause is within the policy ceiling. */
      requestable: true;
      /** Stable policy that proved the request. */
      policyId: string;
      /** Approval behavior to use when the request is submitted. */
      approval: AccessRequestApproval;
    }
  | {
      /** False when the request fails closed. */
      requestable: false;
      /** Intentionally coarse denial category that avoids leaking unnecessary policy detail. */
      reason: AccessRequestDenialReason;
    };

/** Trusted subject attributes used only to resolve subject-relative request-ceiling comparisons. */
export type AccessRequestSubject<Attribute extends string> = Readonly<
  Partial<Record<Attribute, string>>
>;

/** Cold request-policy evaluator; applications decide whether this policy is applicable or advertised. */
export type AccessRequestPolicy<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Stable application-owned policy identifier. */
  readonly policyId: string;
  /** Approval behavior carried by this policy. */
  readonly approval: AccessRequestApproval;
  /** Evaluate one exact requested grant against the compiled authority ceiling. */
  evaluate(args: {
    /** Exact authority being requested. */
    grant: AccessGrant<Permission, Dimension, Attribute>;
    /** Current subject values needed only for subject-relative ceiling proof. */
    subject?: AccessRequestSubject<Attribute>;
  }): AccessRequestEvaluation;
  /** Boolean convenience for callers that do not need the coarse denial reason. */
  canRequest(args: {
    /** Exact authority being requested. */
    grant: AccessGrant<Permission, Dimension, Attribute>;
    /** Current subject values needed only for subject-relative ceiling proof. */
    subject?: AccessRequestSubject<Attribute>;
  }): boolean;
};

/** One normalized half-open interval; omitted bounds represent negative/positive infinity. */
type RequestValidityWindow = {
  /** Inclusive lower bound when present. */
  startsAtEpochMs?: number;
  /** Exclusive upper bound when present. */
  endsAtEpochMs?: number;
};

/** Normalized validity plus submitted-window metadata used by request-limit checks. */
type RequestValiditySummary = {
  /** Number of windows supplied by the caller before normalization. */
  submittedWindows: number;
  /** Canonical disjoint windows; empty means the request contributes no authority. */
  windows: readonly RequestValidityWindow[];
  /** True when any canonical interval is timeless or one-sided. */
  unbounded: boolean;
};

/** One concrete compiled leaf/scope clause paired with the source grant's normalized validity. */
type RequestAuthorityClause<Leaf extends string, Dimension extends string, Attribute extends string> = {
  /** Concrete leaf produced by parent/implication compilation. */
  grant: CompiledAccessGrant<Leaf, Dimension, Attribute>;
  /** Canonical temporal coverage carried by the source grant. */
  windows: readonly RequestValidityWindow[];
};

/** Require a positive safe integer when a request-policy bound is configured. */
function requirePositiveSafeInteger(value: number | undefined, label: string): void {
  if (value !== undefined && (!Number.isSafeInteger(value) || value < 1)) {
    throw new Error(`${label} must be a positive safe integer`);
  }
}

/** Normalize one validity input using the same half-open interval semantics as the access compiler. */
function normalizeRequestValidity(
  validity: AccessValidity | readonly AccessValidity[] | undefined,
): RequestValiditySummary {
  if (validity === undefined) {
    return { submittedWindows: 1, windows: Object.freeze([Object.freeze({})]), unbounded: true };
  }
  const input = Array.isArray(validity) ? validity : [validity];
  const submittedWindows = input.length;
  const windows: RequestValidityWindow[] = [];
  for (const window of input) {
    const start = window.startsAtEpochMs;
    const end = window.endsAtEpochMs;
    if (start !== undefined && !Number.isSafeInteger(start)) {
      throw new Error("startsAtEpochMs must be a safe integer");
    }
    if (end !== undefined && !Number.isSafeInteger(end)) {
      throw new Error("endsAtEpochMs must be a safe integer");
    }
    if (start !== undefined && end !== undefined) {
      if (start > end) throw new Error("startsAtEpochMs must not be after endsAtEpochMs");
      if (start === end) continue;
    }
    windows.push(Object.freeze({
      ...(start === undefined ? {} : { startsAtEpochMs: start }),
      ...(end === undefined ? {} : { endsAtEpochMs: end }),
    }));
  }
  if (windows.length === 0) {
    return { submittedWindows, windows: Object.freeze([]), unbounded: false };
  }
  windows.sort((left, right) => {
    const leftStart = left.startsAtEpochMs ?? Number.NEGATIVE_INFINITY;
    const rightStart = right.startsAtEpochMs ?? Number.NEGATIVE_INFINITY;
    if (leftStart !== rightStart) return leftStart - rightStart;
    return (left.endsAtEpochMs ?? Number.POSITIVE_INFINITY) -
      (right.endsAtEpochMs ?? Number.POSITIVE_INFINITY);
  });
  const merged: RequestValidityWindow[] = [];
  for (const window of windows) {
    const previous = merged[merged.length - 1];
    if (!previous) {
      merged.push(window);
      continue;
    }
    const previousEnd = previous.endsAtEpochMs;
    const nextStart = window.startsAtEpochMs;
    if (previousEnd !== undefined && nextStart !== undefined && nextStart > previousEnd) {
      merged.push(window);
      continue;
    }
    const nextEnd = window.endsAtEpochMs;
    const end = previousEnd === undefined || nextEnd === undefined
      ? undefined
      : Math.max(previousEnd, nextEnd);
    merged[merged.length - 1] = Object.freeze({
      ...(previous.startsAtEpochMs === undefined ? {} : { startsAtEpochMs: previous.startsAtEpochMs }),
      ...(end === undefined ? {} : { endsAtEpochMs: end }),
    });
  }
  let unbounded = false;
  for (const window of merged) {
    if (window.startsAtEpochMs === undefined || window.endsAtEpochMs === undefined) {
      unbounded = true;
      break;
    }
  }
  return { submittedWindows, windows: Object.freeze(merged), unbounded };
}

/** Validate one typed grant when it is used as cold request-policy or direct-policy input. */
function validateRequestGrant<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  grant: AccessGrant<Permission, Dimension, Attribute>,
  label: string,
): void {
  if (!catalog.isPermission(grant.permission)) throw new Error(`${label} uses an unknown permission`);
  if (grant.scope) {
    const supported = catalog.supportedScopeDimensions(grant.permission);
    for (const rawDimension of Object.keys(grant.scope)) {
      if (!supported.has(rawDimension as Dimension)) {
        throw new Error(`${label} uses unsupported scope dimension ${rawDimension}`);
      }
      const source = grant.scope[rawDimension as Dimension];
      if (!source) continue;
      if (source.kind === "subject") {
        if (!source.attribute) throw new Error(`${label} has an empty subject attribute`);
        continue;
      }
      for (const id of source.ids) {
        if (!id) throw new Error(`${label} has an empty scope id`);
      }
    }
  }
  normalizeRequestValidity(grant.validity);
}

/** Compile one source grant through the real catalog so parents and implications cannot diverge from authorization semantics. */
function compileRequestGrantClauses<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  grant: AccessGrant<Permission, Dimension, Attribute>,
): readonly RequestAuthorityClause<Leaf, Dimension, Attribute>[] {
  const validity = normalizeRequestValidity(grant.validity);
  const snapshot = compileAccessSnapshot<Permission, Leaf, Dimension, Attribute>(catalog, { grants: [grant] });
  const clauses: RequestAuthorityClause<Leaf, Dimension, Attribute>[] = [];
  for (const compiled of snapshot.grants) clauses.push({ grant: compiled, windows: validity.windows });
  if (snapshot.temporal) {
    for (const compiled of snapshot.temporal.grants) clauses.push({ grant: compiled, windows: validity.windows });
  }
  return Object.freeze(clauses);
}

/** Return whether one requested compiled scope clause is no broader than one ceiling clause. */
function requestScopeCovered<Dimension extends string, Attribute extends string>(
  requested: readonly CompiledAccessConstraint<Dimension, Attribute>[],
  ceiling: readonly CompiledAccessConstraint<Dimension, Attribute>[],
  subject: AccessRequestSubject<Attribute> | undefined,
): boolean {
  for (const ceilingConstraint of ceiling) {
    let requestedConstraint: CompiledAccessConstraint<Dimension, Attribute> | undefined;
    for (const candidate of requested) {
      if (candidate.dimension === ceilingConstraint.dimension) {
        requestedConstraint = candidate;
        break;
      }
    }
    if (!requestedConstraint) return false;
    if (ceilingConstraint.kind === "ids") {
      if (requestedConstraint.kind !== "ids") return false;
      const allowed = new Set(ceilingConstraint.ids);
      for (const id of requestedConstraint.ids) if (!allowed.has(id)) return false;
      continue;
    }
    if (requestedConstraint.kind === "subject") {
      if (requestedConstraint.attribute !== ceilingConstraint.attribute) return false;
      continue;
    }
    const subjectValue = subject?.[ceilingConstraint.attribute];
    if (subjectValue === undefined) return false;
    for (const id of requestedConstraint.ids) if (id !== subjectValue) return false;
  }
  return true;
}

/** Return whether one half-open requested interval is fully contained by one ceiling interval. */
function requestWindowCovered(requested: RequestValidityWindow, ceiling: RequestValidityWindow): boolean {
  if (requested.startsAtEpochMs === undefined) {
    if (ceiling.startsAtEpochMs !== undefined) return false;
  } else if (ceiling.startsAtEpochMs !== undefined && ceiling.startsAtEpochMs > requested.startsAtEpochMs) {
    return false;
  }
  if (requested.endsAtEpochMs === undefined) {
    return ceiling.endsAtEpochMs === undefined;
  }
  return ceiling.endsAtEpochMs === undefined || ceiling.endsAtEpochMs >= requested.endsAtEpochMs;
}

/** Return whether every requested validity interval is contained by this single correlated ceiling clause. */
function requestValidityCovered(
  requested: readonly RequestValidityWindow[],
  ceiling: readonly RequestValidityWindow[],
): boolean {
  for (const requestWindow of requested) {
    let covered = false;
    for (const ceilingWindow of ceiling) {
      if (requestWindowCovered(requestWindow, ceilingWindow)) {
        covered = true;
        break;
      }
    }
    if (!covered) return false;
  }
  return true;
}

/** Apply policy-wide temporal limits independently of each ceiling grant's own temporal coverage. */
function requestWithinValidityLimits(
  summary: RequestValiditySummary,
  limits: AccessRequestValidityLimits | undefined,
): boolean {
  if (!limits) return true;
  if (limits.maximumWindows !== undefined && summary.submittedWindows > limits.maximumWindows) return false;
  if (summary.unbounded && (limits.allowUnbounded === false || limits.maximumDurationMs !== undefined)) return false;
  if (limits.maximumDurationMs === undefined) return true;
  let total = 0;
  for (const window of summary.windows) {
    if (window.startsAtEpochMs === undefined || window.endsAtEpochMs === undefined) return false;
    total += window.endsAtEpochMs - window.startsAtEpochMs;
    if (!Number.isSafeInteger(total) || total > limits.maximumDurationMs) return false;
  }
  return true;
}

/** Create a cold request ceiling that proves exact AccessGrant authority without touching the hot evaluator. */
export function defineAccessRequestPolicy<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string = string>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  definition: AccessRequestPolicyDefinition<Permission, Dimension, Attribute>,
): AccessRequestPolicy<Permission, Dimension, Attribute> {
  if (!definition.policyId.trim()) throw new Error("request policyId must not be empty");
  if (definition.ceilings.length === 0) throw new Error("request policy ceilings must not be empty");
  if (definition.approval.kind === "policy" && !definition.approval.policyId.trim()) {
    throw new Error("request approval policyId must not be empty");
  }
  requirePositiveSafeInteger(definition.validity?.maximumWindows, "maximumWindows");
  requirePositiveSafeInteger(definition.validity?.maximumDurationMs, "maximumDurationMs");

  const ceilings: RequestAuthorityClause<Leaf, Dimension, Attribute>[] = [];
  for (const ceiling of definition.ceilings) {
    validateRequestGrant(catalog, ceiling, "request policy ceiling");
    for (const clause of compileRequestGrantClauses(catalog, ceiling)) ceilings.push(clause);
  }
  if (ceilings.length === 0) throw new Error("request policy ceilings grant no authority");
  const policyId = definition.policyId;
  const approval = Object.freeze({ ...definition.approval }) as AccessRequestApproval;
  const limits = definition.validity === undefined ? undefined : Object.freeze({ ...definition.validity });

  /** Evaluate one grant using the immutable compiled policy ceiling. */
  function evaluate(args: {
    /** Exact authority being requested. */
    grant: AccessGrant<Permission, Dimension, Attribute>;
    /** Current subject values needed for subject-relative proof. */
    subject?: AccessRequestSubject<Attribute>;
  }): AccessRequestEvaluation {
    let requested: readonly RequestAuthorityClause<Leaf, Dimension, Attribute>[];
    let validity: RequestValiditySummary;
    try {
      validateRequestGrant(catalog, args.grant, "access request");
      validity = normalizeRequestValidity(args.grant.validity);
      requested = compileRequestGrantClauses(catalog, args.grant);
    } catch {
      return { requestable: false, reason: "invalid-request" };
    }
    if (requested.length === 0 || validity.windows.length === 0) {
      return { requestable: false, reason: "empty-request" };
    }
    if (!requestWithinValidityLimits(validity, limits)) {
      return { requestable: false, reason: "validity-not-requestable" };
    }

    for (const requestClause of requested) {
      let permissionMatch = false;
      let scopeMatch = false;
      let validityMatch = false;
      for (const ceilingClause of ceilings) {
        if (ceilingClause.grant.permission !== requestClause.grant.permission) continue;
        permissionMatch = true;
        if (!requestScopeCovered(
          requestClause.grant.constraints,
          ceilingClause.grant.constraints,
          args.subject,
        )) continue;
        scopeMatch = true;
        if (!requestValidityCovered(requestClause.windows, ceilingClause.windows)) continue;
        validityMatch = true;
        break;
      }
      if (!permissionMatch) return { requestable: false, reason: "permission-not-requestable" };
      if (!scopeMatch) return { requestable: false, reason: "scope-not-requestable" };
      if (!validityMatch) return { requestable: false, reason: "validity-not-requestable" };
    }
    return { requestable: true, policyId, approval };
  }

  return Object.freeze({
    policyId,
    approval,
    evaluate,
    canRequest(args) {
      return evaluate(args).requestable;
    },
  });
}

/** Wire/service submission describing exact authority requested for one access subject. */
export type AccessRequestSubmit<Permission extends string, Dimension extends string, Attribute extends string = string> = {
  /** Caller-generated retry key unique for this requester. */
  idempotencyKey: string;
  /** Subject whose authority would change when the request is approved. */
  subjectId: string;
  /** Application-selected request policy that must currently apply. */
  policyId: string;
  /** Exact AccessOnce authority being requested. */
  grant: AccessGrant<Permission, Dimension, Attribute>;
};

/** User-facing terminal action supported by the request transition wire. */
export type AccessRequestTransitionAction = "approve" | "deny" | "cancel";

/** Optimistic transition request used by approval/cancellation endpoints. */
export type AccessRequestTransition = {
  /** Durable request being transitioned. */
  requestId: string;
  /** Revision loaded by the actor before taking this action. */
  expectedRevision: string;
  /** Requested lifecycle action. */
  action: AccessRequestTransitionAction;
};

/** Durable access-request lifecycle including one internal recoverable authority-issuance state. */
export type AccessRequestState = "pending" | "issuing" | "approved" | "denied" | "cancelled" | "expired";

/** Durable request fields supplied when an application request store creates or updates a record. */
export type AccessRequestCreate<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = AccessRequestSubmit<Permission, Dimension, Attribute> & {
  /** Authenticated actor that originally submitted the request; never trust this from the request wire itself. */
  requesterId: string;
  /** Approval behavior selected when the request was accepted. */
  approval: AccessRequestApproval;
  /** Current durable lifecycle state. */
  state: AccessRequestState;
  /** Optional application-owned queue/routing token for manual approval. */
  route?: Route;
};

/** Versioned durable access-request record returned by the application store. */
export type AccessRequestRecord<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = AccessRequestCreate<Permission, Dimension, Attribute, Route> & {
  /** Stable durable request identifier generated by the application store. */
  requestId: string;
  /** Compare-and-set revision for lifecycle transitions. */
  revision: string;
};

/** Result of atomically creating a request or observing the winner for the same requester/idempotency key. */
export type AccessRequestCreateResult<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** True only for the call that durably created the idempotency-key record. */
  created: boolean;
  /** Newly created or previously committed request. */
  request: AccessRequestRecord<Permission, Dimension, Attribute, Route>;
};

/** BYO durable request storage contract; databases and locking strategies stay outside AccessOnce. */
export type AccessRequestStore<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Serialize lifecycle work for one durable request during approval issuance and terminal transitions. */
  withRequestLock<Result>(requestId: string, work: () => Promise<Result>): Promise<Result>;
  /** Read one request by its stable durable id. */
  read(requestId: string): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route> | undefined>;
  /** Read an earlier submission without re-evaluating policy, so retries stay idempotent across policy changes. */
  readByIdempotency(
    requesterId: string,
    idempotencyKey: string,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route> | undefined>;
  /** Atomically create or return the unique record for `(requesterId, idempotencyKey)`. */
  createOrRead(
    request: AccessRequestCreate<Permission, Dimension, Attribute, Route>,
  ): Promise<AccessRequestCreateResult<Permission, Dimension, Attribute, Route>>;
  /** Replace one request only when its durable revision still matches the expected value. */
  compareAndSet(
    requestId: string,
    expectedRevision: string,
    next: AccessRequestCreate<Permission, Dimension, Attribute, Route>,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
};

/** Current application resolution for a request policy, including subject values needed by relative ceilings. */
export type AccessRequestPolicyResolution<Permission extends string, Dimension extends string, Attribute extends string = string> = {
  /** Application-selected policy that currently applies. */
  policy: AccessRequestPolicy<Permission, Dimension, Attribute>;
  /** Current subject attributes used by subject-relative request ceilings. */
  subject?: AccessRequestSubject<Attribute>;
};

/** Context passed to application approval-route resolution before a manual request is accepted. */
export type AccessRequestRouteContext<Permission extends string, Dimension extends string, Attribute extends string = string> = {
  /** Authenticated actor submitting the request. */
  requesterId: string;
  /** Access subject that would receive the grant. */
  subjectId: string;
  /** Exact authority requested. */
  grant: AccessGrant<Permission, Dimension, Attribute>;
  /** Current request policy selected by the application. */
  policy: AccessRequestPolicy<Permission, Dimension, Attribute>;
  /** Current subject values used while proving the request. */
  subject?: AccessRequestSubject<Attribute>;
};

/** Context passed to application authorization before a human/user lifecycle transition is committed. */
export type AccessRequestTransitionAuthorization<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Authenticated actor attempting the transition. */
  actorId: string;
  /** Requested user-facing transition. */
  action: AccessRequestTransitionAction;
  /** Current durable request. */
  request: AccessRequestRecord<Permission, Dimension, Attribute, Route>;
  /** Current policy resolution for approve actions; omitted for deny/cancel. */
  resolution?: AccessRequestPolicyResolution<Permission, Dimension, Attribute>;
};

/** Exact authority-issuance command emitted only after a durable approval claim exists. */
export type AccessRequestIssuance<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Stable retry key; issuers must make repeated calls with this key idempotent. */
  issuanceKey: string;
  /** Durable request whose approval is being committed. */
  request: AccessRequestRecord<Permission, Dimension, Attribute, Route>;
};

/** Durable access-request service exposed to application endpoints and recovery jobs. */
export type AccessRequestService<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Submit exact authority for the authenticated requester; automatic policies commit immediately. */
  submit(
    requesterId: string,
    request: AccessRequestSubmit<Permission, Dimension, Attribute>,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Read one durable request; endpoint authorization remains application-owned. */
  read(requestId: string): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Apply approve/deny/cancel with optimistic revision and idempotent same-terminal retries. */
  transition(
    actorId: string,
    transition: AccessRequestTransition,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Expire a still-pending request from an application scheduler or maintenance job. */
  expire(
    requestId: string,
    expectedRevision: string,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Resume a claimed issuance or a pending automatic request after a crash/interruption. */
  recover(requestId: string): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
};

/** Stable issuance id used to make cross-store authority publication retry-safe. */
export function accessRequestIssuanceKey(requestId: string): string {
  return `access-request:${requestId}`;
}

/** Canonicalize one direct request grant for idempotency-key replay comparison. */
function accessRequestGrantKey<Permission extends string, Dimension extends string, Attribute extends string>(
  grant: AccessGrant<Permission, Dimension, Attribute>,
): string {
  const scope: [string, string, readonly string[] | string][] = [];
  if (grant.scope) {
    const dimensions = Object.keys(grant.scope);
    dimensions.sort();
    for (const rawDimension of dimensions) {
      const source = grant.scope[rawDimension as Dimension];
      if (!source) continue;
      if (source.kind === "subject") {
        scope.push([rawDimension, "subject", source.attribute]);
      } else {
        const ids = [...new Set(source.ids)];
        ids.sort();
        scope.push([rawDimension, "ids", ids]);
      }
    }
  }
  const validity = normalizeRequestValidity(grant.validity);
  return JSON.stringify([grant.permission, scope, validity.windows]);
}

/** Require that an idempotency-key winner represents the same submitted authority, not a different reused request. */
function assertSameRequestSubmission<Permission extends string, Dimension extends string, Attribute extends string, Route>(
  existing: AccessRequestRecord<Permission, Dimension, Attribute, Route>,
  requesterId: string,
  request: AccessRequestSubmit<Permission, Dimension, Attribute>,
): void {
  if (
    existing.requesterId !== requesterId ||
    existing.subjectId !== request.subjectId ||
    existing.policyId !== request.policyId ||
    accessRequestGrantKey(existing.grant) !== accessRequestGrantKey(request.grant)
  ) {
    throw new Error("access request idempotency key was already used for different authority");
  }
}

/** Return a copy of one request with only its lifecycle state changed. */
function requestWithState<Permission extends string, Dimension extends string, Attribute extends string, Route>(
  request: AccessRequestRecord<Permission, Dimension, Attribute, Route>,
  state: AccessRequestState,
): AccessRequestCreate<Permission, Dimension, Attribute, Route> {
  return {
    requesterId: request.requesterId,
    idempotencyKey: request.idempotencyKey,
    subjectId: request.subjectId,
    policyId: request.policyId,
    grant: request.grant,
    approval: request.approval,
    state,
    ...(request.route === undefined ? {} : { route: request.route }),
  };
}

/** Build the generic durable approval service without choosing a database, organization model, or transport. */
export function createAccessRequestService<Permission extends string, Dimension extends string, Attribute extends string = string, Route = unknown>(options: {
  /** Durable request storage and per-request serialization supplied by the application. */
  store: AccessRequestStore<Permission, Dimension, Attribute, Route>;
  /** Resolve the currently applicable policy; returning undefined makes the request unavailable. */
  resolvePolicy(args: {
    /** Authenticated original requester. */
    requesterId: string;
    /** Access subject that would receive authority. */
    subjectId: string;
    /** Stable policy identifier saved with the request. */
    policyId: string;
  }): AccessRequestPolicyResolution<Permission, Dimension, Attribute> | undefined | Promise<AccessRequestPolicyResolution<Permission, Dimension, Attribute> | undefined>;
  /** Resolve a concrete application queue/route before accepting manual requests. */
  resolveApprovalRoute?: (
    args: AccessRequestRouteContext<Permission, Dimension, Attribute>,
  ) => Route | undefined | Promise<Route | undefined>;
  /** Re-check current actor authority for approve/deny/cancel before mutating request state. */
  authorizeTransition(
    args: AccessRequestTransitionAuthorization<Permission, Dimension, Attribute, Route>,
  ): boolean | Promise<boolean>;
  /** Durably issue the exact requested grant; repeated issuanceKey calls must be idempotent. */
  issue(
    args: AccessRequestIssuance<Permission, Dimension, Attribute, Route>,
  ): Promise<void>;
}): AccessRequestService<Permission, Dimension, Attribute, Route> {
  /** Load one request or fail without fabricating nonexistence/authorization semantics. */
  async function requireRequest(requestId: string) {
    const request = await options.store.read(requestId);
    if (!request) throw new Error("access request not found");
    return request;
  }

  /** Resolve the current app-selected policy and require that it still proves this exact request. */
  async function requireCurrentPolicy(
    request: Pick<AccessRequestCreate<Permission, Dimension, Attribute, Route>, "requesterId" | "subjectId" | "policyId" | "grant">,
  ): Promise<AccessRequestPolicyResolution<Permission, Dimension, Attribute>> {
    const resolution = await options.resolvePolicy({
      requesterId: request.requesterId,
      subjectId: request.subjectId,
      policyId: request.policyId,
    });
    if (!resolution || resolution.policy.policyId !== request.policyId) {
      throw new Error("access request policy is not currently applicable");
    }
    const evaluation = resolution.policy.evaluate({
      grant: request.grant,
      ...(resolution.subject === undefined ? {} : { subject: resolution.subject }),
    });
    if (!evaluation.requestable) {
      throw new Error(`access request is no longer requestable: ${evaluation.reason}`);
    }
    return resolution;
  }

  /** Finish one already-claimed approval; approved is written only after idempotent authority issuance succeeds. */
  async function finishIssuance(
    request: AccessRequestRecord<Permission, Dimension, Attribute, Route>,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>> {
    if (request.state !== "issuing") throw new Error("access request is not issuing");
    await options.issue({ issuanceKey: accessRequestIssuanceKey(request.requestId), request });
    return options.store.compareAndSet(
      request.requestId,
      request.revision,
      requestWithState(request, "approved"),
    );
  }

  /** Resume a claimed issuance or safely claim a pending automatic request under the request lock. */
  async function recoverLocked(requestId: string) {
    let current = await requireRequest(requestId);
    if (current.state === "issuing") return finishIssuance(current);
    if (current.state !== "pending" || current.approval.kind !== "automatic") return current;

    const resolution = await requireCurrentPolicy(current);
    if (resolution.policy.approval.kind !== "automatic") {
      throw new Error("access request approval policy changed before automatic issuance");
    }
    current = await options.store.compareAndSet(
      current.requestId,
      current.revision,
      requestWithState(current, "issuing"),
    );
    return finishIssuance(current);
  }

  return {
    async submit(requesterId, request) {
      if (!requesterId.trim()) throw new Error("requesterId must not be empty");
      if (!request.idempotencyKey.trim()) throw new Error("idempotencyKey must not be empty");
      if (!request.subjectId.trim()) throw new Error("subjectId must not be empty");
      if (!request.policyId.trim()) throw new Error("policyId must not be empty");

      const existing = await options.store.readByIdempotency(requesterId, request.idempotencyKey);
      if (existing) {
        assertSameRequestSubmission(existing, requesterId, request);
        if (
          existing.state === "issuing" ||
          (existing.state === "pending" && existing.approval.kind === "automatic")
        ) {
          return options.store.withRequestLock(existing.requestId, () => recoverLocked(existing.requestId));
        }
        return existing;
      }

      const resolution = await options.resolvePolicy({
        requesterId,
        subjectId: request.subjectId,
        policyId: request.policyId,
      });
      if (!resolution || resolution.policy.policyId !== request.policyId) {
        throw new Error("access request policy is unavailable");
      }
      const evaluation = resolution.policy.evaluate({
        grant: request.grant,
        ...(resolution.subject === undefined ? {} : { subject: resolution.subject }),
      });
      if (!evaluation.requestable) {
        throw new Error(`access request is not requestable: ${evaluation.reason}`);
      }

      let route: Route | undefined;
      if (evaluation.approval.kind === "policy") {
        if (!options.resolveApprovalRoute) throw new Error("access request approval route is unavailable");
        route = await options.resolveApprovalRoute({
          requesterId,
          subjectId: request.subjectId,
          grant: request.grant,
          policy: resolution.policy,
          ...(resolution.subject === undefined ? {} : { subject: resolution.subject }),
        });
        if (route === undefined) throw new Error("access request approval route is unavailable");
      }

      const created = await options.store.createOrRead({
        requesterId,
        idempotencyKey: request.idempotencyKey,
        subjectId: request.subjectId,
        policyId: request.policyId,
        grant: request.grant,
        approval: evaluation.approval,
        // Creation records the request only; automatic approval is claimed after a fresh policy check under lock.
        state: "pending",
        ...(route === undefined ? {} : { route }),
      });
      assertSameRequestSubmission(created.request, requesterId, request);
      if (
        created.request.state === "issuing" ||
        (created.request.state === "pending" && created.request.approval.kind === "automatic")
      ) {
        return options.store.withRequestLock(
          created.request.requestId,
          () => recoverLocked(created.request.requestId),
        );
      }
      return created.request;
    },

    read(requestId) {
      return requireRequest(requestId);
    },

    async transition(actorId, transition) {
      if (!actorId.trim()) throw new Error("actorId must not be empty");
      return options.store.withRequestLock(transition.requestId, async () => {
        let current = await requireRequest(transition.requestId);
        const sameTerminal =
          (transition.action === "approve" && current.state === "approved") ||
          (transition.action === "deny" && current.state === "denied") ||
          (transition.action === "cancel" && current.state === "cancelled");
        if (sameTerminal) return current;
        if (current.state === "issuing") {
          if (transition.action !== "approve") {
            throw new Error("access request approval is already being issued and cannot be rewritten");
          }
          return finishIssuance(current);
        }
        if (current.state !== "pending") throw new Error("access request already has a conflicting terminal state");
        if (current.revision !== transition.expectedRevision) {
          throw new Error("access request changed since this action loaded");
        }

        let resolution: AccessRequestPolicyResolution<Permission, Dimension, Attribute> | undefined;
        if (transition.action === "approve") resolution = await requireCurrentPolicy(current);
        const authorized = await options.authorizeTransition({
          actorId,
          action: transition.action,
          request: current,
          ...(resolution === undefined ? {} : { resolution }),
        });
        if (!authorized) throw new Error("actor is not authorized for this access request transition");

        if (transition.action !== "approve") {
          return options.store.compareAndSet(
            current.requestId,
            current.revision,
            requestWithState(current, transition.action === "deny" ? "denied" : "cancelled"),
          );
        }

        current = await options.store.compareAndSet(
          current.requestId,
          current.revision,
          requestWithState(current, "issuing"),
        );
        return finishIssuance(current);
      });
    },

    async expire(requestId, expectedRevision) {
      return options.store.withRequestLock(requestId, async () => {
        const current = await requireRequest(requestId);
        if (current.state === "expired") return current;
        if (current.state !== "pending") throw new Error("only a pending access request can expire");
        if (current.revision !== expectedRevision) {
          throw new Error("access request changed since expiry loaded");
        }
        return options.store.compareAndSet(
          requestId,
          current.revision,
          requestWithState(current, "expired"),
        );
      });
    },

    recover(requestId) {
      return options.store.withRequestLock(requestId, () => recoverLocked(requestId));
    },
  };
}
