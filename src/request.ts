import type { AccessCatalog } from "./catalog.js";
import { compileAccessSnapshot } from "./compiler.js";
import type { AccessRelationshipResource } from "./relationship.js";
import type {
  AccessGrant,
  AccessScopeSource,
  AccessValidity,
  CompiledAccessConstraint,
  CompiledAccessGrant,
} from "./types.js";

/** Application-owned approval routing decision attached to one request rule. */
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

/** Optional rule-wide bounds on temporal authority a requester may ask for. */
export type AccessRequestValidityLimits = {
  /** Whether timeless or one-sided validity may be requested; defaults to true unless duration is bounded. */
  allowUnbounded?: boolean;
  /** Maximum number of validity windows submitted on one request before merging overlaps. */
  maximumWindows?: number;
  /** Maximum total duration after overlapping bounded windows are merged. */
  maximumDurationMs?: number;
};

/** Grant authority that can be requested from the actor snapshot plane. */
export type AccessGrantRequestAuthority<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Discriminator for compiled actor authority. */
  kind: "grant";
  /** Exact grant requested for the access subject. */
  grant: AccessGrant<Permission, Dimension, Attribute>;
};

/** Exact object relationship that can be requested from the high-cardinality ACL plane. */
export type AccessRelationshipRequestAuthority = {
  /** Discriminator for object/resource relationship authority. */
  kind: "relationship";
  /** Exact object whose relationship is requested. */
  resource: AccessRelationshipResource;
  /** Application-defined relation such as reader or editor. */
  relation: string;
  /** Optional temporal validity for this exact relationship. */
  validity?: AccessValidity | readonly AccessValidity[];
};

/** Authority requested through the control plane without changing the hot evaluator. */
export type AccessRequestAuthority<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> =
  | AccessGrantRequestAuthority<Permission, Dimension, Attribute>
  | AccessRelationshipRequestAuthority;

/** Grant-plane authority allowed by one request rule. */
export type AccessGrantRequestAllowance<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Discriminator for actor-grant request rules. */
  kind: "grant";
  /** Grants whose compiled authority forms the maximum requestable union. */
  grants: readonly AccessGrant<Permission, Dimension, Attribute>[];
};

/** Object relationship vocabulary allowed by one request rule. Exact object applicability remains application-owned. */
export type AccessRelationshipRequestAllowance = {
  /** Discriminator for object relationship request rules. */
  kind: "relationship";
  /** Resource namespaces this rule may target, for example document or encounter. */
  resourceTypes: readonly string[];
  /** Relationships this rule may request, for example reader or editor. */
  relations: readonly string[];
};

/** Maximum authority vocabulary for one application-selected request rule. */
export type AccessRequestAllowance<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> =
  | AccessGrantRequestAllowance<Permission, Dimension, Attribute>
  | AccessRelationshipRequestAllowance;

/** Declarative rule selected by an application for one request workflow. */
export type AccessRequestRuleDefinition<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Stable application-owned request rule identifier. */
  ruleId: string;
  /** Maximum grant or relationship vocabulary this workflow can request. */
  allow: AccessRequestAllowance<Permission, Dimension, Attribute>;
  /** Automatic or application-routed approval behavior. */
  approval: AccessRequestApproval;
  /** Optional temporal limits applied to either authority kind. */
  validity?: AccessRequestValidityLimits;
};

/** Coarse fail-closed reason returned when requested authority is outside its selected rule. */
export type AccessRequestDenialReason =
  | "invalid-request"
  | "empty-request"
  | "authority-not-requestable"
  | "permission-not-requestable"
  | "scope-not-requestable"
  | "validity-not-requestable";

/** Result of checking one exact requested authority against an application-selected request rule. */
export type AccessRequestEvaluation =
  | {
      /** True when the exact authority is within the rule. */
      requestable: true;
      /** Stable rule that proved the request. */
      ruleId: string;
      /** Approval behavior to use when the request is submitted. */
      approval: AccessRequestApproval;
    }
  | {
      /** False when the request fails closed. */
      requestable: false;
      /** Intentionally coarse denial category that avoids leaking unnecessary policy detail. */
      reason: AccessRequestDenialReason;
    };

/** Trusted subject attributes used only to resolve subject-relative grant comparisons. */
export type AccessRequestSubject<Attribute extends string> = Readonly<
  Partial<Record<Attribute, string>>
>;

/** Cold request rule evaluator; applications decide whether this rule is applicable or advertised. */
export type AccessRequestRule<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Stable application-owned rule identifier. */
  readonly ruleId: string;
  /** Approval behavior carried by this rule. */
  readonly approval: AccessRequestApproval;
  /** Evaluate one exact authority against the rule. */
  evaluate(args: {
    /** Exact actor grant or object relationship being requested. */
    authority: AccessRequestAuthority<Permission, Dimension, Attribute>;
    /** Current subject values needed only for subject-relative grant proof. */
    subject?: AccessRequestSubject<Attribute>;
  }): AccessRequestEvaluation;
  /** Boolean convenience for callers that do not need the coarse denial reason. */
  canRequest(args: {
    /** Exact actor grant or object relationship being requested. */
    authority: AccessRequestAuthority<Permission, Dimension, Attribute>;
    /** Current subject values needed only for subject-relative grant proof. */
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

/** Require a non-empty unique vocabulary list for relationship request rules. */
function requestVocabulary(values: readonly string[], label: string): ReadonlySet<string> {
  if (values.length === 0) throw new Error(`${label} must not be empty`);
  const result = new Set<string>();
  for (const value of values) {
    if (!value.trim()) throw new Error(`${label} must contain non-empty strings`);
    result.add(value);
  }
  return result;
}

/** Return the validity carried by either supported request authority kind. */
function requestAuthorityValidity<Permission extends string, Dimension extends string, Attribute extends string>(
  authority: AccessRequestAuthority<Permission, Dimension, Attribute>,
): AccessValidity | readonly AccessValidity[] | undefined {
  return authority.kind === "grant" ? authority.grant.validity : authority.validity;
}

/** Validate one relationship request without interpreting application resource/relation semantics. */
function validateRelationshipRequest(authority: AccessRelationshipRequestAuthority): void {
  if (!authority.resource.type.trim()) throw new Error("relationship resource type must not be empty");
  if (!authority.resource.id.trim()) throw new Error("relationship resource id must not be empty");
  if (!authority.relation.trim()) throw new Error("relationship relation must not be empty");
  normalizeRequestValidity(authority.validity);
}

/** Prove that one approved grant is no broader than the originally requested grant. */
function grantRequestWithinRequest<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  approved: AccessGrant<Permission, Dimension, Attribute>,
  requested: AccessGrant<Permission, Dimension, Attribute>,
  subject: AccessRequestSubject<Attribute> | undefined,
): boolean {
  try {
    validateRequestGrant(catalog, approved, "approved access request");
    validateRequestGrant(catalog, requested, "original access request");
    const approvedClauses = compileRequestGrantClauses(catalog, approved);
    const requestedClauses = compileRequestGrantClauses(catalog, requested);
    if (approvedClauses.length === 0) return false;
    for (const approvedClause of approvedClauses) {
      let covered = false;
      for (const requestedClause of requestedClauses) {
        if (approvedClause.grant.permission !== requestedClause.grant.permission) continue;
        if (!requestScopeCovered(approvedClause.grant.constraints, requestedClause.grant.constraints, subject)) continue;
        if (!requestValidityCovered(approvedClause.windows, requestedClause.windows)) continue;
        covered = true;
        break;
      }
      if (!covered) return false;
    }
    return true;
  } catch {
    return false;
  }
}

/** Prove that approved authority is equal to or narrower than what the requester actually asked for. */
function requestAuthorityWithinRequest<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  approved: AccessRequestAuthority<Permission, Dimension, Attribute>,
  requested: AccessRequestAuthority<Permission, Dimension, Attribute>,
  subject: AccessRequestSubject<Attribute> | undefined,
): boolean {
  if (approved.kind !== requested.kind) return false;
  if (approved.kind === "grant" && requested.kind === "grant") {
    return grantRequestWithinRequest(catalog, approved.grant, requested.grant, subject);
  }
  if (approved.kind !== "relationship" || requested.kind !== "relationship") return false;
  try {
    validateRelationshipRequest(approved);
    validateRelationshipRequest(requested);
  } catch {
    return false;
  }
  if (
    approved.resource.type !== requested.resource.type ||
    approved.resource.id !== requested.resource.id ||
    approved.relation !== requested.relation
  ) return false;
  const approvedValidity = normalizeRequestValidity(approved.validity);
  const requestedValidity = normalizeRequestValidity(requested.validity);
  return approvedValidity.windows.length > 0 && requestValidityCovered(approvedValidity.windows, requestedValidity.windows);
}

/** Create a cold request rule that proves actor grants or exact object relationships without touching the hot evaluator. */
export function defineAccessRequestRule<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string = string>(
  catalog: AccessCatalog<Permission, Leaf, Dimension>,
  definition: AccessRequestRuleDefinition<Permission, Dimension, Attribute>,
): AccessRequestRule<Permission, Dimension, Attribute> {
  if (!definition.ruleId.trim()) throw new Error("request ruleId must not be empty");
  if (definition.approval.kind === "policy" && !definition.approval.policyId.trim()) {
    throw new Error("request approval policyId must not be empty");
  }
  requirePositiveSafeInteger(definition.validity?.maximumWindows, "maximumWindows");
  requirePositiveSafeInteger(definition.validity?.maximumDurationMs, "maximumDurationMs");

  const grantCeilings: RequestAuthorityClause<Leaf, Dimension, Attribute>[] = [];
  let resourceTypes: ReadonlySet<string> | undefined;
  let relations: ReadonlySet<string> | undefined;
  if (definition.allow.kind === "grant") {
    if (definition.allow.grants.length === 0) throw new Error("request rule grants must not be empty");
    for (const ceiling of definition.allow.grants) {
      validateRequestGrant(catalog, ceiling, "request rule grant ceiling");
      for (const clause of compileRequestGrantClauses(catalog, ceiling)) grantCeilings.push(clause);
    }
    if (grantCeilings.length === 0) throw new Error("request rule grants provide no authority");
  } else {
    resourceTypes = requestVocabulary(definition.allow.resourceTypes, "request rule resourceTypes");
    relations = requestVocabulary(definition.allow.relations, "request rule relations");
  }
  const ruleId = definition.ruleId;
  const approval = Object.freeze({ ...definition.approval }) as AccessRequestApproval;
  const limits = definition.validity === undefined ? undefined : Object.freeze({ ...definition.validity });

  /** Evaluate one authority using the immutable compiled rule. */
  function evaluate(args: {
    /** Exact actor grant or object relationship being requested. */
    authority: AccessRequestAuthority<Permission, Dimension, Attribute>;
    /** Current subject values needed for subject-relative grant proof. */
    subject?: AccessRequestSubject<Attribute>;
  }): AccessRequestEvaluation {
    let validity: RequestValiditySummary;
    try {
      validity = normalizeRequestValidity(requestAuthorityValidity(args.authority));
    } catch {
      return { requestable: false, reason: "invalid-request" };
    }
    if (validity.windows.length === 0) return { requestable: false, reason: "empty-request" };
    if (!requestWithinValidityLimits(validity, limits)) {
      return { requestable: false, reason: "validity-not-requestable" };
    }

    if (definition.allow.kind === "relationship") {
      if (args.authority.kind !== "relationship") return { requestable: false, reason: "authority-not-requestable" };
      try {
        validateRelationshipRequest(args.authority);
      } catch {
        return { requestable: false, reason: "invalid-request" };
      }
      if (!resourceTypes!.has(args.authority.resource.type) || !relations!.has(args.authority.relation)) {
        return { requestable: false, reason: "authority-not-requestable" };
      }
      return { requestable: true, ruleId, approval };
    }

    if (args.authority.kind !== "grant") return { requestable: false, reason: "authority-not-requestable" };
    let requested: readonly RequestAuthorityClause<Leaf, Dimension, Attribute>[];
    try {
      validateRequestGrant(catalog, args.authority.grant, "access request");
      requested = compileRequestGrantClauses(catalog, args.authority.grant);
    } catch {
      return { requestable: false, reason: "invalid-request" };
    }
    if (requested.length === 0) return { requestable: false, reason: "empty-request" };

    for (const requestClause of requested) {
      let permissionMatch = false;
      let scopeMatch = false;
      let validityMatch = false;
      for (const ceilingClause of grantCeilings) {
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
    return { requestable: true, ruleId, approval };
  }

  return Object.freeze({
    ruleId,
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
  /** Subject/principal whose authority would change when approved. */
  subjectId: string;
  /** Application-selected request rule that must currently apply. */
  ruleId: string;
  /** Exact actor grant or object relationship requested. */
  authority: AccessRequestAuthority<Permission, Dimension, Attribute>;
};

/** User-facing terminal action supported by the request transition wire. */
export type AccessRequestTransitionAction = "approve" | "deny" | "cancel";

/** Durable audit decision attached when a request leaves pending state. */
export type AccessRequestDecision<Permission extends string, Dimension extends string, Attribute extends string = string> = {
  /** Terminal or issuance-starting decision. */
  action: AccessRequestTransitionAction | "expire";
  /** Authenticated actor responsible for a user decision; omitted for automatic/system actions. */
  actorId?: string;
  /** Optional application-facing explanation retained for audit/UI. */
  reason?: string;
  /** Exact authority selected for approval; omitted for non-approve decisions. */
  authority?: AccessRequestAuthority<Permission, Dimension, Attribute>;
};

/** Optimistic transition request used by approval/cancellation endpoints. */
export type AccessRequestTransition<Permission extends string, Dimension extends string, Attribute extends string = string> = {
  /** Durable request being transitioned. */
  requestId: string;
  /** Revision loaded by the actor before taking this action. */
  expectedRevision: string;
  /** Requested lifecycle action. */
  action: AccessRequestTransitionAction;
  /** Optional narrower approved authority; omitted means approve exactly what was requested. */
  authority?: AccessRequestAuthority<Permission, Dimension, Attribute>;
  /** Optional durable decision explanation. */
  reason?: string;
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
  /** Durable approval/denial/cancellation/expiry audit decision once present. */
  decision?: AccessRequestDecision<Permission, Dimension, Attribute>;
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
  /** Read an earlier submission without re-evaluating rules, so retries stay idempotent across rule changes. */
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

/** Current application resolution for a request rule, including subject values needed by relative grant ceilings. */
export type AccessRequestRuleResolution<Permission extends string, Dimension extends string, Attribute extends string = string> = {
  /** Application-selected rule that currently applies. */
  rule: AccessRequestRule<Permission, Dimension, Attribute>;
  /** Current subject attributes used by subject-relative grant ceilings. */
  subject?: AccessRequestSubject<Attribute>;
};

/** Context passed to application approval-route resolution before a manual request is accepted. */
export type AccessRequestRouteContext<Permission extends string, Dimension extends string, Attribute extends string = string> = {
  /** Authenticated actor submitting the request. */
  requesterId: string;
  /** Access subject/principal that would receive authority. */
  subjectId: string;
  /** Exact requested authority. */
  authority: AccessRequestAuthority<Permission, Dimension, Attribute>;
  /** Current request rule selected by the application. */
  rule: AccessRequestRule<Permission, Dimension, Attribute>;
  /** Current subject values used while proving grant authority. */
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
  /** Authority selected for approval after narrowing; omitted for deny/cancel. */
  authority?: AccessRequestAuthority<Permission, Dimension, Attribute>;
  /** Current rule resolution for approve actions; omitted for deny/cancel. */
  resolution?: AccessRequestRuleResolution<Permission, Dimension, Attribute>;
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
  /** Exact approved actor grant or object relationship to publish through the application's ordinary authority path. */
  authority: AccessRequestAuthority<Permission, Dimension, Attribute>;
};

/** Durable access-request service exposed to application endpoints and recovery jobs. */
export type AccessRequestService<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Submit exact authority for the authenticated requester; automatic rules commit immediately. */
  submit(
    requesterId: string,
    request: AccessRequestSubmit<Permission, Dimension, Attribute>,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Read one durable request; endpoint authorization remains application-owned. */
  read(requestId: string): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Apply approve/deny/cancel with optimistic revision and idempotent same-terminal retries. */
  transition(
    actorId: string,
    transition: AccessRequestTransition<Permission, Dimension, Attribute>,
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

/** Canonicalize one request authority for idempotency-key replay comparison. */
function accessRequestAuthorityKey<Permission extends string, Dimension extends string, Attribute extends string>(
  authority: AccessRequestAuthority<Permission, Dimension, Attribute>,
): string {
  if (authority.kind === "relationship") {
    const validity = normalizeRequestValidity(authority.validity);
    return JSON.stringify(["relationship", authority.resource.type, authority.resource.id, authority.relation, validity.windows]);
  }
  const grant = authority.grant;
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
  return JSON.stringify(["grant", grant.permission, scope, validity.windows]);
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
    existing.ruleId !== request.ruleId ||
    accessRequestAuthorityKey(existing.authority) !== accessRequestAuthorityKey(request.authority)
  ) {
    throw new Error("access request idempotency key was already used for different authority");
  }
}

/** Return a copy of one request with lifecycle/decision changes while preserving the original requested authority. */
function requestWithState<Permission extends string, Dimension extends string, Attribute extends string, Route>(
  request: AccessRequestRecord<Permission, Dimension, Attribute, Route>,
  state: AccessRequestState,
  decision: AccessRequestDecision<Permission, Dimension, Attribute> | undefined = request.decision,
): AccessRequestCreate<Permission, Dimension, Attribute, Route> {
  return {
    requesterId: request.requesterId,
    idempotencyKey: request.idempotencyKey,
    subjectId: request.subjectId,
    ruleId: request.ruleId,
    authority: request.authority,
    approval: request.approval,
    state,
    ...(request.route === undefined ? {} : { route: request.route }),
    ...(decision === undefined ? {} : { decision }),
  };
}

/** Build the generic durable approval service without choosing a database, organization model, or transport. */
export function createAccessRequestService<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string = string, Route = unknown>(options: {
  /** Catalog used only for cold approval-narrowing proofs between actor grants. */
  catalog: AccessCatalog<Permission, Leaf, Dimension>;
  /** Durable request storage and per-request serialization supplied by the application. */
  store: AccessRequestStore<Permission, Dimension, Attribute, Route>;
  /** Resolve the currently applicable rule; returning undefined makes the request unavailable. */
  resolveRule(args: {
    /** Authenticated original requester. */
    requesterId: string;
    /** Access subject/principal that would receive authority. */
    subjectId: string;
    /** Stable rule identifier saved with the request. */
    ruleId: string;
    /** Original exact authority requested, allowing the host to apply object/context-specific applicability. */
    authority: AccessRequestAuthority<Permission, Dimension, Attribute>;
  }): AccessRequestRuleResolution<Permission, Dimension, Attribute> | undefined | Promise<AccessRequestRuleResolution<Permission, Dimension, Attribute> | undefined>;
  /** Resolve a concrete application queue/route before accepting manual requests. */
  resolveApprovalRoute?: (
    args: AccessRequestRouteContext<Permission, Dimension, Attribute>,
  ) => Route | undefined | Promise<Route | undefined>;
  /** Re-check current actor authority for approve/deny/cancel before mutating request state. */
  authorizeTransition(
    args: AccessRequestTransitionAuthorization<Permission, Dimension, Attribute, Route>,
  ): boolean | Promise<boolean>;
  /** Durably issue exact approved authority; relationship issuers should use their canonical relationship mutation/projection path. */
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

  /** Resolve the current app-selected rule and require that it still proves the selected approval authority. */
  async function requireCurrentRule(
    request: Pick<AccessRequestCreate<Permission, Dimension, Attribute, Route>, "requesterId" | "subjectId" | "ruleId" | "authority">,
    authority: AccessRequestAuthority<Permission, Dimension, Attribute>,
  ): Promise<AccessRequestRuleResolution<Permission, Dimension, Attribute>> {
    const resolution = await options.resolveRule({
      requesterId: request.requesterId,
      subjectId: request.subjectId,
      ruleId: request.ruleId,
      authority: request.authority,
    });
    if (!resolution || resolution.rule.ruleId !== request.ruleId) {
      throw new Error("access request rule is not currently applicable");
    }
    const evaluation = resolution.rule.evaluate({
      authority,
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
    const authority = request.decision?.action === "approve" && request.decision.authority
      ? request.decision.authority
      : request.authority;
    await options.issue({ issuanceKey: accessRequestIssuanceKey(request.requestId), request, authority });
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

    const resolution = await requireCurrentRule(current, current.authority);
    if (resolution.rule.approval.kind !== "automatic") {
      throw new Error("access request approval rule changed before automatic issuance");
    }
    current = await options.store.compareAndSet(
      current.requestId,
      current.revision,
      requestWithState(current, "issuing", { action: "approve", authority: current.authority }),
    );
    return finishIssuance(current);
  }

  return {
    async submit(requesterId, request) {
      if (!requesterId.trim()) throw new Error("requesterId must not be empty");
      if (!request.idempotencyKey.trim()) throw new Error("idempotencyKey must not be empty");
      if (!request.subjectId.trim()) throw new Error("subjectId must not be empty");
      if (!request.ruleId.trim()) throw new Error("ruleId must not be empty");

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

      const resolution = await options.resolveRule({
        requesterId,
        subjectId: request.subjectId,
        ruleId: request.ruleId,
        authority: request.authority,
      });
      if (!resolution || resolution.rule.ruleId !== request.ruleId) {
        throw new Error("access request rule is unavailable");
      }
      const evaluation = resolution.rule.evaluate({
        authority: request.authority,
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
          authority: request.authority,
          rule: resolution.rule,
          ...(resolution.subject === undefined ? {} : { subject: resolution.subject }),
        });
        if (route === undefined) throw new Error("access request approval route is unavailable");
      }

      const created = await options.store.createOrRead({
        requesterId,
        idempotencyKey: request.idempotencyKey,
        subjectId: request.subjectId,
        ruleId: request.ruleId,
        authority: request.authority,
        approval: evaluation.approval,
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
      if (transition.reason !== undefined && !transition.reason.trim()) {
        throw new Error("access request transition reason must not be empty when supplied");
      }
      if (transition.action !== "approve" && transition.authority !== undefined) {
        throw new Error("only approve may select narrower authority");
      }
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

        let resolution: AccessRequestRuleResolution<Permission, Dimension, Attribute> | undefined;
        let approvedAuthority: AccessRequestAuthority<Permission, Dimension, Attribute> | undefined;
        if (transition.action === "approve") {
          approvedAuthority = transition.authority ?? current.authority;
          resolution = await requireCurrentRule(current, approvedAuthority);
          if (!requestAuthorityWithinRequest(options.catalog, approvedAuthority, current.authority, resolution.subject)) {
            throw new Error("approved access request authority must not be broader than the original request");
          }
        }
        const authorized = await options.authorizeTransition({
          actorId,
          action: transition.action,
          request: current,
          ...(approvedAuthority === undefined ? {} : { authority: approvedAuthority }),
          ...(resolution === undefined ? {} : { resolution }),
        });
        if (!authorized) throw new Error("actor is not authorized for this access request transition");

        if (transition.action !== "approve") {
          return options.store.compareAndSet(
            current.requestId,
            current.revision,
            requestWithState(current, transition.action === "deny" ? "denied" : "cancelled", {
              action: transition.action,
              actorId,
              ...(transition.reason === undefined ? {} : { reason: transition.reason }),
            }),
          );
        }

        current = await options.store.compareAndSet(
          current.requestId,
          current.revision,
          requestWithState(current, "issuing", {
            action: "approve",
            actorId,
            authority: approvedAuthority!,
            ...(transition.reason === undefined ? {} : { reason: transition.reason }),
          }),
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
          requestWithState(current, "expired", { action: "expire" }),
        );
      });
    },

    recover(requestId) {
      return options.store.withRequestLock(requestId, () => recoverLocked(requestId));
    },
  };
}
