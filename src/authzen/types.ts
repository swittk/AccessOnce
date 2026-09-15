/** JSON object carried by AuthZEN properties, context, metadata extensions, and decision context. */
export type AuthZenObject = Readonly<Record<string, unknown>>;

/** Subject/principal in an AuthZEN access evaluation. */
export type AuthZenSubject = {
  /** Subject namespace such as `user` or `service`. */
  type: string;
  /** Identifier unique within the subject type. */
  id: string;
  /** Optional subject attributes understood by the PDP. */
  properties?: AuthZenObject;
};

/** Subject selector used by subject search, where the identifier is intentionally omitted. */
export type AuthZenSubjectSelector = {
  /** Subject namespace to search. */
  type: string;
  /** Optional identifier is ignored by conforming subject-search PDPs. */
  id?: string;
  /** Optional subject attributes understood by the PDP. */
  properties?: AuthZenObject;
};

/** Resource/target in an AuthZEN access evaluation. */
export type AuthZenResource = {
  /** Resource namespace such as `document` or `account`. */
  type: string;
  /** Identifier unique within the resource type. */
  id: string;
  /** Optional resource attributes understood by the PDP. */
  properties?: AuthZenObject;
};

/** Resource selector used by resource search, where the identifier is intentionally omitted. */
export type AuthZenResourceSelector = {
  /** Resource namespace to search. */
  type: string;
  /** Optional identifier is ignored by conforming resource-search PDPs. */
  id?: string;
  /** Optional resource attributes understood by the PDP. */
  properties?: AuthZenObject;
};

/** Action/verb in an AuthZEN request. */
export type AuthZenAction = {
  /** Application-defined action name. */
  name: string;
  /** Optional action parameters or attributes understood by the PDP. */
  properties?: AuthZenObject;
};

/** Environmental attributes carried with one AuthZEN request. */
export type AuthZenContext = AuthZenObject;

/** AuthZEN allow/deny result returned to a Policy Enforcement Point. */
export type AuthZenDecision = {
  /** True permits the operation; false denies it. */
  decision: boolean;
  /** Optional enforcement information, reasons, obligations, or implementation-specific metadata. */
  context?: AuthZenContext;
};

/** One complete AuthZEN access-evaluation request. */
export type AuthZenEvaluationRequest = {
  /** Principal whose authority is being evaluated. */
  subject: AuthZenSubject;
  /** Requested operation. */
  action: AuthZenAction;
  /** Target resource. */
  resource: AuthZenResource;
  /** Optional environmental request attributes. */
  context?: AuthZenContext;
};

/** One boxcar evaluation whose fields may inherit top-level defaults. */
export type AuthZenPartialEvaluation = {
  /** Optional per-evaluation subject overriding the top-level default. */
  subject?: AuthZenSubject;
  /** Optional per-evaluation action overriding the top-level default. */
  action?: AuthZenAction;
  /** Optional per-evaluation resource overriding the top-level default. */
  resource?: AuthZenResource;
  /** Optional per-evaluation context overriding the top-level default. */
  context?: AuthZenContext;
};

/** Standard short-circuit semantics supported by AuthZEN boxcar evaluation. */
export type AuthZenEvaluationsSemantic =
  | "execute_all"
  | "deny_on_first_deny"
  | "permit_on_first_permit";

/** Options carried by the AuthZEN Access Evaluations request. */
export type AuthZenEvaluationsOptions = AuthZenObject & {
  /** Evaluation execution/short-circuit behavior; execute_all is the default. */
  evaluations_semantic?: AuthZenEvaluationsSemantic;
};

/** AuthZEN boxcar request with optional defaults shared by each evaluation. */
export type AuthZenEvaluationsRequest = {
  /** Optional default subject inherited by evaluations that omit subject. */
  subject?: AuthZenSubject;
  /** Optional default action inherited by evaluations that omit action. */
  action?: AuthZenAction;
  /** Optional default resource inherited by evaluations that omit resource. */
  resource?: AuthZenResource;
  /** Optional default context inherited by evaluations that omit context. */
  context?: AuthZenContext;
  /** Discrete evaluations; absent or empty means single-evaluation compatibility behavior. */
  evaluations?: readonly AuthZenPartialEvaluation[];
  /** Optional boxcar execution controls. */
  options?: AuthZenEvaluationsOptions;
};

/** AuthZEN boxcar response preserving evaluation order. */
export type AuthZenEvaluationsResponse = {
  /** Decisions returned in the same order as the evaluations actually executed. */
  evaluations: readonly AuthZenDecision[];
};

/** Pagination request shared by AuthZEN search endpoints. */
export type AuthZenSearchPageRequest = {
  /** Opaque continuation token from the preceding response. */
  token?: string;
  /** Maximum number of results requested. */
  limit?: number;
  /** Optional implementation-specific pagination attributes. */
  properties?: AuthZenObject;
};

/** Pagination response shared by AuthZEN search endpoints. */
export type AuthZenSearchPageResponse = {
  /** Opaque token for the next page; empty string means the result set is complete. */
  next_token: string;
  /** Optional number of results included in this response. */
  count?: number;
  /** Optional total matching results at request time. */
  total?: number;
  /** Optional implementation-specific pagination attributes. */
  properties?: AuthZenObject;
};

/** Search request for subjects permitted to perform an action on a resource. */
export type AuthZenSubjectSearchRequest = {
  /** Subject type being searched; its id is intentionally not meaningful. */
  subject: AuthZenSubjectSelector;
  /** Action each returned subject must be permitted to perform. */
  action: AuthZenAction;
  /** Resource on which returned subjects must be permitted. */
  resource: AuthZenResource;
  /** Optional environmental request attributes. */
  context?: AuthZenContext;
  /** Optional opaque-token pagination request. */
  page?: AuthZenSearchPageRequest;
};

/** Search request for resources on which a subject may perform an action. */
export type AuthZenResourceSearchRequest = {
  /** Subject whose accessible resources are being searched. */
  subject: AuthZenSubject;
  /** Action the subject must be permitted to perform. */
  action: AuthZenAction;
  /** Resource type being searched; its id is intentionally not meaningful. */
  resource: AuthZenResourceSelector;
  /** Optional environmental request attributes. */
  context?: AuthZenContext;
  /** Optional opaque-token pagination request. */
  page?: AuthZenSearchPageRequest;
};

/** Search request for actions a subject may perform on a resource. */
export type AuthZenActionSearchRequest = {
  /** Subject whose permitted actions are being searched. */
  subject: AuthZenSubject;
  /** Resource on which actions are being searched. */
  resource: AuthZenResource;
  /** Optional environmental request attributes. */
  context?: AuthZenContext;
  /** Optional opaque-token pagination request. */
  page?: AuthZenSearchPageRequest;
};

/** Search response containing only the entity category requested by the endpoint. */
export type AuthZenSearchResponse<Entity> = {
  /** Optional pagination state. */
  page?: AuthZenSearchPageResponse;
  /** Optional response context or implementation diagnostics. */
  context?: AuthZenContext;
  /** Authorized entities matching the search request. */
  results: readonly Entity[];
};

/** AuthZEN Policy Decision Point metadata document. */
export type AuthZenPdpMetadata = {
  /** Canonical HTTPS identifier of the PDP. */
  policy_decision_point: string;
  /** Required endpoint for single access evaluation. */
  access_evaluation_endpoint: string;
  /** Optional endpoint for boxcar access evaluations. */
  access_evaluations_endpoint?: string;
  /** Optional subject-search endpoint. */
  search_subject_endpoint?: string;
  /** Optional resource-search endpoint. */
  search_resource_endpoint?: string;
  /** Optional action-search endpoint. */
  search_action_endpoint?: string;
  /** Optional registered AuthZEN capability URNs. */
  capabilities?: readonly string[];
  /** Optional signed metadata JWT; AccessOnce exposes but does not verify it. */
  signed_metadata?: string;
};
