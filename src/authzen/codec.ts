import type {
  AuthZenAction,
  AuthZenContext,
  AuthZenDecision,
  AuthZenEvaluationsResponse,
  AuthZenObject,
  AuthZenPdpMetadata,
  AuthZenResource,
  AuthZenSearchPageResponse,
  AuthZenSearchResponse,
  AuthZenSubject,
} from "./types.js";
import { AuthZenRequestError } from "./errors.js";

/** Return a plain non-array object or reject the wire value. */
export function requireAuthZenObject(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AuthZenRequestError(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

/** Return one required string field. */
export function requireAuthZenString(
  object: Record<string, unknown>,
  key: string,
  label: string,
): string {
  const value = object[key];
  if (typeof value !== "string") {
    throw new AuthZenRequestError(`${label}.${key} must be a string`);
  }
  return value;
}

/** Parse one optional object field. */
export function optionalAuthZenObject(
  object: Record<string, unknown>,
  key: string,
  label: string,
): AuthZenObject | undefined {
  const value = object[key];
  return value === undefined
    ? undefined
    : requireAuthZenObject(value, `${label}.${key}`);
}

/** Parse one complete AuthZEN subject. */
export function parseAuthZenSubject(value: unknown, label: string): AuthZenSubject {
  const object = requireAuthZenObject(value, label);
  const properties = optionalAuthZenObject(object, "properties", label);
  return {
    type: requireAuthZenString(object, "type", label),
    id: requireAuthZenString(object, "id", label),
    ...(properties ? { properties } : {}),
  };
}

/** Parse one complete AuthZEN resource. */
export function parseAuthZenResource(value: unknown, label: string): AuthZenResource {
  const object = requireAuthZenObject(value, label);
  const properties = optionalAuthZenObject(object, "properties", label);
  return {
    type: requireAuthZenString(object, "type", label),
    id: requireAuthZenString(object, "id", label),
    ...(properties ? { properties } : {}),
  };
}

/** Parse one AuthZEN action. */
export function parseAuthZenAction(value: unknown, label: string): AuthZenAction {
  const object = requireAuthZenObject(value, label);
  const properties = optionalAuthZenObject(object, "properties", label);
  return {
    name: requireAuthZenString(object, "name", label),
    ...(properties ? { properties } : {}),
  };
}

/** Parse optional AuthZEN context. */
export function parseAuthZenContext(
  value: unknown,
  label: string,
): AuthZenContext | undefined {
  return value === undefined ? undefined : requireAuthZenObject(value, label);
}

/** Parse one AuthZEN allow/deny decision. */
export function parseAuthZenDecision(value: unknown, label = "response"): AuthZenDecision {
  const object = requireAuthZenObject(value, label);
  if (typeof object.decision !== "boolean") {
    throw new AuthZenRequestError(`${label}.decision must be a boolean`);
  }
  const context = parseAuthZenContext(object.context, `${label}.context`);
  return {
    decision: object.decision,
    ...(context ? { context } : {}),
  };
}

/** Parse an AuthZEN boxcar response. */
export function parseAuthZenEvaluationsResponse(
  value: unknown,
): AuthZenEvaluationsResponse {
  const object = requireAuthZenObject(value, "response");
  if (!Array.isArray(object.evaluations)) {
    throw new AuthZenRequestError("response.evaluations must be an array");
  }
  const evaluations: AuthZenDecision[] = [];
  for (let index = 0; index < object.evaluations.length; index += 1) {
    evaluations.push(
      parseAuthZenDecision(object.evaluations[index], `response.evaluations[${index}]`),
    );
  }
  return { evaluations };
}

/** Parse one optional non-negative integer field. */
function optionalNonNegativeInteger(
  object: Record<string, unknown>,
  key: string,
  label: string,
): number | undefined {
  const value = object[key];
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new AuthZenRequestError(`${label}.${key} must be a non-negative safe integer`);
  }
  return value as number;
}

/** Parse AuthZEN search pagination metadata. */
function parseSearchPage(value: unknown): AuthZenSearchPageResponse {
  const object = requireAuthZenObject(value, "response.page");
  const properties = optionalAuthZenObject(object, "properties", "response.page");
  const count = optionalNonNegativeInteger(object, "count", "response.page");
  const total = optionalNonNegativeInteger(object, "total", "response.page");
  return {
    next_token: requireAuthZenString(object, "next_token", "response.page"),
    ...(count !== undefined ? { count } : {}),
    ...(total !== undefined ? { total } : {}),
    ...(properties ? { properties } : {}),
  };
}

/** Parse one AuthZEN search response using the entity parser for that endpoint. */
export function parseAuthZenSearchResponse<Entity>(
  value: unknown,
  parseEntity: (value: unknown, label: string) => Entity,
): AuthZenSearchResponse<Entity> {
  const object = requireAuthZenObject(value, "response");
  if (!Array.isArray(object.results)) {
    throw new AuthZenRequestError("response.results must be an array");
  }
  const results: Entity[] = [];
  for (let index = 0; index < object.results.length; index += 1) {
    results.push(parseEntity(object.results[index], `response.results[${index}]`));
  }
  const page = object.page === undefined ? undefined : parseSearchPage(object.page);
  const context = parseAuthZenContext(object.context, "response.context");
  return {
    ...(page ? { page } : {}),
    ...(context ? { context } : {}),
    results,
  };
}

/** Parse AuthZEN PDP discovery metadata and ignore unknown extension fields. */
export function parseAuthZenPdpMetadata(value: unknown): AuthZenPdpMetadata {
  const object = requireAuthZenObject(value, "metadata");
  const optionalEndpoint = (key: string) => {
    const endpoint = object[key];
    if (endpoint === undefined) return undefined;
    if (typeof endpoint !== "string") {
      throw new AuthZenRequestError(`metadata.${key} must be a string`);
    }
    return endpoint;
  };
  let capabilities: string[] | undefined;
  if (object.capabilities !== undefined) {
    if (!Array.isArray(object.capabilities)) {
      throw new AuthZenRequestError("metadata.capabilities must be an array");
    }
    capabilities = [];
    for (const capability of object.capabilities) {
      if (typeof capability !== "string") {
        throw new AuthZenRequestError("metadata.capabilities entries must be strings");
      }
      capabilities.push(capability);
    }
  }
  const signedMetadata = optionalEndpoint("signed_metadata");
  const accessEvaluationsEndpoint = optionalEndpoint("access_evaluations_endpoint");
  const subjectEndpoint = optionalEndpoint("search_subject_endpoint");
  const resourceEndpoint = optionalEndpoint("search_resource_endpoint");
  const actionEndpoint = optionalEndpoint("search_action_endpoint");
  return {
    policy_decision_point: requireAuthZenString(
      object,
      "policy_decision_point",
      "metadata",
    ),
    access_evaluation_endpoint: requireAuthZenString(
      object,
      "access_evaluation_endpoint",
      "metadata",
    ),
    ...(accessEvaluationsEndpoint !== undefined
      ? { access_evaluations_endpoint: accessEvaluationsEndpoint }
      : {}),
    ...(subjectEndpoint !== undefined ? { search_subject_endpoint: subjectEndpoint } : {}),
    ...(resourceEndpoint !== undefined ? { search_resource_endpoint: resourceEndpoint } : {}),
    ...(actionEndpoint !== undefined ? { search_action_endpoint: actionEndpoint } : {}),
    ...(capabilities ? { capabilities } : {}),
    ...(signedMetadata ? { signed_metadata: signedMetadata } : {}),
  };
}
