import {
  parseAuthZenAction,
  parseAuthZenDecision,
  parseAuthZenEvaluationsResponse,
  parseAuthZenPdpMetadata,
  parseAuthZenResource,
  parseAuthZenSearchResponse,
  parseAuthZenSubject,
} from "./codec.js";
import { AuthZenHttpError, AuthZenRequestError } from "./errors.js";
import type {
  AuthZenAction,
  AuthZenActionSearchRequest,
  AuthZenDecision,
  AuthZenEvaluationRequest,
  AuthZenEvaluationsRequest,
  AuthZenEvaluationsResponse,
  AuthZenPdpMetadata,
  AuthZenResource,
  AuthZenResourceSearchRequest,
  AuthZenSearchResponse,
  AuthZenSubject,
  AuthZenSubjectSearchRequest,
} from "./types.js";

/** Transport options shared by AuthZEN HTTPS discovery and API clients. */
export type AuthZenHttpTransportOptions = {
  /** Fetch implementation; defaults to the platform global fetch. */
  fetch?: typeof fetch;
  /** Static or lazily produced headers such as Authorization. */
  headers?: HeadersInit | (() => HeadersInit | Promise<HeadersInit>);
  /** Optional generator for X-Request-ID on authorization API requests. */
  requestId?: () => string | undefined;
};

/** Standard AuthZEN HTTPS client for evaluation, boxcar evaluation, and search endpoints. */
export type AuthZenHttpClient = {
  /** Execute one standard Access Evaluation request. */
  evaluate(request: AuthZenEvaluationRequest): Promise<AuthZenDecision>;
  /** Execute one standard Access Evaluations boxcar request. */
  evaluations(
    request: AuthZenEvaluationsRequest,
  ): Promise<AuthZenDecision | AuthZenEvaluationsResponse>;
  /** Search subjects when the configured PDP exposes that endpoint. */
  searchSubjects(
    request: AuthZenSubjectSearchRequest,
  ): Promise<AuthZenSearchResponse<AuthZenSubject>>;
  /** Search resources when the configured PDP exposes that endpoint. */
  searchResources(
    request: AuthZenResourceSearchRequest,
  ): Promise<AuthZenSearchResponse<AuthZenResource>>;
  /** Search actions when the configured PDP exposes that endpoint. */
  searchActions(
    request: AuthZenActionSearchRequest,
  ): Promise<AuthZenSearchResponse<AuthZenAction>>;
};

/** Internal endpoint set used by the transport-neutral public client facade. */
type AuthZenHttpEndpoints = {
  /** Single-evaluation endpoint. */
  evaluation: string;
  /** Optional boxcar endpoint. */
  evaluations?: string;
  /** Optional subject-search endpoint. */
  searchSubjects?: string;
  /** Optional resource-search endpoint. */
  searchResources?: string;
  /** Optional action-search endpoint. */
  searchActions?: string;
};

/** Validate the AuthZEN PDP identifier rules needed by discovery/default endpoint construction. */
function parsePolicyDecisionPoint(value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthZenRequestError("AuthZEN policy_decision_point must be an absolute URL");
  }
  if (url.protocol !== "https:") {
    throw new AuthZenRequestError("AuthZEN policy_decision_point must use https");
  }
  if (url.search || url.hash) {
    throw new AuthZenRequestError("AuthZEN policy_decision_point must not contain query or fragment components");
  }
  return url;
}

/** Validate an advertised operation endpoint before configured credentials can be sent to it. */
function requireHttpsEndpoint(value: string, field: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new AuthZenRequestError(`AuthZEN ${field} must be an absolute URL`);
  }
  if (url.protocol !== "https:") {
    throw new AuthZenRequestError(`AuthZEN ${field} must use https`);
  }
  return url.href;
}

/** Append one default AuthZEN path to a PDP identifier while preserving any tenant path prefix. */
function defaultEndpoint(policyDecisionPoint: URL, path: string): string {
  const base = policyDecisionPoint.href.endsWith("/")
    ? policyDecisionPoint.href
    : `${policyDecisionPoint.href}/`;
  return new URL(path.replace(/^\//u, ""), base).href;
}

/** Build the RFC8615 well-known metadata URL by inserting the AuthZEN suffix before the PDP path. */
export function authZenMetadataUrl(policyDecisionPoint: string): string {
  const pdp = parsePolicyDecisionPoint(policyDecisionPoint);
  const originalPath = pdp.pathname === "/" ? "" : pdp.pathname;
  pdp.pathname = `/.well-known/authzen-configuration${originalPath}`;
  return pdp.href;
}

/** Resolve caller headers without mutating a reusable Headers object supplied by the application. */
async function resolveHeaders(
  options: AuthZenHttpTransportOptions,
  json: boolean,
  requestId?: string,
): Promise<Headers> {
  const supplied =
    typeof options.headers === "function"
      ? await options.headers()
      : options.headers;
  const headers = new Headers(supplied);
  if (json) headers.set("Content-Type", "application/json");
  if (requestId) headers.set("X-Request-ID", requestId);
  return headers;
}

/** Parse a successful JSON response and enforce request-id echo when the PEP supplied one. */
async function readJsonResponse(response: Response, requestId?: string): Promise<unknown> {
  if (!response.ok) {
    let text = "";
    try {
      text = await response.text();
    } catch {
      // The HTTP status remains the primary transport failure even when the optional error body aborts.
    }
    throw new AuthZenHttpError(response.status, text);
  }
  const text = await response.text();
  if (requestId && response.headers.get("X-Request-ID") !== requestId) {
    throw new AuthZenRequestError("AuthZEN PDP did not echo the supplied X-Request-ID");
  }
  const contentType = response.headers.get("Content-Type") ?? "";
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/json") {
    throw new AuthZenRequestError("AuthZEN successful response must use application/json");
  }
  try {
    const parsed: unknown = JSON.parse(text);
    return parsed;
  } catch (error) {
    throw new AuthZenRequestError("AuthZEN response body is not valid JSON", { cause: error });
  }
}

/** POST one AuthZEN JSON object through the normative HTTPS binding. */
async function postJson(
  endpoint: string,
  body: object,
  options: AuthZenHttpTransportOptions,
): Promise<unknown> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("No fetch implementation is available for AuthZEN HTTPS");
  const requestId = options.requestId?.();
  const response = await fetchImpl(endpoint, {
    method: "POST",
    redirect: "error",
    headers: await resolveHeaders(options, true, requestId),
    body: JSON.stringify(body),
  });
  return readJsonResponse(response, requestId);
}

/** Require one optional endpoint before invoking a capability discovered as unsupported. */
function requireEndpoint(endpoint: string | undefined, capability: string): string {
  if (!endpoint) throw new Error(`AuthZEN PDP does not advertise ${capability}`);
  return endpoint;
}

/** Parse one Access Evaluations response using the request mode and short-circuit contract. */
function parseEvaluationsHttpResponse(
  request: AuthZenEvaluationsRequest,
  value: unknown,
): AuthZenDecision | AuthZenEvaluationsResponse {
  const requested = request.evaluations;
  if (!requested || requested.length === 0) return parseAuthZenDecision(value);

  const response = parseAuthZenEvaluationsResponse(value);
  const returned = response.evaluations;
  if (returned.length === 0 || returned.length > requested.length) {
    throw new AuthZenRequestError(
      "AuthZEN evaluations response cardinality does not match the request",
    );
  }

  const semantic = request.options?.evaluations_semantic ?? "execute_all";
  if (semantic === "execute_all") {
    if (returned.length !== requested.length) {
      throw new AuthZenRequestError(
        "AuthZEN execute_all response must contain one decision per requested evaluation",
      );
    }
    return response;
  }

  const shortCircuitDecision = semantic === "deny_on_first_deny" ? false : true;
  for (let index = 0; index < returned.length - 1; index += 1) {
    if (returned[index]!.decision === shortCircuitDecision) {
      throw new AuthZenRequestError(
        "AuthZEN evaluations response continued after its short-circuit decision",
      );
    }
  }
  if (returned.length < requested.length && returned.at(-1)!.decision !== shortCircuitDecision) {
    throw new AuthZenRequestError(
      "AuthZEN evaluations response ended before its short-circuit decision",
    );
  }
  return response;
}

/** Create the HTTP client implementation over one resolved endpoint set. */
function createClient(
  endpoints: AuthZenHttpEndpoints,
  options: AuthZenHttpTransportOptions,
): AuthZenHttpClient {
  return {
    async evaluate(request) {
      return parseAuthZenDecision(await postJson(endpoints.evaluation, request, options));
    },
    async evaluations(request) {
      const endpoint = requireEndpoint(endpoints.evaluations, "Access Evaluations");
      return parseEvaluationsHttpResponse(
        request,
        await postJson(endpoint, request, options),
      );
    },
    async searchSubjects(request) {
      const endpoint = requireEndpoint(endpoints.searchSubjects, "Subject Search");
      return parseAuthZenSearchResponse(
        await postJson(endpoint, request, options),
        parseAuthZenSubject,
      );
    },
    async searchResources(request) {
      const endpoint = requireEndpoint(endpoints.searchResources, "Resource Search");
      return parseAuthZenSearchResponse(
        await postJson(endpoint, request, options),
        parseAuthZenResource,
      );
    },
    async searchActions(request) {
      const endpoint = requireEndpoint(endpoints.searchActions, "Action Search");
      return parseAuthZenSearchResponse(
        await postJson(endpoint, request, options),
        parseAuthZenAction,
      );
    },
  };
}

/** Create a client that uses AuthZEN 1.0's default HTTPS paths below one PDP identifier. */
export function createAuthZenHttpClient(
  policyDecisionPoint: string,
  options: AuthZenHttpTransportOptions = {},
): AuthZenHttpClient {
  const pdp = parsePolicyDecisionPoint(policyDecisionPoint);
  return createClient(
    {
      evaluation: defaultEndpoint(pdp, "/access/v1/evaluation"),
      evaluations: defaultEndpoint(pdp, "/access/v1/evaluations"),
      searchSubjects: defaultEndpoint(pdp, "/access/v1/search/subject"),
      searchResources: defaultEndpoint(pdp, "/access/v1/search/resource"),
      searchActions: defaultEndpoint(pdp, "/access/v1/search/action"),
    },
    options,
  );
}

/** Create a client from discovered metadata, honoring absent optional endpoints as unsupported capabilities. */
export function createAuthZenHttpClientFromMetadata(
  metadata: AuthZenPdpMetadata,
  options: AuthZenHttpTransportOptions = {},
): AuthZenHttpClient {
  parsePolicyDecisionPoint(metadata.policy_decision_point);
  return createClient(
    {
      evaluation: requireHttpsEndpoint(
        metadata.access_evaluation_endpoint,
        "access_evaluation_endpoint",
      ),
      ...(metadata.access_evaluations_endpoint !== undefined
        ? {
            evaluations: requireHttpsEndpoint(
              metadata.access_evaluations_endpoint,
              "access_evaluations_endpoint",
            ),
          }
        : {}),
      ...(metadata.search_subject_endpoint !== undefined
        ? {
            searchSubjects: requireHttpsEndpoint(
              metadata.search_subject_endpoint,
              "search_subject_endpoint",
            ),
          }
        : {}),
      ...(metadata.search_resource_endpoint !== undefined
        ? {
            searchResources: requireHttpsEndpoint(
              metadata.search_resource_endpoint,
              "search_resource_endpoint",
            ),
          }
        : {}),
      ...(metadata.search_action_endpoint !== undefined
        ? {
            searchActions: requireHttpsEndpoint(
              metadata.search_action_endpoint,
              "search_action_endpoint",
            ),
          }
        : {}),
    },
    options,
  );
}

/** Discover and validate one AuthZEN PDP metadata document through the standard well-known URL. */
export async function discoverAuthZenPdpMetadata(
  policyDecisionPoint: string,
  options: AuthZenHttpTransportOptions = {},
): Promise<AuthZenPdpMetadata> {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (!fetchImpl) throw new Error("No fetch implementation is available for AuthZEN discovery");
  const response = await fetchImpl(authZenMetadataUrl(policyDecisionPoint), {
    method: "GET",
    redirect: "error",
    headers: await resolveHeaders(options, false),
  });
  const metadata = parseAuthZenPdpMetadata(await readJsonResponse(response));
  parsePolicyDecisionPoint(policyDecisionPoint);
  parsePolicyDecisionPoint(metadata.policy_decision_point);
  if (metadata.policy_decision_point !== policyDecisionPoint) {
    throw new AuthZenRequestError(
      "AuthZEN metadata policy_decision_point does not match the requested PDP identifier",
    );
  }
  return metadata;
}

/** Discover one PDP and return a ready HTTP client using the endpoints it explicitly advertises. */
export async function discoverAuthZenHttpClient(
  policyDecisionPoint: string,
  options: AuthZenHttpTransportOptions = {},
): Promise<AuthZenHttpClient> {
  return createAuthZenHttpClientFromMetadata(
    await discoverAuthZenPdpMetadata(policyDecisionPoint, options),
    options,
  );
}
