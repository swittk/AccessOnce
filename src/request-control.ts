import type { Access } from "./access.js";
import { parseAccessGrant } from "./control-wire.js";
import type { AccessValidity } from "./types.js";
import type {
  AccessRelationshipRequestAuthority,
  AccessRequestAuthority,
  AccessRequestHistoryPage,
  AccessRequestHistoryQuery,
  AccessRequestRecord,
  AccessRequestSubmit,
  AccessRequestTransition,
  AccessRequestTransitionAction,
} from "./request.js";

/** Bounded decoder settings for untrusted access-request transport payloads. */
export type AccessRequestDecodeOptions = {
  /** Maximum validity windows accepted on one requested/approved authority. */
  maximumValidityWindows?: number;
  /** Maximum requester/decision reason length accepted from the transport. */
  maximumReasonLength?: number;
  /** Maximum audit-history page size accepted from untrusted query payloads; defaults to 256. */
  maximumHistoryPageSize?: number;
};

/** Separate transport for indexed audit/history reads so ordinary requester clients do not gain a discovery API. */
export type AccessRequestHistoryTransport<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Execute one bounded indexed history query; endpoint authorization remains application-owned. */
  query(
    request: AccessRequestHistoryQuery<Permission>,
    signal?: AbortSignal,
  ): Promise<AccessRequestHistoryPage<Permission, Dimension, Attribute, Route>>;
};

/** Small audit/admin client for indexed request-history queries. */
export type AccessRequestHistoryClient<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Query durable request history through the host's indexed backend implementation. */
  query(
    request: AccessRequestHistoryQuery<Permission>,
    signal?: AbortSignal,
  ): Promise<AccessRequestHistoryPage<Permission, Dimension, Attribute, Route>>;
};

/** Minimal read request for one durable access request. */
export type AccessRequestReadRequest = {
  /** Durable request identifier to load. */
  requestId: string;
};

/** Transport-neutral frontend request interface; endpoint authentication remains application-owned. */
export type AccessRequestControlTransport<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Submit exact requested authority. */
  submit(
    request: AccessRequestSubmit<Permission, Dimension, Attribute>,
    signal?: AbortSignal,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Read one durable request by id. */
  read(
    request: AccessRequestReadRequest,
    signal?: AbortSignal,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Apply one approve/deny/cancel transition. */
  transition(
    request: AccessRequestTransition<Permission, Dimension, Attribute>,
    signal?: AbortSignal,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
};

/** Arguments accepted by the request client's submit helper. */
export type AccessRequestControlSubmitArgs<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = AccessRequestSubmit<Permission, Dimension, Attribute> & {
  /** Optional transport cancellation signal. */
  signal?: AbortSignal;
};

/** Arguments accepted by approve client helper. */
export type AccessRequestControlApproveArgs<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** Durable request being approved. */
  requestId: string;
  /** Revision loaded before the action. */
  expectedRevision: string;
  /** Optional equal-or-narrower authority; omitted approves exactly what was requested. */
  authority?: AccessRequestAuthority<Permission, Dimension, Attribute>;
  /** Optional durable approval explanation. */
  reason?: string;
  /** Optional transport cancellation signal. */
  signal?: AbortSignal;
};

/** Arguments accepted by deny/cancel client helpers. */
export type AccessRequestControlRejectArgs = {
  /** Durable request being transitioned. */
  requestId: string;
  /** Revision loaded before the action. */
  expectedRevision: string;
  /** Optional durable decision explanation. */
  reason?: string;
  /** Optional transport cancellation signal. */
  signal?: AbortSignal;
};

/** Small client surface for request submission, reads, and terminal user actions. */
export type AccessRequestControlClient<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
> = {
  /** Submit exact requested authority. */
  submit(
    args: AccessRequestControlSubmitArgs<Permission, Dimension, Attribute>,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Read one request. */
  read(
    requestId: string,
    signal?: AbortSignal,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Send one already-composed approve/deny/cancel transition. */
  transition(
    transition: AccessRequestTransition<Permission, Dimension, Attribute>,
    signal?: AbortSignal,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Approve exactly as requested or with equal-or-narrower authority. */
  approve(
    args: AccessRequestControlApproveArgs<Permission, Dimension, Attribute>,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Deny one request with an optional durable reason. */
  deny(
    args: AccessRequestControlRejectArgs,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Cancel one request with an optional durable reason. */
  cancel(
    args: AccessRequestControlRejectArgs,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
};

/** Narrow an unknown request-wire object without importing a schema/runtime dependency. */
function requestWireRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

/** Decode one required non-empty request-wire string. */
function requestWireString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

/** Decode an optional bounded decision reason without interpreting its contents. */
function requestWireReason(value: unknown, options: AccessRequestDecodeOptions): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string" || !value.trim()) throw new Error("reason must be a non-empty string");
  if (options.maximumReasonLength !== undefined && value.length > options.maximumReasonLength) {
    throw new Error("reason exceeds the configured maximum length");
  }
  return value;
}

/** Decode relationship validity with the same half-open temporal semantics as other AccessOnce wires. */
function parseRequestRelationshipValidity(
  value: unknown,
  options: AccessRequestDecodeOptions,
): AccessValidity | readonly AccessValidity[] | undefined {
  if (value === undefined) return undefined;
  const input = Array.isArray(value) ? value : [value];
  if (input.length === 0) {
    throw new Error("relationship authority validity must contain at least one window");
  }
  if (options.maximumValidityWindows !== undefined && input.length > options.maximumValidityWindows) {
    throw new Error("relationship authority has too many validity windows");
  }
  const windows: AccessValidity[] = [];
  for (const raw of input) {
    const window = requestWireRecord(raw, "relationship authority validity");
    const start = window.startsAtEpochMs;
    const end = window.endsAtEpochMs;
    if (start !== undefined && !Number.isSafeInteger(start)) {
      throw new Error("relationship authority startsAtEpochMs must be a safe integer");
    }
    if (end !== undefined && !Number.isSafeInteger(end)) {
      throw new Error("relationship authority endsAtEpochMs must be a safe integer");
    }
    if (start !== undefined && end !== undefined && Number(start) > Number(end)) {
      throw new Error("relationship authority start must not be after end");
    }
    windows.push({
      ...(start === undefined ? {} : { startsAtEpochMs: Number(start) }),
      ...(end === undefined ? {} : { endsAtEpochMs: Number(end) }),
    });
  }
  return Array.isArray(value) ? windows : windows[0]!;
}

/** Decode one exact object relationship request. */
function parseRelationshipRequestAuthority(
  value: Record<string, unknown>,
  options: AccessRequestDecodeOptions,
): AccessRelationshipRequestAuthority {
  const resource = requestWireRecord(value.resource, "relationship authority resource");
  const validity = parseRequestRelationshipValidity(value.validity, options);
  return {
    kind: "relationship",
    resource: {
      type: requestWireString(resource.type, "relationship authority resource.type"),
      id: requestWireString(resource.id, "relationship authority resource.id"),
    },
    relation: requestWireString(value.relation, "relationship authority relation"),
    ...(validity === undefined ? {} : { validity }),
  };
}

/** Decode actor-grant or exact-object authority from an untrusted request wire. */
export function parseAccessRequestAuthority<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
>(
  access: Access<Permission, Leaf, Dimension, Attribute>,
  input: unknown,
  options: AccessRequestDecodeOptions = {},
): AccessRequestAuthority<Permission, Dimension, Attribute> {
  const value = requestWireRecord(input, "access request authority");
  if (value.kind === "grant") {
    return {
      kind: "grant",
      grant: parseAccessGrant(access, value.grant, {
        ...(options.maximumValidityWindows === undefined
          ? {}
          : { maximumValidityWindows: options.maximumValidityWindows }),
      }),
    };
  }
  if (value.kind === "relationship") return parseRelationshipRequestAuthority(value, options);
  throw new Error("access request authority kind must be grant or relationship");
}

/** Decode one untrusted request submission using catalog-aware grant parsing and bounded relationship parsing. */
export function parseAccessRequestSubmitRequest<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
>(
  access: Access<Permission, Leaf, Dimension, Attribute>,
  input: unknown,
  options: AccessRequestDecodeOptions = {},
): AccessRequestSubmit<Permission, Dimension, Attribute> {
  const request = requestWireRecord(input, "access request submit request");
  const reason = requestWireReason(request.reason, options);
  return {
    idempotencyKey: requestWireString(request.idempotencyKey, "idempotencyKey"),
    subjectId: requestWireString(request.subjectId, "subjectId"),
    ruleId: requestWireString(request.ruleId, "ruleId"),
    authority: parseAccessRequestAuthority(access, request.authority, options),
    ...(reason === undefined ? {} : { reason }),
  };
}

/** Decode one optional safe-integer history timestamp. */
function requestHistoryTime(value: unknown, label: string): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value)) throw new Error(`${label} must be a safe integer`);
  return Number(value);
}

/** Decode a bounded audit-history query without ever implementing an in-memory scan fallback. */
export function parseAccessRequestHistoryQuery<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
>(
  access: Access<Permission, Leaf, Dimension, Attribute>,
  input: unknown,
  options: AccessRequestDecodeOptions = {},
): AccessRequestHistoryQuery<Permission> {
  const request = requestWireRecord(input, "access request history query");
  const requesterId = request.requesterId === undefined ? undefined : requestWireString(request.requesterId, "requesterId");
  const subjectId = request.subjectId === undefined ? undefined : requestWireString(request.subjectId, "subjectId");
  const ruleId = request.ruleId === undefined ? undefined : requestWireString(request.ruleId, "ruleId");
  let states: AccessRequestHistoryQuery<Permission>["states"];
  if (request.states !== undefined) {
    if (!Array.isArray(request.states) || request.states.length === 0) throw new Error("states must be a non-empty array");
    const allowed = new Set(["pending", "issuing", "approved", "denied", "cancelled", "expired"]);
    const parsed: Array<"pending" | "issuing" | "approved" | "denied" | "cancelled" | "expired"> = [];
    for (const state of request.states) {
      if (typeof state !== "string" || !allowed.has(state)) throw new Error("states contains an invalid access request state");
      if (!parsed.includes(state as (typeof parsed)[number])) parsed.push(state as (typeof parsed)[number]);
    }
    states = parsed;
  }
  const authorityKind = request.authorityKind;
  if (authorityKind !== undefined && authorityKind !== "grant" && authorityKind !== "relationship") {
    throw new Error("authorityKind must be grant or relationship");
  }
  let permission: Permission | undefined;
  if (request.permission !== undefined) {
    if (typeof request.permission !== "string" || !access.catalog.isPermission(request.permission)) {
      throw new Error("permission must be a catalog permission");
    }
    permission = request.permission;
  }
  const resourceType = request.resourceType === undefined ? undefined : requestWireString(request.resourceType, "resourceType");
  const resourceId = request.resourceId === undefined ? undefined : requestWireString(request.resourceId, "resourceId");
  if (resourceId !== undefined && resourceType === undefined) throw new Error("resourceId requires resourceType");
  const relation = request.relation === undefined ? undefined : requestWireString(request.relation, "relation");
  const submittedFromEpochMs = requestHistoryTime(request.submittedFromEpochMs, "submittedFromEpochMs");
  const submittedUntilEpochMs = requestHistoryTime(request.submittedUntilEpochMs, "submittedUntilEpochMs");
  const decidedFromEpochMs = requestHistoryTime(request.decidedFromEpochMs, "decidedFromEpochMs");
  const decidedUntilEpochMs = requestHistoryTime(request.decidedUntilEpochMs, "decidedUntilEpochMs");
  if (submittedFromEpochMs !== undefined && submittedUntilEpochMs !== undefined && submittedFromEpochMs > submittedUntilEpochMs) {
    throw new Error("submittedFromEpochMs must not be after submittedUntilEpochMs");
  }
  if (decidedFromEpochMs !== undefined && decidedUntilEpochMs !== undefined && decidedFromEpochMs > decidedUntilEpochMs) {
    throw new Error("decidedFromEpochMs must not be after decidedUntilEpochMs");
  }
  const cursor = request.cursor === undefined ? undefined : requestWireString(request.cursor, "cursor");
  const maximum = options.maximumHistoryPageSize ?? 256;
  let limit: number | undefined;
  if (request.limit !== undefined) {
    if (!Number.isInteger(request.limit) || Number(request.limit) < 1 || Number(request.limit) > maximum) {
      throw new Error(`limit must be an integer between 1 and ${maximum}`);
    }
    limit = Number(request.limit);
  }
  return {
    ...(requesterId === undefined ? {} : { requesterId }),
    ...(subjectId === undefined ? {} : { subjectId }),
    ...(ruleId === undefined ? {} : { ruleId }),
    ...(states === undefined ? {} : { states }),
    ...(authorityKind === undefined ? {} : { authorityKind }),
    ...(permission === undefined ? {} : { permission }),
    ...(resourceType === undefined ? {} : { resourceType }),
    ...(resourceId === undefined ? {} : { resourceId }),
    ...(relation === undefined ? {} : { relation }),
    ...(submittedFromEpochMs === undefined ? {} : { submittedFromEpochMs }),
    ...(submittedUntilEpochMs === undefined ? {} : { submittedUntilEpochMs }),
    ...(decidedFromEpochMs === undefined ? {} : { decidedFromEpochMs }),
    ...(decidedUntilEpochMs === undefined ? {} : { decidedUntilEpochMs }),
    ...(cursor === undefined ? {} : { cursor }),
    ...(limit === undefined ? {} : { limit }),
  };
}

/** Create a separate audit/admin history client over any indexed application transport. */
export function createAccessRequestHistoryClient<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
>(
  transport: AccessRequestHistoryTransport<Permission, Dimension, Attribute, Route>,
): AccessRequestHistoryClient<Permission, Dimension, Attribute, Route> {
  return {
    query(request, signal) {
      return transport.query(request, signal);
    },
  };
}

/** Decode one untrusted durable-request read. */
export function parseAccessRequestReadRequest(input: unknown): AccessRequestReadRequest {
  const request = requestWireRecord(input, "access request read request");
  return { requestId: requestWireString(request.requestId, "requestId") };
}

/** Decode one untrusted approve/deny/cancel transition without accepting system-only expiry. */
export function parseAccessRequestTransitionRequest<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
>(
  access: Access<Permission, Leaf, Dimension, Attribute>,
  input: unknown,
  options: AccessRequestDecodeOptions = {},
): AccessRequestTransition<Permission, Dimension, Attribute> {
  const request = requestWireRecord(input, "access request transition request");
  const action = request.action;
  if (action !== "approve" && action !== "deny" && action !== "cancel") {
    throw new Error("access request action must be approve, deny, or cancel");
  }
  const reason = requestWireReason(request.reason, options);
  if (action !== "approve" && request.authority !== undefined) {
    throw new Error("only approve may carry selected authority");
  }
  const authority = action === "approve" && request.authority !== undefined
    ? parseAccessRequestAuthority(access, request.authority, options)
    : undefined;
  return {
    requestId: requestWireString(request.requestId, "requestId"),
    expectedRevision: requestWireString(request.expectedRevision, "expectedRevision"),
    action,
    ...(authority === undefined ? {} : { authority }),
    ...(reason === undefined ? {} : { reason }),
  };
}

/** Create the tiny frontend request client over any REST/RPC/IPC/application transport. */
export function createAccessRequestControlClient<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  Route = unknown,
>(
  transport: AccessRequestControlTransport<Permission, Dimension, Attribute, Route>,
): AccessRequestControlClient<Permission, Dimension, Attribute, Route> {
  /** Send one convenience terminal action without duplicating transport semantics. */
  function rejectAction(
    action: Exclude<AccessRequestTransitionAction, "approve">,
    args: AccessRequestControlRejectArgs,
  ) {
    return transport.transition(
      {
        requestId: args.requestId,
        expectedRevision: args.expectedRevision,
        action,
        ...(args.reason === undefined ? {} : { reason: args.reason }),
      },
      args.signal,
    );
  }

  return {
    submit(args) {
      return transport.submit(
        {
          idempotencyKey: args.idempotencyKey,
          subjectId: args.subjectId,
          ruleId: args.ruleId,
          authority: args.authority,
          ...(args.reason === undefined ? {} : { reason: args.reason }),
        },
        args.signal,
      );
    },
    read(requestId, signal) {
      return transport.read({ requestId }, signal);
    },
    transition(transition, signal) {
      return transport.transition(transition, signal);
    },
    approve(args) {
      return transport.transition(
        {
          requestId: args.requestId,
          expectedRevision: args.expectedRevision,
          action: "approve",
          ...(args.authority === undefined ? {} : { authority: args.authority }),
          ...(args.reason === undefined ? {} : { reason: args.reason }),
        },
        args.signal,
      );
    },
    deny(args) {
      return rejectAction("deny", args);
    },
    cancel(args) {
      return rejectAction("cancel", args);
    },
  };
}
