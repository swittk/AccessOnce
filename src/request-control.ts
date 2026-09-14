import type { Access } from "./access.js";
import { parseAccessGrant } from "./control-wire.js";
import type {
  AccessRequestRecord,
  AccessRequestSubmit,
  AccessRequestTransition,
  AccessRequestTransitionAction,
} from "./request.js";

/** Bounded decoder settings for untrusted access-request transport payloads. */
export type AccessRequestDecodeOptions = {
  /** Maximum validity windows accepted on one requested grant before policy evaluation. */
  maximumValidityWindows?: number;
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
    request: AccessRequestTransition,
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

/** Arguments accepted by approve/deny/cancel client helpers. */
export type AccessRequestControlTransitionArgs = {
  /** Durable request being transitioned. */
  requestId: string;
  /** Revision loaded before the action. */
  expectedRevision: string;
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
    transition: AccessRequestTransition,
    signal?: AbortSignal,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Approve one request using optimistic revision. */
  approve(
    args: AccessRequestControlTransitionArgs,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Deny one request using optimistic revision. */
  deny(
    args: AccessRequestControlTransitionArgs,
  ): Promise<AccessRequestRecord<Permission, Dimension, Attribute, Route>>;
  /** Cancel one request using optimistic revision. */
  cancel(
    args: AccessRequestControlTransitionArgs,
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

/** Decode one untrusted request submission using the same catalog-aware grant parser as grant administration. */
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
  return {
    idempotencyKey: requestWireString(request.idempotencyKey, "idempotencyKey"),
    subjectId: requestWireString(request.subjectId, "subjectId"),
    policyId: requestWireString(request.policyId, "policyId"),
    grant: parseAccessGrant(access, request.grant, {
      ...(options.maximumValidityWindows === undefined
        ? {}
        : { maximumValidityWindows: options.maximumValidityWindows }),
    }),
  };
}

/** Decode one untrusted durable-request read. */
export function parseAccessRequestReadRequest(input: unknown): AccessRequestReadRequest {
  const request = requestWireRecord(input, "access request read request");
  return { requestId: requestWireString(request.requestId, "requestId") };
}

/** Decode one untrusted approve/deny/cancel transition without accepting system-only expiry. */
export function parseAccessRequestTransitionRequest(input: unknown): AccessRequestTransition {
  const request = requestWireRecord(input, "access request transition request");
  const action = request.action;
  if (action !== "approve" && action !== "deny" && action !== "cancel") {
    throw new Error("access request action must be approve, deny, or cancel");
  }
  return {
    requestId: requestWireString(request.requestId, "requestId"),
    expectedRevision: requestWireString(request.expectedRevision, "expectedRevision"),
    action,
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
  function transitionAction(
    action: AccessRequestTransitionAction,
    args: AccessRequestControlTransitionArgs,
  ) {
    return transport.transition(
      {
        requestId: args.requestId,
        expectedRevision: args.expectedRevision,
        action,
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
          policyId: args.policyId,
          grant: args.grant,
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
      return transitionAction("approve", args);
    },
    deny(args) {
      return transitionAction("deny", args);
    },
    cancel(args) {
      return transitionAction("cancel", args);
    },
  };
}
