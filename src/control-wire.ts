import type { Access } from "./access.js";
import {
  createAccessControlPlane,
  createAccessPublicationControlPlane,
  type AccessControlPlane,
  type AccessControlPlaneOptions,
  type AccessPublicationControlPlaneOptions,
} from "./control.js";
import type { AccessGrant, AccessScopeSource, EffectiveAccessSnapshot } from "./types.js";

/** One or several values accepted by ergonomic control-client helpers. */
export type AccessOneOrMany<Value> = Value | readonly Value[];

/** Add one or more exact grants without duplicating semantically identical grants. */
export type AccessGrantAddMutation<
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Stable wire discriminator for additive grant mutation. */
  operation: "add";
  /** Grants to add atomically with the rest of this request. */
  grants: readonly AccessGrant<Permission, Dimension, Attribute>[];
};

/** Remove one or more exact permission+scope grants. */
export type AccessGrantRemoveMutation<
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Stable wire discriminator for exact grant removal. */
  operation: "remove";
  /** Exact semantic grants to remove. */
  grants: readonly AccessGrant<Permission, Dimension, Attribute>[];
};

/** Remove every direct grant whose permission matches one of the supplied nodes. */
export type AccessGrantRemovePermissionsMutation<Permission extends string> = {
  /** Stable wire discriminator for permission-wide removal. */
  operation: "remove-permissions";
  /** Permission nodes whose direct grants should all be removed regardless of scope. */
  permissions: readonly Permission[];
};

/** Replace the complete direct-grant collection in one mutation step. */
export type AccessGrantReplaceMutation<
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Stable wire discriminator for complete direct-grant replacement. */
  operation: "replace";
  /** Complete replacement direct-grant set. */
  grants: readonly AccessGrant<Permission, Dimension, Attribute>[];
};

/** Built-in frontend/backend mutation vocabulary for direct permission grants. */
export type AccessGrantMutation<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> =
  | AccessGrantAddMutation<Permission, Dimension, Attribute>
  | AccessGrantRemoveMutation<Permission, Dimension, Attribute>
  | AccessGrantRemovePermissionsMutation<Permission>
  | AccessGrantReplaceMutation<Permission, Dimension, Attribute>;

/** Minimal frontend-to-backend request for loading one editable authority source. */
export type AccessControlReadRequest = {
  /** Stable application subject whose editable direct grants are requested. */
  subjectId: string;
};

/** Generic optimistic-concurrency envelope for frontend-to-backend authority mutations. */
export type AccessControlMutationRequest<Mutation> = {
  /** Stable application subject whose authority source is changing. */
  subjectId: string;
  /** Durable revision the editor loaded; stale edits must reject rather than overwrite newer authority. */
  expectedRevision: string;
  /** Ordered mutations applied atomically to the same source revision. */
  mutations: readonly Mutation[];
};

/** Editable direct-grant state returned by both control reads and successful mutations. */
export type AccessGrantControlState<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
> = {
  /** New durable source revision to use for the editor's next mutation. */
  revision: string;
  /** Canonical direct grants after every mutation in the request has been applied. */
  grants: readonly AccessGrant<Permission, Dimension, Attribute>[];
};

/** BYO client transport for AccessOnce control-plane mutations over Parse Cloud, REST, RPC, IPC, or another wire. */
export type AccessControlMutationTransport<Mutation, Response> = {
  /** Send one optimistic-concurrency mutation request to the authoritative backend. */
  mutate(
    request: AccessControlMutationRequest<Mutation>,
    signal?: AbortSignal,
  ): Promise<Response>;
};

/** Recommended direct-grant frontend transport including the read needed to obtain an editor revision. */
export type AccessGrantControlTransport<
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
  ExtraMutation = never,
  State extends AccessGrantControlState<Permission, Dimension, Attribute> = AccessGrantControlState<Permission, Dimension, Attribute>,
> = AccessControlMutationTransport<
  AccessGrantMutation<Permission, Dimension, Attribute> | ExtraMutation,
  State
> & {
  /** Load the subject's current editable direct grants and optimistic-concurrency revision. */
  read(
    request: AccessControlReadRequest,
    signal?: AbortSignal,
  ): Promise<State>;
};

/** Mapping between an application authority source and its direct AccessOnce grant collection. */
export type AccessGrantSourceAdapter<
  Source,
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Read the source's direct editable permission grants. */
  grants(source: Source): readonly AccessGrant<Permission, Dimension, Attribute>[];
  /** Return a replacement source carrying the supplied direct grants without mutating the original source. */
  withGrants(
    source: Source,
    grants: readonly AccessGrant<Permission, Dimension, Attribute>[],
  ): Source;
};

/** Server-side direct-grant mutation service suitable for binding to any transport endpoint. */
export type AccessGrantControlService<
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
> = {
  /** Load one subject's current editable direct grants and source revision. */
  read(input: unknown): Promise<AccessGrantControlState<Permission, Dimension, Attribute>>;
  /** Parse, validate, apply, and safely publish one frontend/backend grant mutation request. */
  mutate(input: unknown): Promise<AccessGrantControlState<Permission, Dimension, Attribute>>;
};

/** Arguments shared by the convenience add/remove/replace control-client helpers. */
export type AccessGrantControlClientArgs<Value> = {
  /** Stable application subject whose direct grants are changing. */
  subjectId: string;
  /** Revision the editor loaded. */
  expectedRevision: string;
  /** One or several values normalized into the batch wire request. */
  values: AccessOneOrMany<Value>;
  /** Optional transport cancellation signal. */
  signal?: AbortSignal;
};

/** Frontend-friendly direct-grant control client; every helper uses the same atomic batch protocol. */
export type AccessGrantControlClient<
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
  ExtraMutation = never,
  State extends AccessGrantControlState<Permission, Dimension, Attribute> = AccessGrantControlState<Permission, Dimension, Attribute>,
> = {
  /** Load the current editable grants and revision before presenting or mutating an admin form. */
  read(args: {
    /** Stable application subject whose direct grants are being edited. */
    subjectId: string;
    /** Optional transport cancellation signal. */
    signal?: AbortSignal;
  }): Promise<State>;
  /** Send an arbitrary ordered batch of built-in direct-grant mutations. */
  mutate(
    request: AccessControlMutationRequest<AccessGrantMutation<Permission, Dimension, Attribute> | ExtraMutation>,
    signal?: AbortSignal,
  ): Promise<State>;
  /** Add one or several exact grants. */
  add(
    args: AccessGrantControlClientArgs<AccessGrant<Permission, Dimension, Attribute>>,
  ): Promise<State>;
  /** Remove one or several exact grants including their scopes. */
  remove(
    args: AccessGrantControlClientArgs<AccessGrant<Permission, Dimension, Attribute>>,
  ): Promise<State>;
  /** Remove every direct grant for one or several permission nodes. */
  removePermissions(
    args: AccessGrantControlClientArgs<Permission>,
  ): Promise<State>;
  /** Replace the complete direct-grant set. */
  replace(args: {
    /** Stable application subject whose direct grants are changing. */
    subjectId: string;
    /** Revision the editor loaded. */
    expectedRevision: string;
    /** Complete replacement direct-grant set. */
    grants: readonly AccessGrant<Permission, Dimension, Attribute>[];
    /** Optional transport cancellation signal. */
    signal?: AbortSignal;
  }): Promise<State>;
};

/** Ensure a wire/source grant comparison is independent of caller array and object insertion order. */
export function accessGrantKey<
  Permission extends string,
  Dimension extends string,
  Attribute extends string,
>(grant: AccessGrant<Permission, Dimension, Attribute>): string {
  const dimensions = grant.scope ? Object.keys(grant.scope).sort() : [];
  const scope: unknown[] = [];
  for (const dimension of dimensions) {
    const constraint = grant.scope?.[dimension as Dimension];
    if (!constraint) continue;
    if (constraint.kind === "ids") {
      const ids = [...new Set(constraint.ids)];
      ids.sort();
      scope.push([dimension, "ids", ids]);
    } else {
      scope.push([dimension, "subject", constraint.attribute]);
    }
  }
  return JSON.stringify([grant.permission, scope]);
}

/** Combine additive bundles without changing scoped grant meaning or retaining duplicate entries. */
export function composeAccessGrants<Permission extends string, Dimension extends string, Attribute extends string>(
  ...sets: readonly (readonly AccessGrant<Permission, Dimension, Attribute>[])[]
): AccessGrant<Permission, Dimension, Attribute>[] {
  const unique = new Map<string, AccessGrant<Permission, Dimension, Attribute>>();
  for (const grants of sets) {
    for (const grant of grants) {
      const key = accessGrantKey(grant);
      if (!unique.has(key)) unique.set(key, grant);
    }
  }
  return [...unique.values()];
}

/** Apply one ordered admin batch with one index, rather than copying and rescanning every grant per edit. */
export function applyAccessGrantMutations<Permission extends string, Dimension extends string, Attribute extends string>(
  current: readonly AccessGrant<Permission, Dimension, Attribute>[],
  mutations: readonly AccessGrantMutation<Permission, Dimension, Attribute>[],
): AccessGrant<Permission, Dimension, Attribute>[] {
  const grants = new Map<string, AccessGrant<Permission, Dimension, Attribute>>();
  for (const grant of current) {
    const key = accessGrantKey(grant);
    if (!grants.has(key)) grants.set(key, grant);
  }
  for (const mutation of mutations) {
    if (mutation.operation === "remove-permissions") {
      // This removes direct entries only. A role/profile can still grant the same permission.
      const removed = new Set(mutation.permissions);
      for (const [key, grant] of grants) {
        if (removed.has(grant.permission)) grants.delete(key);
      }
      continue;
    }
    if (mutation.operation === "replace") grants.clear();
    for (const grant of mutation.grants) {
      const key = accessGrantKey(grant);
      if (mutation.operation === "remove") grants.delete(key);
      else if (!grants.has(key)) grants.set(key, grant);
    }
  }
  return [...grants.values()];
}

/** Turn a controlled editor's before/after lists into one scoped remove/add batch; unchanged grants cost no writes. */
export function createAccessGrantChanges<Permission extends string, Dimension extends string, Attribute extends string>(
  before: readonly AccessGrant<Permission, Dimension, Attribute>[],
  after: readonly AccessGrant<Permission, Dimension, Attribute>[],
): AccessGrantMutation<Permission, Dimension, Attribute>[] {
  const oldGrants = new Map<string, AccessGrant<Permission, Dimension, Attribute>>();
  const nextGrants = new Map<string, AccessGrant<Permission, Dimension, Attribute>>();
  for (const grant of before) oldGrants.set(accessGrantKey(grant), grant);
  for (const grant of after) nextGrants.set(accessGrantKey(grant), grant);
  const removed: AccessGrant<Permission, Dimension, Attribute>[] = [];
  const added: AccessGrant<Permission, Dimension, Attribute>[] = [];
  for (const [key, grant] of oldGrants) if (!nextGrants.has(key)) removed.push(grant);
  for (const [key, grant] of nextGrants) if (!oldGrants.has(key)) added.push(grant);
  const changes: AccessGrantMutation<Permission, Dimension, Attribute>[] = [];
  if (removed.length) changes.push({ operation: "remove", grants: removed });
  if (added.length) changes.push({ operation: "add", grants: added });
  return changes;
}

/** Narrow an unknown JSON object without introducing a schema/runtime dependency. */
function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

/** Parse one untrusted grant against the application catalog before it can reach the durable source. */
function parseGrant<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
>(
  access: Access<Permission, Leaf, Dimension, Attribute>,
  input: unknown,
): AccessGrant<Permission, Dimension, Attribute> {
  const value = record(input, "grant");
  if (typeof value.permission !== "string" || !access.catalog.isPermission(value.permission)) {
    throw new Error("grant.permission is not an assignable catalog permission");
  }
  const permission = value.permission;
  if (value.scope === undefined) return { permission };
  const scopeInput = record(value.scope, "grant.scope");
  const supported = access.catalog.supportedScopeDimensions(permission);
  const scope: Partial<Record<Dimension, AccessScopeSource<Attribute>>> = {};
  for (const rawDimension of Object.keys(scopeInput)) {
    if (!supported.has(rawDimension as Dimension)) {
      throw new Error(`grant.scope uses unsupported dimension ${rawDimension}`);
    }
    const dimension = rawDimension as Dimension;
    const rawConstraint = record(scopeInput[rawDimension], `grant.scope.${rawDimension}`);
    if (rawConstraint.kind === "ids") {
      if (!Array.isArray(rawConstraint.ids)) {
        throw new Error(`grant.scope.${rawDimension}.ids must be an array`);
      }
      const ids: string[] = [];
      for (const id of rawConstraint.ids) {
        if (typeof id !== "string" || !id) {
          throw new Error(`grant.scope.${rawDimension}.ids must contain non-empty strings`);
        }
        ids.push(id);
      }
      scope[dimension] = { kind: "ids", ids };
      continue;
    }
    if (
      rawConstraint.kind !== "subject" ||
      typeof rawConstraint.attribute !== "string" ||
      !rawConstraint.attribute
    ) {
      throw new Error(`grant.scope.${rawDimension} must be ids or subject scope`);
    }
    scope[dimension] = {
      kind: "subject",
      attribute: rawConstraint.attribute as Attribute,
    };
  }
  return { permission, scope };
}

/** Parse one untrusted control read request before it reaches application storage. */
export function parseAccessControlReadRequest(input: unknown): AccessControlReadRequest {
  const request = record(input, "access control read request");
  if (typeof request.subjectId !== "string" || !request.subjectId) {
    throw new Error("subjectId must be a non-empty string");
  }
  return { subjectId: request.subjectId };
}

/** Decode one untrusted grant edit; applications reuse this when their batch also edits profile membership. */
export function parseAccessGrantMutation<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
>(
  access: Access<Permission, Leaf, Dimension, Attribute>,
  input: unknown,
): AccessGrantMutation<Permission, Dimension, Attribute> {
  const mutation = record(input, "mutation");
  if (
    mutation.operation === "add" ||
    mutation.operation === "remove" ||
    mutation.operation === "replace"
  ) {
    if (!Array.isArray(mutation.grants)) {
      throw new Error(`${mutation.operation}.grants must be an array`);
    }
    if (mutation.operation !== "replace" && mutation.grants.length === 0) {
      throw new Error(`${mutation.operation}.grants must not be empty`);
    }
    const grants: AccessGrant<Permission, Dimension, Attribute>[] = [];
    for (const grant of mutation.grants) grants.push(parseGrant(access, grant));
    return { operation: mutation.operation, grants };
  }
  if (mutation.operation === "remove-permissions") {
    if (!Array.isArray(mutation.permissions)) {
      throw new Error("remove-permissions.permissions must be an array");
    }
    if (mutation.permissions.length === 0) {
      throw new Error("remove-permissions.permissions must not be empty");
    }
    const permissions: Permission[] = [];
    for (const permission of mutation.permissions) {
      if (typeof permission !== "string" || !access.catalog.isPermission(permission)) {
        throw new Error("remove-permissions contains an unknown permission");
      }
      permissions.push(permission);
    }
    return { operation: "remove-permissions", permissions };
  }
  throw new Error("Unknown access grant mutation operation");
}

/** Limits chosen by a transport host, not by the authorization evaluator. */
export type AccessMutationDecodeOptions = {
  /** Reject larger batches before decoding their entries. Omitted leaves the transport's request-size limit in charge. */
  maximumMutations?: number;
};

/** Decode the shared revision/batch envelope once; the application supplies only its extra operation decoder. */
export function parseAccessControlMutationRequest<Mutation>(
  input: unknown,
  parseMutation: (input: unknown) => Mutation,
  options: AccessMutationDecodeOptions = {},
): AccessControlMutationRequest<Mutation> {
  const request = record(input, "access control mutation request");
  if (typeof request.subjectId !== "string" || !request.subjectId) {
    throw new Error("subjectId must be a non-empty string");
  }
  if (typeof request.expectedRevision !== "string" || !request.expectedRevision) {
    throw new Error("expectedRevision must be a non-empty string");
  }
  if (!Array.isArray(request.mutations) || request.mutations.length === 0) {
    throw new Error("mutations must be a non-empty array");
  }
  if (options.maximumMutations !== undefined && request.mutations.length > options.maximumMutations) {
    throw new Error("Too many access mutations in one request");
  }
  const mutations: Mutation[] = [];
  for (const mutation of request.mutations) mutations.push(parseMutation(mutation));
  return { subjectId: request.subjectId, expectedRevision: request.expectedRevision, mutations };
}

/** Decode the standard grant-only batch using the same envelope as application-extended control wires. */
export function parseAccessGrantMutationRequest<Permission extends string, Leaf extends Permission, Dimension extends string, Attribute extends string>(
  access: Access<Permission, Leaf, Dimension, Attribute>,
  input: unknown,
): AccessControlMutationRequest<AccessGrantMutation<Permission, Dimension, Attribute>> {
  return parseAccessControlMutationRequest(input, mutation => parseAccessGrantMutation(access, mutation));
}

/** Create a server-side grant mutation service over any versioned application authority source. */
export function createAccessGrantControlService<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
>(options: {
  /** Access model used for wire validation and snapshot publication. */
  access: Access<Permission, Leaf, Dimension, Attribute>;
  /** Existing safe source publication facade. */
  control: AccessControlPlane<
    Source,
    EffectiveAccessSnapshot<Leaf, Dimension, Attribute>
  >;
  /** App mapping that locates direct grants inside its assignment/profile/role source. */
  source: AccessGrantSourceAdapter<Source, Permission, Dimension, Attribute>;
}): AccessGrantControlService<Permission, Dimension, Attribute> {
  return {
    async read(input) {
      const request = parseAccessControlReadRequest(input);
      const current = await options.control.read(request.subjectId);
      return {
        revision: current.revision,
        grants: options.source.grants(current.source),
      };
    },
    async mutate(input) {
      const request = parseAccessGrantMutationRequest(options.access, input);
      const current = await options.control.read(request.subjectId);
      if (current.revision !== request.expectedRevision) {
        throw new Error("Access source changed since this edit loaded");
      }
      const grants = applyAccessGrantMutations(
        options.source.grants(current.source),
        request.mutations,
      );
      const published = await options.control.replace({
        subjectId: request.subjectId,
        expectedRevision: request.expectedRevision,
        source: options.source.withGrants(current.source, grants),
      });
      return {
        revision: published.revision,
        grants,
      };
    },
  };
}

/** Create a control plane and direct-grant mutation service together for the common backend setup. */
export function createAccessGrantControlPlane<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
  Attribute extends string,
  Source,
>(options: AccessControlPlaneOptions<Permission, Leaf, Dimension, Attribute, Source> & {
  /** Mapping that reads/replaces direct grants inside the application authority source. */
  source: AccessGrantSourceAdapter<Source, Permission, Dimension, Attribute>;
}) {
  const control = createAccessControlPlane(options);
  const grants = createAccessGrantControlService({
    access: options.access,
    control,
    source: options.source,
  });
  return Object.freeze({ ...control, grants });
}

/** Normalize one-or-many client helper input without changing the wire representation. */
function values<Value>(input: AccessOneOrMany<Value>): readonly Value[] {
  return Array.isArray(input) ? input as readonly Value[] : [input as Value];
}

/** Create the recommended frontend grant editor over any application transport. */
export function createAccessGrantControlClient<
  Permission extends string,
  Dimension extends string,
  Attribute extends string = string,
  ExtraMutation = never,
  State extends AccessGrantControlState<Permission, Dimension, Attribute> = AccessGrantControlState<Permission, Dimension, Attribute>,
>(options: {
  /** BYO wire adapter; Parse Cloud, REST, RPC, IPC, and tests all implement the same tiny method. */
  transport: AccessGrantControlTransport<Permission, Dimension, Attribute, ExtraMutation, State>;
}): AccessGrantControlClient<Permission, Dimension, Attribute, ExtraMutation, State> {
  /** Send one already-normalized control request through the application transport. */
  function send(
    request: AccessControlMutationRequest<AccessGrantMutation<Permission, Dimension, Attribute> | ExtraMutation>,
    signal?: AbortSignal,
  ) {
    return options.transport.mutate(request, signal);
  }

  return {
    read(args) {
      return options.transport.read({ subjectId: args.subjectId }, args.signal);
    },
    mutate: send,
    add(args) {
      return send({
        subjectId: args.subjectId,
        expectedRevision: args.expectedRevision,
        mutations: [{ operation: "add", grants: values(args.values) }],
      }, args.signal);
    },
    remove(args) {
      return send({
        subjectId: args.subjectId,
        expectedRevision: args.expectedRevision,
        mutations: [{ operation: "remove", grants: values(args.values) }],
      }, args.signal);
    },
    removePermissions(args) {
      return send({
        subjectId: args.subjectId,
        expectedRevision: args.expectedRevision,
        mutations: [{ operation: "remove-permissions", permissions: values(args.values) }],
      }, args.signal);
    },
    replace(args) {
      return send({
        subjectId: args.subjectId,
        expectedRevision: args.expectedRevision,
        mutations: [{ operation: "replace", grants: args.grants }],
      }, args.signal);
    },
  };
}

export {
  createAccessControlPlane,
  createAccessPublicationControlPlane,
  type AccessControlPlane,
  type AccessControlPlaneOptions,
  type AccessPublicationControlPlaneOptions,
};

export * from "./relationship-control.js";
