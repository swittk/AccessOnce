import type {
  AccessPrincipal,
  AccessRelationshipMutation,
  AccessRelationshipSubjectsPage,
  AccessRelationshipSubjectsRequest,
} from "./relationship.js";

export type {
  AccessPrincipal,
  AccessRelationshipMutation,
  AccessRelationshipResource,
  AccessRelationshipSubjectsPage,
  AccessRelationshipSubjectsRequest,
} from "./relationship.js";

/** Exact mutation batch carried by a relationship-control transport. */
export type AccessRelationshipMutationRequest = {
  /** Ordered add/remove/visibility changes applied by the backend as one logical edit. */
  mutations: readonly AccessRelationshipMutation[];
};

/** Transport used by frontend/admin code to inspect and mutate one resource ACL without choosing HTTP/RPC/IPC. */
export type AccessRelationshipControlTransport = {
  /** Read one bounded page of explicit principals for an object relation. */
  listSubjects(
    request: AccessRelationshipSubjectsRequest,
    signal?: AbortSignal
  ): Promise<AccessRelationshipSubjectsPage>;
  /** Apply exact add/remove set mutations; implementations should make retries idempotent. */
  mutate(
    request: AccessRelationshipMutationRequest,
    signal?: AbortSignal
  ): Promise<void>;
};

/** One-or-many principal convenience accepted by relationship editor helpers. */
export type AccessRelationshipPrincipalInput =
  | AccessPrincipal
  | readonly AccessPrincipal[];

/** Arguments shared by the add/remove editor conveniences. */
export type AccessRelationshipControlChangeArgs = {
  /** Resource whose relation is being edited. */
  resource: AccessRelationshipMutation["resource"];
  /** Relation being edited, for example reader or editor. */
  relation: string;
  /** One principal or several principals changed in the same transport call. */
  principals: AccessRelationshipPrincipalInput;
  /** Optional transport cancellation signal. */
  signal?: AbortSignal;
};

/** Transport-neutral frontend/admin client for explicit object ACL membership. */
export type AccessRelationshipControlClient = {
  /** Read explicit principals for one resource relation. */
  listSubjects(
    request: AccessRelationshipSubjectsRequest,
    signal?: AbortSignal
  ): Promise<AccessRelationshipSubjectsPage>;
  /** Add one or many explicit principals to one resource relation. */
  add(args: AccessRelationshipControlChangeArgs): Promise<void>;
  /** Remove one or many explicit principals from one resource relation. */
  remove(args: AccessRelationshipControlChangeArgs): Promise<void>;
  /** Toggle whether this relation is open without explicit principal membership. */
  setUnrestricted(args: {
    /** Resource whose relation policy is changing. */
    resource: AccessRelationshipMutation["resource"];
    /** Relation whose policy is changing. */
    relation: string;
    /** True removes the extra relationship restriction; false requires the relation. */
    unrestricted: boolean;
    /** Optional transport cancellation signal. */
    signal?: AbortSignal;
  }): Promise<void>;
  /** Send an already-composed exact mutation batch. */
  mutate(
    mutations: readonly AccessRelationshipMutation[],
    signal?: AbortSignal
  ): Promise<void>;
};

/** Create the small frontend/admin ACL client over any application transport. */
export function createAccessRelationshipControlClient(
  transport: AccessRelationshipControlTransport
): AccessRelationshipControlClient {
  return {
    listSubjects(request, signal) {
      return transport.listSubjects(request, signal);
    },
    add(args) {
      const principals = Array.isArray(args.principals)
        ? args.principals
        : [args.principals];
      const mutations: AccessRelationshipMutation[] = [];
      for (const principal of principals) {
        mutations.push({
          operation: "add",
          principal,
          resource: args.resource,
          relation: args.relation,
        });
      }
      return transport.mutate({ mutations }, args.signal);
    },
    remove(args) {
      const principals = Array.isArray(args.principals)
        ? args.principals
        : [args.principals];
      const mutations: AccessRelationshipMutation[] = [];
      for (const principal of principals) {
        mutations.push({
          operation: "remove",
          principal,
          resource: args.resource,
          relation: args.relation,
        });
      }
      return transport.mutate({ mutations }, args.signal);
    },
    setUnrestricted(args) {
      return transport.mutate(
        {
          mutations: [
            {
              operation: "set-unrestricted",
              resource: args.resource,
              relation: args.relation,
              unrestricted: args.unrestricted,
            },
          ],
        },
        args.signal
      );
    },
    mutate(mutations, signal) {
      return transport.mutate({ mutations }, signal);
    },
  };
}

/** Complete object-centered ACL editor state after all explicit-principal pages have been loaded. */
export type AccessRelationshipEditorState = {
  /** True when this relation imposes no extra principal restriction. */
  unrestricted: boolean;
  /** Complete explicit principal set represented by the editor. */
  principals: readonly AccessPrincipal[];
};

/** Stable identity for exact explicit-principal set comparison. */
function relationshipPrincipalKey(principal: AccessPrincipal): string {
  return `${principal.type}\u0000${principal.id}`;
}

/**
 * Convert one controlled ACL editor before/after state into minimal exact mutations.
 * Principal changes are emitted before the visibility switch so a non-transactional adapter can restrict only
 * after its intended readers have been installed; proper stores should still apply the whole batch atomically.
 */
export function createAccessRelationshipChanges(args: {
  /** Resource whose one relation is being edited. */
  resource: AccessRelationshipMutation["resource"];
  /** Relation whose membership is being edited. */
  relation: string;
  /** Complete state loaded by the editor. */
  before: AccessRelationshipEditorState;
  /** Complete controlled state the user intends to save. */
  after: AccessRelationshipEditorState;
}): AccessRelationshipMutation[] {
  const before = new Map<string, AccessPrincipal>();
  const after = new Map<string, AccessPrincipal>();
  for (const principal of args.before.principals)
    before.set(relationshipPrincipalKey(principal), principal);
  for (const principal of args.after.principals)
    after.set(relationshipPrincipalKey(principal), principal);
  const mutations: AccessRelationshipMutation[] = [];
  for (const [key, principal] of before) {
    if (!after.has(key))
      mutations.push({
        operation: "remove",
        principal,
        resource: args.resource,
        relation: args.relation,
      });
  }
  for (const [key, principal] of after) {
    if (!before.has(key))
      mutations.push({
        operation: "add",
        principal,
        resource: args.resource,
        relation: args.relation,
      });
  }
  if (args.before.unrestricted !== args.after.unrestricted) {
    mutations.push({
      operation: "set-unrestricted",
      resource: args.resource,
      relation: args.relation,
      unrestricted: args.after.unrestricted,
    });
  }
  return mutations;
}

/** Bounds for untrusted relationship-control wire decoding. */
export type AccessRelationshipDecodeOptions = {
  /** Maximum mutations accepted in one request; omitted leaves transport size limits in charge. */
  maximumMutations?: number;
  /** Maximum requested ACL page size; defaults to 256. */
  maximumSubjectsPageSize?: number;
};

/** Read a required non-empty wire string. */
function relationshipWireString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim())
    throw new Error(`${label} must be a non-empty string`);
  return value;
}

/** Read one principal/resource identity from untrusted relationship-control JSON. */
function relationshipWireIdentity(
  value: unknown,
  label: string
): AccessPrincipal {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  const record = value as Record<string, unknown>;
  return {
    type: relationshipWireString(record.type, `${label}.type`),
    id: relationshipWireString(record.id, `${label}.id`),
  };
}

/** Decode an untrusted object-centered ACL read request without choosing application resource/relation vocabularies. */
export function parseAccessRelationshipSubjectsRequest(
  input: unknown,
  options: AccessRelationshipDecodeOptions = {}
): AccessRelationshipSubjectsRequest {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new Error("relationship subjects request must be an object");
  const record = input as Record<string, unknown>;
  const resource = relationshipWireIdentity(record.resource, "resource");
  const relation = relationshipWireString(record.relation, "relation");
  const cursor =
    record.cursor === undefined
      ? undefined
      : relationshipWireString(record.cursor, "cursor");
  const maximum = options.maximumSubjectsPageSize ?? 256;
  let limit: number | undefined;
  if (record.limit !== undefined) {
    if (
      !Number.isInteger(record.limit) ||
      Number(record.limit) < 1 ||
      Number(record.limit) > maximum
    ) {
      throw new Error(`limit must be an integer between 1 and ${maximum}`);
    }
    limit = Number(record.limit);
  }
  return {
    resource,
    relation,
    ...(cursor === undefined ? {} : { cursor }),
    ...(limit === undefined ? {} : { limit }),
  };
}

/** Decode one untrusted relationship mutation. Application adapters still validate supported principal/resource/relation names. */
export function parseAccessRelationshipMutation(
  input: unknown
): AccessRelationshipMutation {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new Error("relationship mutation must be an object");
  const record = input as Record<string, unknown>;
  const resource = relationshipWireIdentity(record.resource, "resource");
  const relation = relationshipWireString(record.relation, "relation");
  if (record.operation === "set-unrestricted") {
    if (typeof record.unrestricted !== "boolean")
      throw new Error("set-unrestricted.unrestricted must be boolean");
    return {
      operation: "set-unrestricted",
      resource,
      relation,
      unrestricted: record.unrestricted,
    };
  }
  if (record.operation !== "add" && record.operation !== "remove")
    throw new Error("unknown relationship mutation operation");
  return {
    operation: record.operation,
    principal: relationshipWireIdentity(record.principal, "principal"),
    resource,
    relation,
  };
}

/** Decode one bounded relationship mutation batch before application storage is touched. */
export function parseAccessRelationshipMutationRequest(
  input: unknown,
  options: AccessRelationshipDecodeOptions = {}
): AccessRelationshipMutationRequest {
  if (!input || typeof input !== "object" || Array.isArray(input))
    throw new Error("relationship mutation request must be an object");
  const record = input as Record<string, unknown>;
  if (!Array.isArray(record.mutations) || record.mutations.length === 0)
    throw new Error("mutations must be a non-empty array");
  if (
    options.maximumMutations !== undefined &&
    record.mutations.length > options.maximumMutations
  ) {
    throw new Error("too many relationship mutations in one request");
  }
  const mutations: AccessRelationshipMutation[] = [];
  for (const mutation of record.mutations)
    mutations.push(parseAccessRelationshipMutation(mutation));
  return { mutations };
}
