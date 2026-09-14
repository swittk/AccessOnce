import { describe, expect, it } from "vitest";
import {
  createHierarchicalAccess,
  createAccessRequestService,
  type AccessGrant,
  type AccessRequestCreate,
  type AccessRequestRecord,
  type AccessRequestStore,
} from "../src/index.js";

type Permission = "*" | "record" | "record.read" | "record.write" | "billing.read";
type Leaf = "record.read" | "record.write" | "billing.read";
type Dimension = "location" | "resource" | "assignee";
type Attribute = "assigneeId" | "backupAssigneeId";
type Grant = AccessGrant<Permission, Dimension, Attribute>;

/** Shared hierarchical catalog exercising parents, implications, correlated scopes, and subject-relative scopes. */
const access = createHierarchicalAccess<Permission, Leaf, Dimension, Attribute>({
  catalogId: "request-test",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["*", "record", "record.read", "record.write", "billing.read"],
  leaves: ["record.read", "record.write", "billing.read"],
  wildcard: "*",
  scopeDimensions: {
    "record.read": ["location", "resource"],
    "record.write": ["location", "resource"],
    "billing.read": ["assignee"],
  },
  implies: { "record.write": ["record.read"] },
});

/** Build one fixed-id source scope tersely for policy tests. */
function ids(...values: string[]) {
  return { kind: "ids" as const, ids: values };
}

describe("access request policy", () => {
  it("accepts narrower grants and assignable parents while proving implications through the real catalog", () => {
    const policy = access.requestPolicy({
      policyId: "clinical",
      ceilings: [
        {
          permission: "record",
          scope: { location: ids("a", "b"), resource: ids("note", "image") },
        },
      ],
      approval: { kind: "policy", policyId: "clinical-approver" },
    });

    expect(policy.canRequest({
      grant: { permission: "record", scope: { location: ids("a"), resource: ids("note") } },
    })).toBe(true);
    expect(policy.canRequest({
      grant: { permission: "record.write", scope: { location: ids("a"), resource: ids("image") } },
    })).toBe(true);
    expect(policy.canRequest({ grant: { permission: "record" } })).toBe(false);
  });

  it("rejects write when only read is requestable and does not flatten correlated ceilings", () => {
    const readOnly = access.requestPolicy({
      policyId: "read-only",
      ceilings: [{ permission: "record.read" }],
      approval: { kind: "automatic" },
    });
    expect(readOnly.evaluate({ grant: { permission: "record.write" } })).toMatchObject({
      requestable: false,
      reason: "permission-not-requestable",
    });

    const correlated = access.requestPolicy({
      policyId: "correlated",
      ceilings: [
        { permission: "record.read", scope: { location: ids("a"), resource: ids("x") } },
        { permission: "record.read", scope: { location: ids("b"), resource: ids("y") } },
      ],
      approval: { kind: "automatic" },
    });
    expect(correlated.evaluate({
      grant: {
        permission: "record.read",
        scope: { location: ids("a", "b"), resource: ids("x", "y") },
      },
    })).toMatchObject({ requestable: false, reason: "scope-not-requestable" });
  });

  it("preserves subject-relative meaning instead of comparing only today's values", () => {
    const subject = { assigneeId: "u1", backupAssigneeId: "u1" };
    const relative = access.requestPolicy({
      policyId: "own-billing",
      ceilings: [
        {
          permission: "billing.read",
          scope: { assignee: { kind: "subject", attribute: "assigneeId" } },
        },
      ],
      approval: { kind: "automatic" },
    });
    expect(relative.canRequest({
      grant: { permission: "billing.read", scope: { assignee: ids("u1") } },
      subject,
    })).toBe(true);
    expect(relative.canRequest({
      grant: {
        permission: "billing.read",
        scope: { assignee: { kind: "subject", attribute: "backupAssigneeId" } },
      },
      subject,
    })).toBe(false);

    const fixed = access.requestPolicy({
      policyId: "fixed-billing",
      ceilings: [{ permission: "billing.read", scope: { assignee: ids("u1") } }],
      approval: { kind: "automatic" },
    });
    expect(fixed.canRequest({
      grant: {
        permission: "billing.read",
        scope: { assignee: { kind: "subject", attribute: "assigneeId" } },
      },
      subject,
    })).toBe(false);
  });

  it("enforces bounded validity using submitted-window count and merged duration", () => {
    const policy = access.requestPolicy({
      policyId: "temporary",
      ceilings: [{ permission: "record.read" }],
      approval: { kind: "automatic" },
      validity: { allowUnbounded: false, maximumWindows: 2, maximumDurationMs: 100 },
    });
    expect(policy.canRequest({
      grant: {
        permission: "record.read",
        validity: [
          { startsAtEpochMs: 0, endsAtEpochMs: 80 },
          { startsAtEpochMs: 50, endsAtEpochMs: 100 },
        ],
      },
    })).toBe(true);
    expect(policy.evaluate({ grant: { permission: "record.read" } })).toMatchObject({
      requestable: false,
      reason: "validity-not-requestable",
    });
    expect(policy.evaluate({
      grant: {
        permission: "record.read",
        validity: [
          { startsAtEpochMs: 0, endsAtEpochMs: 80 },
          { startsAtEpochMs: 90, endsAtEpochMs: 121 },
        ],
      },
    })).toMatchObject({ requestable: false, reason: "validity-not-requestable" });
    expect(policy.evaluate({
      grant: { permission: "record.read", validity: { startsAtEpochMs: 5, endsAtEpochMs: 5 } },
    })).toMatchObject({ requestable: false, reason: "empty-request" });
  });

  it("honors temporal ceilings in addition to policy-wide duration limits", () => {
    const policy = access.requestPolicy({
      policyId: "shift",
      ceilings: [
        {
          permission: "record.read",
          validity: { startsAtEpochMs: 100, endsAtEpochMs: 200 },
        },
      ],
      approval: { kind: "automatic" },
    });
    expect(policy.canRequest({
      grant: { permission: "record.read", validity: { startsAtEpochMs: 120, endsAtEpochMs: 180 } },
    })).toBe(true);
    expect(policy.evaluate({
      grant: { permission: "record.read", validity: { startsAtEpochMs: 90, endsAtEpochMs: 180 } },
    })).toMatchObject({ requestable: false, reason: "validity-not-requestable" });
  });

  it("rejects malformed policy definitions before they can become request ceilings", () => {
    expect(() => access.requestPolicy({
      policyId: "",
      ceilings: [{ permission: "record.read" }],
      approval: { kind: "automatic" },
    })).toThrow(/policyId/i);
    expect(() => access.requestPolicy({
      policyId: "bad-scope",
      ceilings: [{
        permission: "billing.read",
        scope: { location: ids("a") },
      }],
      approval: { kind: "automatic" },
    })).toThrow(/unsupported scope dimension/i);
    expect(() => access.requestPolicy({
      policyId: "bad-duration",
      ceilings: [{ permission: "record.read" }],
      approval: { kind: "automatic" },
      validity: { maximumDurationMs: 0 },
    })).toThrow(/maximumDurationMs/i);
  });
});

type Route = { queue: string };
type RequestRecord = AccessRequestRecord<Permission, Dimension, Attribute, Route>;

/** Minimal revisioned in-memory request store implementing the durable adapter contract. */
function createStore(): AccessRequestStore<Permission, Dimension, Attribute, Route> & {
  records: Map<string, RequestRecord>;
} {
  const records = new Map<string, RequestRecord>();
  const byIdempotency = new Map<string, string>();
  let nextId = 1;
  return {
    records,
    async withRequestLock(_requestId, work) {
      return work();
    },
    async read(requestId) {
      return records.get(requestId);
    },
    async readByIdempotency(requesterId, idempotencyKey) {
      const requestId = byIdempotency.get(`${requesterId}:${idempotencyKey}`);
      return requestId === undefined ? undefined : records.get(requestId);
    },
    async createOrRead(input: AccessRequestCreate<Permission, Dimension, Attribute, Route>) {
      const key = `${input.requesterId}:${input.idempotencyKey}`;
      const existingId = byIdempotency.get(key);
      if (existingId) return { created: false, request: records.get(existingId)! };
      const request: RequestRecord = { ...input, requestId: `r${nextId++}`, revision: "1" };
      records.set(request.requestId, request);
      byIdempotency.set(key, request.requestId);
      return { created: true, request };
    },
    async compareAndSet(requestId, expectedRevision, next) {
      const current = records.get(requestId);
      if (!current || current.revision !== expectedRevision) throw new Error("request revision mismatch");
      const request: RequestRecord = {
        ...next,
        requestId,
        revision: String(Number(current.revision) + 1),
      };
      records.set(requestId, request);
      return request;
    },
  };
}

/** Common manual policy used by the durable workflow tests. */
function manualPolicy() {
  return access.requestPolicy({
    policyId: "clinical",
    ceilings: [{ permission: "record.read", scope: { location: ids("a") } }],
    approval: { kind: "policy", policyId: "clinical-approver" },
  });
}

describe("access request service", () => {
  it("requires a resolvable route before creating a manual request", async () => {
    const store = createStore();
    const service = createAccessRequestService({
      store,
      resolvePolicy: () => ({ policy: manualPolicy() }),
      resolveApprovalRoute: () => undefined,
      authorizeTransition: () => true,
      issue: async () => {},
    });
    await expect(service.submit("u1", {
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: { permission: "record.read", scope: { location: ids("a") } },
    })).rejects.toThrow(/route|unavailable/i);
    expect(store.records.size).toBe(0);
  });

  it("rechecks current policy and approver authority before durable issuance", async () => {
    const store = createStore();
    let enabled = true;
    let approverAllowed = true;
    const issued: string[] = [];
    const service = createAccessRequestService({
      store,
      resolvePolicy: () => enabled ? { policy: manualPolicy() } : undefined,
      resolveApprovalRoute: () => ({ queue: "clinical" }),
      authorizeTransition: ({ action }) => action !== "approve" || approverAllowed,
      async issue({ issuanceKey }) {
        issued.push(issuanceKey);
      },
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: { permission: "record.read", scope: { location: ids("a") } },
    });
    expect(pending.state).toBe("pending");
    expect(pending.route).toEqual({ queue: "clinical" });

    enabled = false;
    await expect(service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
    })).rejects.toThrow(/requestable|policy/i);
    expect(issued).toEqual([]);

    enabled = true;
    approverAllowed = false;
    await expect(service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
    })).rejects.toThrow(/authorized/i);
    expect(issued).toEqual([]);
  });

  it("uses an issuing claim so crash recovery cannot mark approved before authority commits", async () => {
    const store = createStore();
    const committed = new Set<string>();
    let failAfterCommit = true;
    const service = createAccessRequestService({
      store,
      resolvePolicy: () => ({ policy: manualPolicy() }),
      resolveApprovalRoute: () => ({ queue: "clinical" }),
      authorizeTransition: () => true,
      async issue({ issuanceKey }) {
        committed.add(issuanceKey);
        if (failAfterCommit) throw new Error("simulated crash after durable authority write");
      },
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: { permission: "record.read", scope: { location: ids("a") } },
    });
    await expect(service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
    })).rejects.toThrow(/simulated crash/);
    const issuing = await service.read(pending.requestId);
    expect(issuing.state).toBe("issuing");
    expect(committed).toEqual(new Set([`access-request:${pending.requestId}`]));

    failAfterCommit = false;
    const approved = await service.recover(pending.requestId);
    expect(approved.state).toBe("approved");
    expect(committed).toEqual(new Set([`access-request:${pending.requestId}`]));
  });

  it("makes submission and terminal action retries idempotent but rejects conflicting rewrites", async () => {
    const store = createStore();
    const service = createAccessRequestService({
      store,
      resolvePolicy: () => ({ policy: manualPolicy() }),
      resolveApprovalRoute: () => ({ queue: "clinical" }),
      authorizeTransition: () => true,
      issue: async () => {},
    });
    const input = {
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: { permission: "record.read" as const, scope: { location: ids("a") } },
    };
    const first = await service.submit("u1", input);
    expect(await service.submit("u1", input)).toEqual(first);
    await expect(service.submit("u1", {
      ...input,
      grant: { permission: "record.read", scope: { location: ids("outside") } },
    })).rejects.toThrow(/idempotency/i);

    const denied = await service.transition("boss", {
      requestId: first.requestId,
      expectedRevision: first.revision,
      action: "deny",
    });
    expect(denied.state).toBe("denied");
    expect(await service.transition("boss", {
      requestId: first.requestId,
      expectedRevision: first.revision,
      action: "deny",
    })).toEqual(denied);
    await expect(service.transition("boss", {
      requestId: first.requestId,
      expectedRevision: first.revision,
      action: "approve",
    })).rejects.toThrow(/terminal|conflict/i);
  });

  it("rechecks automatic policy immediately before claiming authority issuance", async () => {
    const store = createStore();
    const automatic = access.requestPolicy({
      policyId: "self-service",
      ceilings: [{ permission: "billing.read", scope: { assignee: ids("u1") } }],
      approval: { kind: "automatic" },
    });
    let resolutions = 0;
    const issued: string[] = [];
    const service = createAccessRequestService({
      store,
      resolvePolicy: () => {
        resolutions += 1;
        return resolutions === 1 ? { policy: automatic } : undefined;
      },
      authorizeTransition: () => true,
      async issue({ issuanceKey }) {
        issued.push(issuanceKey);
      },
    });
    await expect(service.submit("u1", {
      idempotencyKey: "auto-stale",
      subjectId: "u1",
      policyId: "self-service",
      grant: { permission: "billing.read", scope: { assignee: ids("u1") } },
    })).rejects.toThrow(/currently applicable|policy/i);
    expect(issued).toEqual([]);
    expect([...store.records.values()][0]?.state).toBe("pending");
  });

  it("commits automatic policies immediately through the same recoverable issuance protocol", async () => {
    const store = createStore();
    const automatic = access.requestPolicy({
      policyId: "self-service",
      ceilings: [{ permission: "billing.read", scope: { assignee: ids("u1") } }],
      approval: { kind: "automatic" },
    });
    const issued: string[] = [];
    const service = createAccessRequestService({
      store,
      resolvePolicy: () => ({ policy: automatic }),
      authorizeTransition: () => true,
      async issue({ issuanceKey }) {
        issued.push(issuanceKey);
      },
    });
    const approved = await service.submit("u1", {
      idempotencyKey: "auto-1",
      subjectId: "u1",
      policyId: "self-service",
      grant: { permission: "billing.read", scope: { assignee: ids("u1") } },
    });
    expect(approved.state).toBe("approved");
    expect(issued).toEqual([`access-request:${approved.requestId}`]);
  });

  it("expires only pending requests and keeps expiry retries idempotent", async () => {
    const store = createStore();
    const service = createAccessRequestService({
      store,
      resolvePolicy: () => ({ policy: manualPolicy() }),
      resolveApprovalRoute: () => ({ queue: "clinical" }),
      authorizeTransition: () => true,
      issue: async () => {},
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "expiry-1",
      subjectId: "u1",
      policyId: "clinical",
      grant: { permission: "record.read", scope: { location: ids("a") } },
    });
    const expired = await service.expire(pending.requestId, pending.revision);
    expect(expired.state).toBe("expired");
    expect(await service.expire(pending.requestId, pending.revision)).toEqual(expired);
    await expect(service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
    })).rejects.toThrow(/conflicting terminal/i);
  });
});
