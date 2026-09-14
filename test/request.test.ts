import { describe, expect, it } from "vitest";
import {
  createHierarchicalAccess,
  createAccessRequestService,
  type AccessGrant,
  type AccessRequestAuthority,
  type AccessRequestCreate,
  type AccessRequestRecord,
  type AccessRequestRuleDefinition,
  type AccessRequestStore,
} from "../src/index.js";

type Permission = "*" | "record" | "record.read" | "record.write" | "billing.read";
type Leaf = "record.read" | "record.write" | "billing.read";
type Dimension = "location" | "resource" | "assignee";
type Attribute = "assigneeId" | "backupAssigneeId";
type Grant = AccessGrant<Permission, Dimension, Attribute>;
type Authority = AccessRequestAuthority<Permission, Dimension, Attribute>;

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

/** Build one fixed-id source scope tersely for request-rule tests. */
function ids(...values: string[]) {
  return { kind: "ids" as const, ids: values };
}

/** Wrap one ordinary AccessGrant as requested actor authority. */
function grant(grantValue: Grant): Authority {
  return { kind: "grant", grant: grantValue };
}

/** Build one exact object relationship authority. */
function relationship(
  id: string,
  relation = "reader",
  validity?: { startsAtEpochMs?: number; endsAtEpochMs?: number },
): Authority {
  return {
    kind: "relationship",
    resource: { type: "document", id },
    relation,
    ...(validity === undefined ? {} : { validity }),
  };
}

describe("access request rules", () => {
  it("uses the normal grant language for parents, implications and narrowing", () => {
    const rule = access.requestRule({
      ruleId: "restricted",
      allow: {
        kind: "grant",
        grants: [{
          permission: "record",
          scope: { location: ids("a", "b"), resource: ids("note", "image") },
        }],
      },
      approval: { kind: "policy", policyId: "record-approver" },
    });

    expect(rule.canRequest({
      authority: grant({ permission: "record", scope: { location: ids("a"), resource: ids("note") } }),
    })).toBe(true);
    expect(rule.canRequest({
      authority: grant({ permission: "record.write", scope: { location: ids("a"), resource: ids("image") } }),
    })).toBe(true);
    expect(rule.canRequest({ authority: grant({ permission: "record" }) })).toBe(false);
  });

  it("rejects broader grant authority and preserves correlated scope clauses", () => {
    const readOnly = access.requestRule({
      ruleId: "read-only",
      allow: { kind: "grant", grants: [{ permission: "record.read" }] },
      approval: { kind: "automatic" },
    });
    expect(readOnly.evaluate({ authority: grant({ permission: "record.write" }) })).toMatchObject({
      requestable: false,
      reason: "permission-not-requestable",
    });

    const correlated = access.requestRule({
      ruleId: "correlated",
      allow: {
        kind: "grant",
        grants: [
          { permission: "record.read", scope: { location: ids("a"), resource: ids("x") } },
          { permission: "record.read", scope: { location: ids("b"), resource: ids("y") } },
        ],
      },
      approval: { kind: "automatic" },
    });
    expect(correlated.evaluate({
      authority: grant({
        permission: "record.read",
        scope: { location: ids("a", "b"), resource: ids("x", "y") },
      }),
    })).toMatchObject({ requestable: false, reason: "scope-not-requestable" });
  });

  it("preserves subject-relative meaning instead of comparing only current values", () => {
    const subject = { assigneeId: "u1", backupAssigneeId: "u1" };
    const relative = access.requestRule({
      ruleId: "own-billing",
      allow: {
        kind: "grant",
        grants: [{
          permission: "billing.read",
          scope: { assignee: { kind: "subject", attribute: "assigneeId" } },
        }],
      },
      approval: { kind: "automatic" },
    });
    expect(relative.canRequest({
      authority: grant({ permission: "billing.read", scope: { assignee: ids("u1") } }),
      subject,
    })).toBe(true);
    expect(relative.canRequest({
      authority: grant({
        permission: "billing.read",
        scope: { assignee: { kind: "subject", attribute: "backupAssigneeId" } },
      }),
      subject,
    })).toBe(false);
  });

  it("enforces bounded validity and temporal grant ceilings", () => {
    const rule = access.requestRule({
      ruleId: "temporary",
      allow: {
        kind: "grant",
        grants: [{
          permission: "record.read",
          validity: { startsAtEpochMs: 100, endsAtEpochMs: 300 },
        }],
      },
      approval: { kind: "automatic" },
      validity: { allowUnbounded: false, maximumWindows: 2, maximumDurationMs: 100 },
    });
    expect(rule.canRequest({
      authority: grant({
        permission: "record.read",
        validity: [
          { startsAtEpochMs: 120, endsAtEpochMs: 180 },
          { startsAtEpochMs: 160, endsAtEpochMs: 200 },
        ],
      }),
    })).toBe(true);
    expect(rule.evaluate({ authority: grant({ permission: "record.read" }) })).toMatchObject({
      requestable: false,
      reason: "validity-not-requestable",
    });
    expect(rule.evaluate({
      authority: grant({ permission: "record.read", validity: { startsAtEpochMs: 90, endsAtEpochMs: 150 } }),
    })).toMatchObject({ requestable: false, reason: "validity-not-requestable" });
  });

  it("supports exact object relationship requests without actor-snapshot object ids", () => {
    const rule = access.requestRule({
      ruleId: "document-access",
      allow: {
        kind: "relationship",
        resourceTypes: ["document", "encounter"],
        relations: ["reader", "editor"],
      },
      approval: { kind: "policy", policyId: "restricted-record-access" },
      validity: { allowUnbounded: false, maximumDurationMs: 8 * 60 * 60 * 1000 },
    });
    expect(rule.canRequest({
      authority: relationship("doc-1", "reader", { startsAtEpochMs: 100, endsAtEpochMs: 200 }),
    })).toBe(true);
    expect(rule.evaluate({
      authority: {
        kind: "relationship",
        resource: { type: "secret-other-kind", id: "x" },
        relation: "reader",
        validity: { startsAtEpochMs: 100, endsAtEpochMs: 200 },
      },
    })).toMatchObject({ requestable: false, reason: "authority-not-requestable" });
    expect(rule.evaluate({
      authority: relationship("doc-1", "owner", { startsAtEpochMs: 100, endsAtEpochMs: 200 }),
    })).toMatchObject({ requestable: false, reason: "authority-not-requestable" });
  });

  it("keeps compiled request-rule authority stable if the caller later mutates its definition", () => {
    const definition: AccessRequestRuleDefinition<Permission, Dimension, Attribute> = {
      ruleId: "stable-compiled-rule",
      allow: { kind: "grant", grants: [{ permission: "record.read" }] },
      approval: { kind: "automatic" },
    };
    const rule = access.requestRule(definition);
    definition.allow = { kind: "relationship", resourceTypes: ["document"], relations: ["reader"] };

    expect(rule.canRequest({ authority: grant({ permission: "record.read" }) })).toBe(true);
    expect(() => rule.evaluate({
      authority: relationship("doc-1", "reader"),
    })).not.toThrow();
    expect(rule.canRequest({ authority: relationship("doc-1", "reader") })).toBe(false);
  });

  it("rejects malformed rule definitions", () => {
    expect(() => access.requestRule({
      ruleId: "",
      allow: { kind: "grant", grants: [{ permission: "record.read" }] },
      approval: { kind: "automatic" },
    })).toThrow(/ruleId/i);
    expect(() => access.requestRule({
      ruleId: "bad-scope",
      allow: {
        kind: "grant",
        grants: [{ permission: "billing.read", scope: { location: ids("a") } }],
      },
      approval: { kind: "automatic" },
    })).toThrow(/unsupported scope dimension/i);
    expect(() => access.requestRule({
      ruleId: "bad-relationship",
      allow: { kind: "relationship", resourceTypes: [], relations: ["reader"] },
      approval: { kind: "automatic" },
    })).toThrow(/resourceTypes/i);
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

/** Common manual actor-grant rule used by durable workflow tests. */
function manualGrantRule() {
  return access.requestRule({
    ruleId: "restricted",
    allow: {
      kind: "grant",
      grants: [{
        permission: "record.read",
        scope: { location: ids("a", "b"), resource: ids("note", "image") },
        validity: { startsAtEpochMs: 0, endsAtEpochMs: 1000 },
      }],
    },
    approval: { kind: "policy", policyId: "record-approver" },
  });
}

/** Common object relationship rule representing the native-ACL use case. */
function documentRule() {
  return access.requestRule({
    ruleId: "document-access",
    allow: { kind: "relationship", resourceTypes: ["document"], relations: ["reader", "editor"] },
    approval: { kind: "policy", policyId: "record-approver" },
    validity: { allowUnbounded: false, maximumDurationMs: 1000 },
  });
}

describe("access request service", () => {
  it("supports justified automatic timed access with durable audit timestamps", async () => {
    const store = createStore();
    let now = 10_000;
    const rule = access.requestRule({
      ruleId: "restricted-record",
      allow: { kind: "relationship", resourceTypes: ["document"], relations: ["reader"] },
      approval: { kind: "automatic" },
      reasonRequired: true,
      validity: { allowUnbounded: false, maximumWindows: 1, maximumDurationMs: 30 * 60 * 1000 },
    });
    const issued: Authority[] = [];
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      nowEpochMs: () => now,
      resolveRule: () => ({ rule }),
      authorizeTransition: () => true,
      async issue({ authority }) {
        issued.push(authority);
      },
    });
    const input = {
      idempotencyKey: "justified-1",
      subjectId: "u1",
      ruleId: "restricted-record",
      authority: relationship("r1", "reader", {
        startsAtEpochMs: 10_000,
        endsAtEpochMs: 10_000 + 15 * 60 * 1000,
      }),
    };
    await expect(service.submit("u1", input)).rejects.toThrow(/reason/i);
    expect(store.records.size).toBe(0);

    now = 11_000;
    const approved = await service.submit("u1", { ...input, reason: "Direct care review" });
    expect(approved.state).toBe("approved");
    expect(approved.reason).toBe("Direct care review");
    expect(approved.submittedAtEpochMs).toBe(11_000);
    expect(approved.decision).toMatchObject({
      action: "approve",
      decidedAtEpochMs: 11_000,
      authority: input.authority,
    });
    expect(issued).toEqual([input.authority]);
  });
  it("requires a resolvable route before creating a manual request", async () => {
    const store = createStore();
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => ({ rule: manualGrantRule() }),
      resolveApprovalRoute: () => undefined,
      authorizeTransition: () => true,
      issue: async () => {},
    });
    await expect(service.submit("u1", {
      idempotencyKey: "k1",
      subjectId: "u1",
      ruleId: "restricted",
      authority: grant({
        permission: "record.read",
        scope: { location: ids("a"), resource: ids("note") },
        validity: { startsAtEpochMs: 0, endsAtEpochMs: 100 },
      }),
    })).rejects.toThrow(/route|unavailable/i);
    expect(store.records.size).toBe(0);
  });

  it("rechecks current rules and approver authority before issuance", async () => {
    const store = createStore();
    let enabled = true;
    let approverAllowed = true;
    const issued: Authority[] = [];
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => enabled ? { rule: manualGrantRule() } : undefined,
      resolveApprovalRoute: () => ({ queue: "restricted" }),
      authorizeTransition: ({ action }) => action !== "approve" || approverAllowed,
      async issue({ authority }) {
        issued.push(authority);
      },
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "k1",
      subjectId: "u1",
      ruleId: "restricted",
      authority: grant({
        permission: "record.read",
        scope: { location: ids("a"), resource: ids("note") },
        validity: { startsAtEpochMs: 0, endsAtEpochMs: 100 },
      }),
    });
    enabled = false;
    await expect(service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
    })).rejects.toThrow(/rule|requestable/i);
    expect(issued).toEqual([]);

    enabled = true;
    approverAllowed = false;
    await expect(service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
    })).rejects.toThrow(/authorized/i);
  });

  it("lets an approver narrow actor authority but never broaden it", async () => {
    const store = createStore();
    const issued: Authority[] = [];
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => ({ rule: manualGrantRule() }),
      resolveApprovalRoute: () => ({ queue: "restricted" }),
      authorizeTransition: () => true,
      async issue({ authority }) {
        issued.push(authority);
      },
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "narrow-grant",
      subjectId: "u1",
      ruleId: "restricted",
      authority: grant({
        permission: "record.read",
        scope: { location: ids("a", "b"), resource: ids("note", "image") },
        validity: { startsAtEpochMs: 0, endsAtEpochMs: 500 },
      }),
    });
    const approvedAuthority = grant({
      permission: "record.read",
      scope: { location: ids("a"), resource: ids("note") },
      validity: { startsAtEpochMs: 50, endsAtEpochMs: 100 },
    });
    const approved = await service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
      authority: approvedAuthority,
      reason: "Only through end of shift",
    });
    expect(approved.state).toBe("approved");
    expect(approved.decision).toMatchObject({
      action: "approve",
      actorId: "boss",
      reason: "Only through end of shift",
      authority: approvedAuthority,
    });
    expect(issued).toEqual([approvedAuthority]);

    const second = await service.submit("u2", {
      idempotencyKey: "broaden-grant",
      subjectId: "u2",
      ruleId: "restricted",
      authority: grant({
        permission: "record.read",
        scope: { location: ids("a"), resource: ids("note") },
        validity: { startsAtEpochMs: 0, endsAtEpochMs: 100 },
      }),
    });
    await expect(service.transition("boss", {
      requestId: second.requestId,
      expectedRevision: second.revision,
      action: "approve",
      authority: grant({
        permission: "record.read",
        scope: { location: ids("a", "b"), resource: ids("note") },
        validity: { startsAtEpochMs: 0, endsAtEpochMs: 100 },
      }),
    })).rejects.toThrow(/broader|original request/i);
  });

  it("issues exact object relationships and lets approval only shorten their validity", async () => {
    const store = createStore();
    const issued: Authority[] = [];
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: ({ authority }) =>
        authority.kind === "relationship" && authority.resource.id === "doc-1"
          ? { rule: documentRule() }
          : undefined,
      resolveApprovalRoute: () => ({ queue: "restricted" }),
      authorizeTransition: () => true,
      async issue({ authority }) {
        issued.push(authority);
      },
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "doc-1",
      subjectId: "u1",
      ruleId: "document-access",
      authority: relationship("doc-1", "reader", { startsAtEpochMs: 100, endsAtEpochMs: 900 }),
    });
    const narrowed = relationship("doc-1", "reader", { startsAtEpochMs: 200, endsAtEpochMs: 400 });
    const approved = await service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
      authority: narrowed,
      reason: "Temporary chart review",
    });
    expect(approved.state).toBe("approved");
    expect(issued).toEqual([narrowed]);

    const other = await service.submit("u2", {
      idempotencyKey: "doc-1-2",
      subjectId: "u2",
      ruleId: "document-access",
      authority: relationship("doc-1", "reader", { startsAtEpochMs: 100, endsAtEpochMs: 300 }),
    });
    await expect(service.transition("boss", {
      requestId: other.requestId,
      expectedRevision: other.revision,
      action: "approve",
      authority: relationship("doc-2", "reader", { startsAtEpochMs: 100, endsAtEpochMs: 200 }),
    })).rejects.toThrow(/broader|original request/i);
    await expect(service.transition("boss", {
      requestId: other.requestId,
      expectedRevision: other.revision,
      action: "approve",
      authority: relationship("doc-1", "reader", { startsAtEpochMs: 50, endsAtEpochMs: 350 }),
    })).rejects.toThrow(/broader|original request/i);
  });

  it("stores decline reasons without interpreting them", async () => {
    const store = createStore();
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => ({ rule: documentRule() }),
      resolveApprovalRoute: () => ({ queue: "restricted" }),
      authorizeTransition: () => true,
      issue: async () => {},
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "deny-reason",
      subjectId: "u1",
      ruleId: "document-access",
      authority: relationship("doc-1", "reader", { startsAtEpochMs: 0, endsAtEpochMs: 100 }),
    });
    const denied = await service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "deny",
      reason: "Use the normal consultation workflow",
    });
    expect(denied).toMatchObject({
      state: "denied",
      decision: {
        action: "deny",
        actorId: "boss",
        reason: "Use the normal consultation workflow",
      },
    });
  });

  it("uses an issuing claim so crash recovery cannot mark approved before authority commits", async () => {
    const store = createStore();
    const committed = new Set<string>();
    let failAfterCommit = true;
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => ({ rule: documentRule() }),
      resolveApprovalRoute: () => ({ queue: "restricted" }),
      authorizeTransition: () => true,
      async issue({ issuanceKey }) {
        committed.add(issuanceKey);
        if (failAfterCommit) throw new Error("simulated crash after durable authority write");
      },
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "crash",
      subjectId: "u1",
      ruleId: "document-access",
      authority: relationship("doc-1", "reader", { startsAtEpochMs: 0, endsAtEpochMs: 100 }),
    });
    await expect(service.transition("boss", {
      requestId: pending.requestId,
      expectedRevision: pending.revision,
      action: "approve",
    })).rejects.toThrow(/simulated crash/);
    expect((await service.read(pending.requestId)).state).toBe("issuing");
    failAfterCommit = false;
    expect((await service.recover(pending.requestId)).state).toBe("approved");
    expect(committed).toEqual(new Set([`access-request:${pending.requestId}`]));
  });

  it("keeps submission and terminal retries idempotent while conflicting rewrites fail", async () => {
    const store = createStore();
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => ({ rule: documentRule() }),
      resolveApprovalRoute: () => ({ queue: "restricted" }),
      authorizeTransition: () => true,
      issue: async () => {},
    });
    const input = {
      idempotencyKey: "retry",
      subjectId: "u1",
      ruleId: "document-access",
      authority: relationship("doc-1", "reader", { startsAtEpochMs: 0, endsAtEpochMs: 100 }),
    };
    const first = await service.submit("u1", input);
    expect(await service.submit("u1", input)).toEqual(first);
    await expect(service.submit("u1", {
      ...input,
      authority: relationship("doc-2", "reader", { startsAtEpochMs: 0, endsAtEpochMs: 100 }),
    })).rejects.toThrow(/idempotency/i);
    const denied = await service.transition("boss", {
      requestId: first.requestId,
      expectedRevision: first.revision,
      action: "deny",
      reason: "no",
    });
    expect(await service.transition("boss", {
      requestId: first.requestId,
      expectedRevision: first.revision,
      action: "deny",
      reason: "different retry text",
    })).toEqual(denied);
    await expect(service.transition("boss", {
      requestId: first.requestId,
      expectedRevision: first.revision,
      action: "approve",
    })).rejects.toThrow(/terminal|conflict/i);
  });

  it("rechecks automatic rules immediately before issuance", async () => {
    const store = createStore();
    const automatic = access.requestRule({
      ruleId: "self-service",
      allow: { kind: "grant", grants: [{ permission: "billing.read", scope: { assignee: ids("u1") } }] },
      approval: { kind: "automatic" },
    });
    let resolutions = 0;
    const issued: Authority[] = [];
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => {
        resolutions += 1;
        return resolutions === 1 ? { rule: automatic } : undefined;
      },
      authorizeTransition: () => true,
      async issue({ authority }) {
        issued.push(authority);
      },
    });
    await expect(service.submit("u1", {
      idempotencyKey: "auto-stale",
      subjectId: "u1",
      ruleId: "self-service",
      authority: grant({ permission: "billing.read", scope: { assignee: ids("u1") } }),
    })).rejects.toThrow(/currently applicable|rule/i);
    expect(issued).toEqual([]);
    expect([...store.records.values()][0]?.state).toBe("pending");
  });

  it("commits automatic rules immediately through the same recoverable protocol", async () => {
    const store = createStore();
    const automatic = access.requestRule({
      ruleId: "self-service",
      allow: { kind: "grant", grants: [{ permission: "billing.read", scope: { assignee: ids("u1") } }] },
      approval: { kind: "automatic" },
    });
    const issued: Authority[] = [];
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => ({ rule: automatic }),
      authorizeTransition: () => true,
      async issue({ authority }) {
        issued.push(authority);
      },
    });
    const requested = grant({ permission: "billing.read", scope: { assignee: ids("u1") } });
    const approved = await service.submit("u1", {
      idempotencyKey: "auto-1",
      subjectId: "u1",
      ruleId: "self-service",
      authority: requested,
    });
    expect(approved.state).toBe("approved");
    expect(approved.decision).toMatchObject({ action: "approve", authority: requested });
    expect(issued).toEqual([requested]);
  });

  it("expires only pending requests and records the system decision", async () => {
    const store = createStore();
    const service = createAccessRequestService({
      catalog: access.catalog,
      store,
      resolveRule: () => ({ rule: documentRule() }),
      resolveApprovalRoute: () => ({ queue: "restricted" }),
      authorizeTransition: () => true,
      issue: async () => {},
    });
    const pending = await service.submit("u1", {
      idempotencyKey: "expiry",
      subjectId: "u1",
      ruleId: "document-access",
      authority: relationship("doc-1", "reader", { startsAtEpochMs: 0, endsAtEpochMs: 100 }),
    });
    const expired = await service.expire(pending.requestId, pending.revision);
    expect(expired).toMatchObject({ state: "expired", decision: { action: "expire" } });
    expect(await service.expire(pending.requestId, pending.revision)).toEqual(expired);
  });
});
