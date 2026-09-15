import { describe, expect, it, vi } from "vitest";
import {
  createAccessRequestControlClient,
  createAccessRequestHistoryClient,
  createHierarchicalAccess,
  parseAccessRequestHistoryQuery,
  parseAccessRequestReadRequest,
  parseAccessRequestSubmitRequest,
  parseAccessRequestTransitionRequest,
} from "../src/index.js";

type Permission = "*" | "record.read";
type Leaf = "record.read";
type Dimension = "location";

/** Tiny request-wire catalog used to prove untrusted authority decoding. */
const access = createHierarchicalAccess<Permission, Leaf, Dimension>({
  catalogId: "request-wire-test",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["*", "record.read"],
  leaves: ["record.read"],
  wildcard: "*",
  scopeDimensions: { "record.read": ["location"] },
});

describe("access request control wire", () => {
  it("parses grant and relationship submissions plus narrowed approval/reason", () => {
    expect(parseAccessRequestSubmitRequest(access, {
      idempotencyKey: "k1",
      subjectId: "u1",
      ruleId: "restricted",
      authority: {
        kind: "grant",
        grant: {
          permission: "record.read",
          scope: { location: { kind: "ids", ids: ["a"] } },
        },
      },
    })).toEqual({
      idempotencyKey: "k1",
      subjectId: "u1",
      ruleId: "restricted",
      authority: {
        kind: "grant",
        grant: {
          permission: "record.read",
          scope: { location: { kind: "ids", ids: ["a"] } },
        },
      },
    });

    expect(parseAccessRequestSubmitRequest(access, {
      idempotencyKey: "k2",
      subjectId: "u1",
      ruleId: "document-access",
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
        validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 },
      },
    })).toMatchObject({
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
      },
    });

    expect(parseAccessRequestReadRequest({ requestId: "r1" })).toEqual({ requestId: "r1" });
    expect(parseAccessRequestTransitionRequest(access, {
      requestId: "r1",
      expectedRevision: "2",
      action: "approve",
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
        validity: { startsAtEpochMs: 12, endsAtEpochMs: 18 },
      },
      reason: "Until end of shift",
    })).toMatchObject({
      requestId: "r1",
      expectedRevision: "2",
      action: "approve",
      reason: "Until end of shift",
      authority: { kind: "relationship" },
    });
  });

  it("bounds untrusted authority and reason payloads", () => {
    expect(() => parseAccessRequestSubmitRequest(access, {
      idempotencyKey: "k1",
      subjectId: "u1",
      ruleId: "restricted",
      authority: {
        kind: "grant",
        grant: {
          permission: "record.read",
          scope: { unknown: { kind: "ids", ids: ["a"] } },
        },
      },
    })).toThrow(/unsupported dimension/i);
    expect(() => parseAccessRequestSubmitRequest(access, {
      idempotencyKey: "k1",
      subjectId: "u1",
      ruleId: "document-access",
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
        validity: [
          { startsAtEpochMs: 1, endsAtEpochMs: 2 },
          { startsAtEpochMs: 3, endsAtEpochMs: 4 },
        ],
      },
    }, { maximumValidityWindows: 1 })).toThrow(/validity windows/i);
    expect(() => parseAccessRequestSubmitRequest(access, {
      idempotencyKey: "k-empty-validity",
      subjectId: "u1",
      ruleId: "document-access",
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
        validity: [],
      },
    })).toThrow(/at least one window/i);
    expect(() => parseAccessRequestTransitionRequest(access, {
      requestId: "r1",
      expectedRevision: "2",
      action: "deny",
      reason: "too long",
    }, { maximumReasonLength: 3 })).toThrow(/maximum length/i);
    expect(() => parseAccessRequestTransitionRequest(access, {
      requestId: "r1",
      expectedRevision: "2",
      action: "deny",
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
      },
    })).toThrow(/only approve/i);
  });

  it("keeps the client transport tiny while supporting narrower approval and reasons", async () => {
    const submit = vi.fn(async (request) => ({
      ...request,
      requestId: "r1",
      revision: "1",
      requesterId: "u1",
      submittedAtEpochMs: 100,
      approval: { kind: "policy" as const, policyId: "restricted" },
      state: "pending" as const,
    }));
    const read = vi.fn(async () => ({
      requestId: "r1",
      requesterId: "u1",
      submittedAtEpochMs: 100,
      subjectId: "u1",
      revision: "1",
      idempotencyKey: "k1",
      ruleId: "document-access",
      authority: {
        kind: "relationship" as const,
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
      },
      approval: { kind: "policy" as const, policyId: "restricted" },
      state: "pending" as const,
    }));
    const transition = vi.fn(async () => read());
    const client = createAccessRequestControlClient({ submit, read, transition });
    const controller = new AbortController();
    await client.submit({
      idempotencyKey: "k1",
      subjectId: "u1",
      ruleId: "document-access",
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
      },
      signal: controller.signal,
    });
    await client.approve({
      requestId: "r1",
      expectedRevision: "1",
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
        validity: { endsAtEpochMs: 20 },
      },
      reason: "shorter",
      signal: controller.signal,
    });
    expect(transition).toHaveBeenCalledWith({
      requestId: "r1",
      expectedRevision: "1",
      action: "approve",
      authority: {
        kind: "relationship",
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
        validity: { endsAtEpochMs: 20 },
      },
      reason: "shorter",
    }, controller.signal);
    await client.deny({ requestId: "r1", expectedRevision: "1", reason: "no", signal: controller.signal });
    expect(transition).toHaveBeenLastCalledWith({
      requestId: "r1",
      expectedRevision: "1",
      action: "deny",
      reason: "no",
    }, controller.signal);
  });

  it("parses bounded indexed history queries and keeps history on a separate audit client", async () => {
    expect(parseAccessRequestHistoryQuery(access, {
      subjectId: "u1",
      ruleId: "restricted-record",
      authorityKind: "relationship",
      resourceType: "record",
      resourceId: "r1",
      relation: "reader",
      states: ["approved", "denied"],
      submittedFromEpochMs: 100,
      submittedUntilEpochMs: 200,
      limit: 50,
    }, { maximumHistoryPageSize: 100 })).toEqual({
      subjectId: "u1",
      ruleId: "restricted-record",
      authorityKind: "relationship",
      resourceType: "record",
      resourceId: "r1",
      relation: "reader",
      states: ["approved", "denied"],
      submittedFromEpochMs: 100,
      submittedUntilEpochMs: 200,
      limit: 50,
    });
    expect(() => parseAccessRequestHistoryQuery(access, {
      resourceId: "r1",
    })).toThrow(/resourceType/i);
    expect(() => parseAccessRequestHistoryQuery(access, {
      limit: 101,
    }, { maximumHistoryPageSize: 100 })).toThrow(/limit/i);

    const query = vi.fn(async (request, signal) => ({ requests: [], cursor: request.cursor }));
    const history = createAccessRequestHistoryClient({ query });
    const controller = new AbortController();
    await history.query({ subjectId: "u1", cursor: "next" }, controller.signal);
    expect(query).toHaveBeenCalledWith({ subjectId: "u1", cursor: "next" }, controller.signal);
  });

});
