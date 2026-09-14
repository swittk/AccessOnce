import { describe, expect, it, vi } from "vitest";
import {
  createAccessRequestControlClient,
  createHierarchicalAccess,
  parseAccessRequestReadRequest,
  parseAccessRequestSubmitRequest,
  parseAccessRequestTransitionRequest,
} from "../src/index.js";

type Permission = "*" | "record.read";
type Leaf = "record.read";
type Dimension = "location";

/** Tiny request-wire catalog used to prove untrusted grant decoding. */
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
  it("parses bounded submit/read/transition requests and rejects unsupported grant scopes", () => {
    expect(parseAccessRequestSubmitRequest(access, {
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: {
        permission: "record.read",
        scope: { location: { kind: "ids", ids: ["a"] } },
      },
    })).toEqual({
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: {
        permission: "record.read",
        scope: { location: { kind: "ids", ids: ["a"] } },
      },
    });
    expect(parseAccessRequestReadRequest({ requestId: "r1" })).toEqual({ requestId: "r1" });
    expect(parseAccessRequestTransitionRequest({
      requestId: "r1",
      expectedRevision: "2",
      action: "approve",
    })).toEqual({ requestId: "r1", expectedRevision: "2", action: "approve" });
    expect(() => parseAccessRequestSubmitRequest(access, {
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: {
        permission: "record.read",
        scope: { unknown: { kind: "ids", ids: ["a"] } },
      },
    })).toThrow(/unsupported dimension/i);
    expect(() => parseAccessRequestSubmitRequest(access, {
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: {
        permission: "record.read",
        validity: [
          { startsAtEpochMs: 1, endsAtEpochMs: 2 },
          { startsAtEpochMs: 3, endsAtEpochMs: 4 },
        ],
      },
    }, { maximumValidityWindows: 1 })).toThrow(/validity windows/i);
  });

  it("keeps the client transport tiny and forwards cancellation signals", async () => {
    const submit = vi.fn(async (request) => ({ ...request, requestId: "r1", revision: "1", requesterId: "u1", approval: { kind: "automatic" as const }, state: "approved" as const }));
    const read = vi.fn(async () => ({
      requestId: "r1",
      requesterId: "u1",
      subjectId: "u1",
      revision: "1",
      idempotencyKey: "k1",
      policyId: "clinical",
      grant: { permission: "record.read" as const },
      approval: { kind: "automatic" as const },
      state: "approved" as const,
    }));
    const transition = vi.fn(async () => read());
    const client = createAccessRequestControlClient({ submit, read, transition });
    const controller = new AbortController();
    await client.submit({
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: { permission: "record.read" },
      signal: controller.signal,
    });
    expect(submit).toHaveBeenCalledWith({
      idempotencyKey: "k1",
      subjectId: "u1",
      policyId: "clinical",
      grant: { permission: "record.read" },
    }, controller.signal);
    await client.approve({ requestId: "r1", expectedRevision: "1", signal: controller.signal });
    expect(transition).toHaveBeenCalledWith({
      requestId: "r1",
      expectedRevision: "1",
      action: "approve",
    }, controller.signal);
  });
});
