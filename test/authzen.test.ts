import { describe, expect, it, vi } from "vitest";
import { createHierarchicalAccess } from "../src/index.js";
import {
  AuthZenRequestError,
  authZenMetadataUrl,
  createAccessOnceAuthZenPdp,
  createAuthZenHttpClient,
  createAuthZenHttpClientFromMetadata,
  discoverAuthZenPdpMetadata,
} from "../src/authzen/index.js";

type Permission = "*" | "record" | "record.read";
type Leaf = "record.read";
type Dimension = "location";

/** Small canonical AccessOnce model used to exercise the standard wire bridge. */
const access = createHierarchicalAccess<Permission, Leaf, Dimension>({
  catalogId: "authzen-test",
  catalogVersion: 1,
  compilerVersion: 1,
  wildcard: "*",
  permissions: ["*", "record", "record.read"],
  leaves: ["record.read"],
  scopeDimensions: { "record.read": ["location"] },
});

/** Create a local AuthZEN PDP that maps action.name directly and reads location from resource properties. */
function createTestPdp(loadSnapshot: (subjectId: string) => ReturnType<typeof access.compile> | undefined) {
  return createAccessOnceAuthZenPdp({
    evaluator: access,
    loadSnapshot(subject) {
      return loadSnapshot(subject.id);
    },
    mapEvaluation(request) {
      if (request.action.name !== "record.read") return undefined;
      const location = request.resource.properties?.location;
      if (typeof location !== "string") return undefined;
      return { permission: "record.read" as const, context: { location } };
    },
  });
}

describe("AuthZEN adapter", () => {
  it("bridges a standard evaluation to the in-memory AccessOnce evaluator", async () => {
    const snapshot = access.compile({
      grants: [
        {
          permission: "record.read",
          scope: { location: { kind: "ids", ids: ["site-a"] } },
        },
      ],
    });
    const pdp = createTestPdp((subjectId) => (subjectId === "alice" ? snapshot : undefined));

    await expect(
      pdp.evaluate({
        subject: { type: "user", id: "alice" },
        action: { name: "record.read" },
        resource: { type: "record", id: "r1", properties: { location: "site-a" } },
      }),
    ).resolves.toEqual({ decision: true });
    await expect(
      pdp.evaluate({
        subject: { type: "user", id: "alice" },
        action: { name: "record.read" },
        resource: { type: "record", id: "r2", properties: { location: "site-b" } },
      }),
    ).resolves.toEqual({ decision: false });
  });

  it("supports boxcar defaults, standard short-circuit semantics, and one snapshot load per subject", async () => {
    const snapshot = access.compile({
      grants: [
        {
          permission: "record.read",
          scope: { location: { kind: "ids", ids: ["site-a"] } },
        },
      ],
    });
    const load = vi.fn(() => snapshot);
    const pdp = createTestPdp(load);

    await expect(
      pdp.evaluations({
        subject: { type: "user", id: "alice" },
        action: { name: "record.read" },
        options: { evaluations_semantic: "deny_on_first_deny" },
        evaluations: [
          { resource: { type: "record", id: "1", properties: { location: "site-a" } } },
          { resource: { type: "record", id: "2", properties: { location: "site-b" } } },
          { resource: { type: "record", id: "3", properties: { location: "site-a" } } },
        ],
      }),
    ).resolves.toEqual({ evaluations: [{ decision: true }, { decision: false }] });
    expect(load).toHaveBeenCalledOnce();
  });

  it("rejects malformed wire payloads before policy evaluation", async () => {
    const pdp = createTestPdp(() => undefined);
    await expect(
      pdp.evaluate({ action: { name: "record.read" }, resource: { type: "record", id: "1" } }),
    ).rejects.toBeInstanceOf(AuthZenRequestError);
  });

  it("uses the final AuthZEN 1.0 HTTPS paths and preserves request ids", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      expect(String(input)).toBe("https://pdp.example.com/tenant/access/v1/evaluation");
      expect(init?.method).toBe("POST");
      expect(init?.redirect).toBe("error");
      const headers = new Headers(init?.headers);
      expect(headers.get("Content-Type")).toBe("application/json");
      expect(headers.get("Authorization")).toBe("Bearer test");
      expect(headers.get("X-Request-ID")).toBe("request-1");
      return new Response(JSON.stringify({ decision: true }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "X-Request-ID": "request-1",
        },
      });
    });
    const client = createAuthZenHttpClient("https://pdp.example.com/tenant", {
      fetch: fetchMock,
      headers: { Authorization: "Bearer test" },
      requestId: () => "request-1",
    });

    await expect(
      client.evaluate({
        subject: { type: "user", id: "alice" },
        action: { name: "record.read" },
        resource: { type: "record", id: "1" },
      }),
    ).resolves.toEqual({ decision: true });
  });

  it("normalizes malformed successful HTTP responses to AuthZEN request errors", async () => {
    const malformedResponses = [
      new Response(JSON.stringify({ decision: true }), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Request-ID": "wrong-request" },
      }),
      new Response(JSON.stringify({ decision: true }), {
        status: 200,
        headers: { "Content-Type": "text/plain", "X-Request-ID": "request-1" },
      }),
      new Response("{", {
        status: 200,
        headers: { "Content-Type": "application/json", "X-Request-ID": "request-1" },
      }),
    ];

    for (const response of malformedResponses) {
      const client = createAuthZenHttpClient("https://pdp.example.com", {
        fetch: async () => response,
        requestId: () => "request-1",
      });
      await expect(client.evaluate({
        subject: { type: "user", id: "alice" },
        action: { name: "record.read" },
        resource: { type: "record", id: "1" },
      })).rejects.toBeInstanceOf(AuthZenRequestError);
    }
  });

  it("uses the standard resource-search endpoint and parses authorized entities", async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      expect(String(input)).toBe("https://pdp.example.com/access/v1/search/resource");
      return new Response(
        JSON.stringify({
          page: { next_token: "", count: 1, total: 1 },
          results: [{ type: "record", id: "r1" }],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    const client = createAuthZenHttpClient("https://pdp.example.com", { fetch: fetchMock });
    await expect(
      client.searchResources({
        subject: { type: "user", id: "alice" },
        action: { name: "record.read" },
        resource: { type: "record" },
      }),
    ).resolves.toEqual({
      page: { next_token: "", count: 1, total: 1 },
      results: [{ type: "record", id: "r1" }],
    });
  });

  it("discovers tenant metadata at the well-known URL and honors advertised capabilities", async () => {
    expect(authZenMetadataUrl("https://pdp.example.com/tenant1")).toBe(
      "https://pdp.example.com/.well-known/authzen-configuration/tenant1",
    );
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          policy_decision_point: "https://pdp.example.com/tenant1",
          access_evaluation_endpoint: "https://pdp.example.com/evaluate",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const metadata = await discoverAuthZenPdpMetadata(
      "https://pdp.example.com/tenant1",
      { fetch: fetchMock },
    );
    expect(metadata.access_evaluation_endpoint).toBe("https://pdp.example.com/evaluate");

    const client = createAuthZenHttpClientFromMetadata(metadata, { fetch: fetchMock });
    await expect(
      client.searchResources({
        subject: { type: "user", id: "alice" },
        action: { name: "record.read" },
        resource: { type: "record" },
      }),
    ).rejects.toThrow("does not advertise Resource Search");
  });
  it("rejects cleartext advertised endpoints before sending configured headers", () => {
    expect(() =>
      createAuthZenHttpClientFromMetadata({
        policy_decision_point: "https://pdp.example.com",
        access_evaluation_endpoint: "http://pdp.example.com/access/v1/evaluation",
      }),
    ).toThrow("access_evaluation_endpoint must use https");
  });

  it("preserves malformed advertised optional endpoints so validation fails closed", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          policy_decision_point: "https://pdp.example.com",
          access_evaluation_endpoint: "https://pdp.example.com/access/v1/evaluation",
          access_evaluations_endpoint: "",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );
    const metadata = await discoverAuthZenPdpMetadata("https://pdp.example.com", { fetch: fetchMock });
    expect(metadata.access_evaluations_endpoint).toBe("");
    expect(() => createAuthZenHttpClientFromMetadata(metadata)).toThrow(
      /access_evaluations_endpoint must be an absolute URL/,
    );
    expect(() =>
      createAuthZenHttpClientFromMetadata({
        policy_decision_point: "https://pdp.example.com",
        access_evaluation_endpoint: "https://pdp.example.com/access/v1/evaluation",
        search_subject_endpoint: "",
      }),
    ).toThrow(/search_subject_endpoint must be an absolute URL/);
  });

  it("normalizes malformed PDP and advertised endpoint URLs to AuthZEN request errors", () => {
    expect(() => createAuthZenHttpClient("not an absolute URL")).toThrow(AuthZenRequestError);
    expect(() =>
      createAuthZenHttpClientFromMetadata({
        policy_decision_point: "https://pdp.example.com",
        access_evaluation_endpoint: "not an absolute URL",
      }),
    ).toThrow(AuthZenRequestError);
  });

  it("requires the discovered PDP identifier to exactly match the requested identifier", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(
        JSON.stringify({
          policy_decision_point: "https://pdp.example.com/",
          access_evaluation_endpoint: "https://pdp.example.com/access/v1/evaluation",
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      ),
    );

    await expect(
      discoverAuthZenPdpMetadata("https://pdp.example.com", { fetch: fetchMock }),
    ).rejects.toThrow(/does not match the requested PDP identifier/);
  });

});
