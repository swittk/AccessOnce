import { describe, expect, it, vi } from "vitest";
import {
  authorizeAccess,
  authorizeAccessMany,
  constrainRelationshipQuery,
  compileAccessSnapshot,
  createAccessEvaluator,
  defineAccessCatalog,
} from "../src/index.js";

type Permission = "record.read";
type Dimension = "location";

/** Minimal catalog proving narrow object ACLs do not slow ordinary records. */
const catalog = defineAccessCatalog<Permission, Permission, Dimension>({
  catalogId: "relationship-test",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["record.read"],
  leaves: ["record.read"],
  scopeDimensions: { "record.read": ["location"] },
  includes: (granted, requested) => granted === requested,
});

describe("relationship ACL adapter", () => {
  it("does no adapter I/O for a normal object", async () => {
    const snapshot = compileAccessSnapshot(catalog, { grants: [{ permission: "record.read" }] });
    const evaluator = createAccessEvaluator(catalog);
    const check = vi.fn(async () => true);
    expect(await authorizeAccess(evaluator, snapshot, { permission: "record.read" }, { check })).toBe(true);
    expect(check).not.toHaveBeenCalled();
  });

  it("batches only object ACLs that survive the local permission check", async () => {
    const snapshot = compileAccessSnapshot(catalog, {
      grants: [{ permission: "record.read", scope: { location: { kind: "ids", ids: ["a"] } } }],
    });
    const evaluator = createAccessEvaluator(catalog);
    const checkMany = vi.fn(async (requests) =>
      requests.map((request) => request.principal.id === "user-a"),
    );
    const results = await authorizeAccessMany(
      evaluator,
      snapshot,
      [
        { permission: "record.read", context: { location: "a" } },
        {
          permission: "record.read",
          context: { location: "a" },
          principal: { type: "user", id: "user-a" },
          relationship: { resource: { type: "record", id: "r1" }, relation: "reader" },
        },
        {
          permission: "record.read",
          context: { location: "b" },
          principal: { type: "user", id: "user-a" },
          relationship: { resource: { type: "record", id: "r2" }, relation: "reader" },
        },
      ],
      { check: async () => false, checkMany },
    );
    expect(results).toEqual([true, true, false]);
    expect(checkMany).toHaveBeenCalledOnce();
    expect(checkMany.mock.calls[0]?.[0]).toHaveLength(1);
  });

  it("pushes collection authorization into one backend query operation without per-row fallback", async () => {
    const query = { where: ["site = a"] };
    const constrainQuery = vi.fn(async (request) => {
      request.query.where.push(`acl:${request.principal.id}:${request.relation}`);
      return request.query;
    });
    const result = await constrainRelationshipQuery(
      { constrainQuery },
      {
        query,
        principal: { type: "user", id: "user-a" },
        resourceType: "document",
        relation: "reader",
      },
    );
    expect(result).toBe(query);
    expect(result.where).toEqual(["site = a", "acl:user-a:reader"]);
    expect(constrainQuery).toHaveBeenCalledOnce();
  });

  it("checks explicit people/groups/roles only when the object requires a relation", async () => {
    const snapshot = compileAccessSnapshot(catalog, { grants: [{ permission: "record.read" }] });
    const evaluator = createAccessEvaluator(catalog);
    const check = vi.fn(async (request) => request.principal.id === "user-a");
    expect(
      await authorizeAccess(
        evaluator,
        snapshot,
        {
          permission: "record.read",
          principal: { type: "user", id: "user-a" },
          relationship: { resource: { type: "record", id: "r1" }, relation: "reader" },
        },
        { check },
      ),
    ).toBe(true);
    expect(check).toHaveBeenCalledOnce();
  });
});
