import { describe, expect, it, vi } from "vitest";
import {
  authorizeAccess,
  authorizeAccessMany,
  constrainRelationshipQuery,
  compileAccessSnapshot,
  createAccessEvaluator,
  defineAccessCatalog,
  materializeAccessRelationshipAt,
  sweepAccessRelationshipProjections,
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

  it("bounds fallback relationship checks while preserving result order", async () => {
    const snapshot = compileAccessSnapshot(catalog, { grants: [{ permission: "record.read" }] });
    const evaluator = createAccessEvaluator(catalog);
    let active = 0;
    let peak = 0;
    const requests = Array.from({ length: 40 }, (_, index) => ({
      permission: "record.read" as const,
      principal: { type: "user", id: `user-${index}` },
      relationship: {
        resource: { type: "record", id: `r${index}` },
        relation: "reader",
      },
    }));
    const check = vi.fn(async (request) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active -= 1;
      return Number(request.principal.id.slice(5)) % 2 === 0;
    });

    const results = await authorizeAccessMany(evaluator, snapshot, requests, { check });
    expect(peak).toBeLessThanOrEqual(32);
    expect(peak).toBeGreaterThan(1);
    expect(results).toEqual(requests.map((_, index) => index % 2 === 0));
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


  it("materializes temporal relationship source and reports only the next real boundary", () => {
    const source = {
      unrestricted: false,
      subjects: [
        { principal: { type: "user", id: "always" } },
        {
          principal: { type: "user", id: "alice" },
          validity: [
            { startsAtEpochMs: 10, endsAtEpochMs: 20 },
            { startsAtEpochMs: 15, endsAtEpochMs: 30 },
          ],
        },
        {
          principal: { type: "role", id: "future" },
          validity: { startsAtEpochMs: 40 },
        },
      ],
    } as const;

    expect(materializeAccessRelationshipAt(source, 5)).toEqual({
      unrestricted: false,
      principals: [{ type: "user", id: "always" }],
      nextTransitionAtEpochMs: 10,
    });
    expect(materializeAccessRelationshipAt(source, 15)).toEqual({
      unrestricted: false,
      principals: [
        { type: "user", id: "always" },
        { type: "user", id: "alice" },
      ],
      // Overlapping windows merge, so the redundant inner end at 20 does not schedule a useless sweep.
      nextTransitionAtEpochMs: 30,
    });
    expect(materializeAccessRelationshipAt(source, 20)).toEqual({
      unrestricted: false,
      principals: [
        { type: "user", id: "always" },
        { type: "user", id: "alice" },
      ],
      nextTransitionAtEpochMs: 30,
    });
    expect(materializeAccessRelationshipAt(source, 35)).toEqual({
      unrestricted: false,
      principals: [{ type: "user", id: "always" }],
      nextTransitionAtEpochMs: 40,
    });
    expect(materializeAccessRelationshipAt(source, 50)).toEqual({
      unrestricted: false,
      principals: [
        { type: "user", id: "always" },
        { type: "role", id: "future" },
      ],
    });
  });

  it("passes an explicit temporal instant straight through native query pushdown", async () => {
    const query = { where: [] as string[] };
    const constrainQuery = vi.fn(async (request) => {
      request.query.where.push(`at:${request.atEpochMs}`);
      return request.query;
    });
    await constrainRelationshipQuery(
      { constrainQuery },
      {
        query,
        principal: { type: "user", id: "alice" },
        resourceType: "document",
        relation: "reader",
        atEpochMs: 1234,
      },
    );
    expect(query.where).toEqual(["at:1234"]);
  });

  it("runs one bounded due-projection sweep with adapter-owned reconciliation", async () => {
    const targets = Array.from({ length: 9 }, (_, index) => ({
      resource: { type: "document", id: `d${index}` },
      relation: "reader",
    }));
    let active = 0;
    let peak = 0;
    const listDue = vi.fn(async () => targets);
    const reconcileAt = vi.fn(async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 1));
      active -= 1;
      return undefined;
    });
    await expect(
      sweepAccessRelationshipProjections(
        { listDue, reconcileAt },
        500,
        { limit: 9, concurrency: 3 },
      ),
    ).resolves.toBe(9);
    expect(listDue).toHaveBeenCalledWith(500, 9);
    expect(reconcileAt).toHaveBeenCalledTimes(9);
    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThan(1);
  });

  it("forwards an explicit relationship evaluation instant through authorization helpers", async () => {
    const snapshot = compileAccessSnapshot(catalog, { grants: [{ permission: "record.read" }] });
    const evaluator = createAccessEvaluator(catalog);
    const check = vi.fn(async (request) => request.atEpochMs === 1234);
    await expect(
      authorizeAccess(
        evaluator,
        snapshot,
        {
          permission: "record.read",
          principal: { type: "user", id: "user-a" },
          relationship: { resource: { type: "record", id: "r1" }, relation: "reader" },
          atEpochMs: 1234,
        },
        { check },
      ),
    ).resolves.toBe(true);
    expect(check).toHaveBeenCalledWith({
      principal: { type: "user", id: "user-a" },
      resource: { type: "record", id: "r1" },
      relation: "reader",
      atEpochMs: 1234,
    });
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
