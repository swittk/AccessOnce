import { describe, expect, it } from "vitest";
import { createHierarchicalAccess, type AccessGrant } from "../src/index.js";

/** Small role/profile catalog with a cross-subtree implication and correlated scopes. */
const access = createHierarchicalAccess({
  catalogId: "source-preview", catalogVersion: 1, compilerVersion: 1,
  wildcard: "*",
  permissions: ["*", "record", "record.read", "record.write", "audit.read"],
  leaves: ["record.read", "record.write", "audit.read"],
  scopeDimensions: { "record.read": ["location", "resource"], "record.write": ["location", "resource"], "audit.read": ["location", "resource"] },
  implies: { "record.write": ["audit.read"] },
});

/** Source fixture restricted to one exact location/resource combination. */
function grant(location: string, resource: string): AccessGrant<"record.read", "location" | "resource"> {
  return { permission: "record.read", scope: { location: { kind: "ids", ids: [location] }, resource: { kind: "ids", ids: [resource] } } };
}

describe("additive source composition", () => {
  it("preserves correlated clauses and matches the normal compiler exactly", () => {
    const first = grant("a", "x");
    const second = grant("b", "y");
    const result = access.compileSources({ sources: [
      { id: "profile-a", grants: [first] },
      { id: "profile-b", grants: [second] },
      { id: "direct", grants: [first] },
    ], sourceRevision: "17" });
    expect(result.snapshot).toEqual(access.compile({ grants: [first, second, first], sourceRevision: "17" }));
    expect(result.contributions[0]?.sourceIds).toEqual(["profile-a", "direct"]);
    expect(access.can(result.snapshot, "record.read", { location: "a", resource: "x" })).toBe(true);
    expect(access.can(result.snapshot, "record.read", { location: "a", resource: "y" })).toBe(false);
    expect(Object.keys(result.snapshot)).not.toContain("contributions");
    expect(Object.isFrozen(result.contributions[0]?.sourceIds)).toBe(true);
  });

  it("attributes parents and implications to their original bundle", () => {
    const result = access.compileSources({ sources: [{ id: "writer-role", grants: [{ permission: "record" }] }] });
    expect(access.can(result.snapshot, "audit.read")).toBe(true);
    expect(result.contributions).toHaveLength(3);
    for (const row of result.contributions) expect(row.sourceIds).toEqual(["writer-role"]);
  });

  it("does not let a restricted profile narrow an unrestricted grant from another profile", () => {
    const result = access.compileSources({ sources: [
      { id: "unrestricted", grants: [{ permission: "record.read" }] },
      { id: "site-a", grants: [grant("a", "x")] },
    ] });
    expect(access.can(result.snapshot, "record.read", { location: "elsewhere", resource: "other" })).toBe(true);
    expect(result.contributions).toHaveLength(2);
  });

  it("unions temporal windows across sources without inflating provenance into the snapshot", () => {
    const result = access.compileSources({ sources: [
      { id: "temporary-a", grants: [{ permission: "record.read", validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 } }] },
      { id: "temporary-b", grants: [{ permission: "record.read", validity: { startsAtEpochMs: 15, endsAtEpochMs: 30 } }] },
    ] });
    const flat = access.compile({ grants: [
      { permission: "record.read", validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 } },
      { permission: "record.read", validity: { startsAtEpochMs: 15, endsAtEpochMs: 30 } },
    ] });
    expect(result.snapshot).toEqual(flat);
    expect(result.snapshot.temporal?.transitions).toEqual([
      { atEpochMs: 10, addGrantIndexes: [0], removeGrantIndexes: [] },
      { atEpochMs: 30, addGrantIndexes: [], removeGrantIndexes: [0] },
    ]);
    expect(result.contributions).toHaveLength(1);
    expect(result.contributions[0]?.sourceIds).toEqual(["temporary-a", "temporary-b"]);
  });

});
