import { describe, expect, it } from "vitest";
import {
  compileAccessSnapshot,
  createAccess,
  createDenyAllSnapshot,
  createAccessEvaluator,
  createHierarchicalAccess,
  defineAccessCatalog,
  hierarchicalPermissionIncludes,
  type AccessGrant,
} from "../src/index.js";

type Permission = "*" | "record" | "record.read" | "record.write" | "billing.read";
type Leaf = "record.read" | "record.write" | "billing.read";
type Dimension = "location" | "resource" | "assignee";
type Attribute = "assigneeId";

/** Small test catalog exercising parent expansion, implication, fixed scopes, and subject-relative scopes. */
const catalog = defineAccessCatalog<Permission, Leaf, Dimension>({
  catalogId: "test",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["*", "record", "record.read", "record.write", "billing.read"],
  leaves: ["record.read", "record.write", "billing.read"],
  scopeDimensions: {
    "record.read": ["location", "resource"],
    "record.write": ["location", "resource"],
    "billing.read": ["location", "assignee"],
  },
  includes(granted, requested) {
    return granted === "*" || granted === requested || (granted === "record" && requested.startsWith("record."));
  },
  implies: {
    "record.write": ["record.read"],
  },
});

/** Compile test grants with the stable subject attribute used by own-assignee checks. */
function compile(grants: readonly AccessGrant<Permission, Dimension, Attribute>[]) {
  return compileAccessSnapshot(catalog, {
    grants,
    subject: { assigneeId: "user-a" },
    sourceRevision: "7",
  });
}

describe("AccessOnce core", () => {
  it("expands parents and implications only on the cold path", () => {
    const snapshot = compile([
      { permission: "record.write", scope: { location: { kind: "ids", ids: ["b", "a", "a"] } } },
    ]);
    expect(snapshot.grants.map((grant) => grant.permission)).toEqual(["record.read", "record.write"]);
    expect(snapshot.grants[0]?.constraints[0]).toEqual({ dimension: "location", kind: "ids", ids: ["a", "b"] });
  });

  it("preserves an explicitly empty source revision", () => {
    expect(compileAccessSnapshot(catalog, { grants: [], sourceRevision: "" }).sourceRevision).toBe("");
    expect(createDenyAllSnapshot(catalog, "").sourceRevision).toBe("");
  });

  it("returns deeply immutable canonical snapshots so identity caching cannot go stale", () => {
    const snapshot = compile([
      {
        permission: "record.read",
        scope: { location: { kind: "ids", ids: ["site-a"] } },
      },
    ]);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.grants)).toBe(true);
    expect(Object.isFrozen(snapshot.grants[0])).toBe(true);
    expect(Object.isFrozen(snapshot.grants[0]?.constraints)).toBe(true);
    expect(Object.isFrozen(snapshot.grants[0]?.constraints[0])).toBe(true);
    const constraint = snapshot.grants[0]?.constraints[0];
    if (constraint?.kind === "ids") expect(Object.isFrozen(constraint.ids)).toBe(true);
    expect(Object.isFrozen(snapshot.subject)).toBe(true);
  });

  it("carries descendant implications through a parent grant even when they leave the parent subtree", () => {
    const crossTreeCatalog = defineAccessCatalog<Permission, Leaf, Dimension>({
      catalogId: "cross-tree-test",
      catalogVersion: 1,
      compilerVersion: 1,
      permissions: ["*", "record", "record.read", "record.write", "billing.read"],
      leaves: ["record.read", "record.write", "billing.read"],
      scopeDimensions: {
        "record.read": ["location"],
        "record.write": ["location"],
        "billing.read": ["location"],
      },
      includes(granted, requested) {
        return granted === "*" || granted === requested ||
          (granted === "record" && requested.startsWith("record."));
      },
      implies: {
        "record.write": ["billing.read"],
      },
    });
    const snapshot = compileAccessSnapshot(crossTreeCatalog, {
      grants: [{
        permission: "record",
        scope: { location: { kind: "ids", ids: ["site-a"] } },
      }],
    });
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(crossTreeCatalog);
    expect(access.can(snapshot, "billing.read", { location: "site-a" })).toBe(true);
    expect(access.can(snapshot, "billing.read", { location: "site-b" })).toBe(false);
  });

  it("snapshots caller-owned catalog arrays so later mutation cannot change authorization meaning", () => {
    const permissions: Permission[] = ["*", "record", "record.read", "record.write", "billing.read"];
    const leaves: Leaf[] = ["record.read", "record.write", "billing.read"];
    const recordReadDimensions: Dimension[] = ["location"];
    const writeImplications: Permission[] = ["record.read"];
    const stableCatalog = defineAccessCatalog<Permission, Leaf, Dimension>({
      catalogId: "immutable-definition-test",
      catalogVersion: 1,
      compilerVersion: 1,
      permissions,
      leaves,
      scopeDimensions: {
        "record.read": recordReadDimensions,
        "record.write": ["location"],
        "billing.read": ["location"],
      },
      includes(granted, requested) {
        return granted === "*" || granted === requested ||
          (granted === "record" && requested.startsWith("record."));
      },
      implies: { "record.write": writeImplications },
    });

    permissions.splice(0);
    leaves.splice(0);
    recordReadDimensions.push("resource");
    writeImplications.splice(0);

    const snapshot = compileAccessSnapshot(stableCatalog, {
      grants: [{ permission: "record.write", scope: { location: { kind: "ids", ids: ["site-a"] } } }],
    });
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(stableCatalog);
    expect(access.can(snapshot, "record.write", { location: "site-a" })).toBe(true);
    expect(access.can(snapshot, "record.read", { location: "site-a" })).toBe(true);
    expect(stableCatalog.permissions).toHaveLength(5);
    expect(stableCatalog.leaves).toHaveLength(3);
    expect(stableCatalog.scopeDimensions("record.read")).toEqual(["location"]);
  });

  it("fails closed when required scope context is missing", () => {
    const snapshot = compile([
      { permission: "record.read", scope: { location: { kind: "ids", ids: ["site-a"] } } },
    ]);
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(catalog);
    expect(access.can(snapshot, "record.read")).toBe(false);
    expect(access.can(snapshot, "record.read", { location: "site-a" })).toBe(true);
    expect(access.can(snapshot, "record.read", { location: "site-b" })).toBe(false);
  });

  it("handles own-assignee as a generic subject-relative scope", () => {
    const snapshot = compile([
      {
        permission: "billing.read",
        scope: {
          location: { kind: "ids", ids: ["site-a"] },
          assignee: { kind: "subject", attribute: "assigneeId" },
        },
      },
    ]);
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(catalog);
    expect(access.can(snapshot, "billing.read", { location: "site-a", assignee: "user-a" })).toBe(true);
    expect(access.can(snapshot, "billing.read", { location: "site-a", assignee: "user-b" })).toBe(false);
    expect(
      access.allowedValues(snapshot, "billing.read", "assignee", {
        context: { location: "site-a" },
      }),
    ).toEqual({
      kind: "some",
      values: ["user-a"],
    });
  });

  it("keeps projections fail-closed when a subject-relative scope cannot resolve", () => {
    const snapshot = compileAccessSnapshot<Permission, Leaf, Dimension, Attribute>(catalog, {
      grants: [
        {
          permission: "billing.read",
          scope: {
            location: { kind: "ids", ids: ["site-a"] },
            assignee: { kind: "subject", attribute: "assigneeId" },
          },
        },
      ],
    });
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(catalog);

    expect(access.can(snapshot, "billing.read", { location: "site-a", assignee: "user-a" })).toBe(false);
    expect(access.allowedValues(snapshot, "billing.read", "location")).toEqual({ kind: "none" });
    expect(access.queryPlan(snapshot, "billing.read")).toEqual({ kind: "none" });
  });

  it("projects values declaratively without leaking grant representation", () => {
    const snapshot = compile([
      {
        permission: "billing.read",
        scope: {
          location: { kind: "ids", ids: ["site-own"] },
          assignee: { kind: "subject", attribute: "assigneeId" },
        },
      },
      {
        permission: "billing.read",
        scope: { location: { kind: "ids", ids: ["site-all"] } },
      },
      {
        permission: "record.read",
        scope: {
          location: { kind: "ids", ids: ["site-resource"] },
          resource: { kind: "ids", ids: ["record-a"] },
        },
      },
    ]);
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(catalog);

    expect(
      access.allowedValues(snapshot, "billing.read", "location", {
        requireUnrestricted: ["assignee"],
      }),
    ).toEqual({ kind: "some", values: ["site-all"] });
    expect(
      access.allowedValues(snapshot, "billing.read", "location", {
        requireRestricted: ["assignee"],
      }),
    ).toEqual({ kind: "some", values: ["site-own"] });
    expect(
      access.allowedValues(snapshot, "record.read", "location", {
        requireUnrestricted: ["resource"],
      }),
    ).toEqual({ kind: "none" });
    expect(
      access.queryPlan(snapshot, "billing.read", { requireUnrestricted: ["assignee"] }),
    ).toEqual({ kind: "some", clauses: [{ location: ["site-all"] }] });
  });

  it("offers a declarative hierarchy facade for dotted permission trees", () => {
    const access = createHierarchicalAccess({
      catalogId: "hierarchy-facade-test",
      catalogVersion: 1,
      compilerVersion: 1,
      wildcard: "*",
      permissions: ["*", "record", "record.read", "record.write", "billing.read"],
      leaves: ["record.read", "record.write", "billing.read"],
      scopeDimensions: {
        "record.read": ["location", "resource"],
        "record.write": ["location", "resource"],
        "billing.read": ["location", "assignee"],
      },
    });
    const snapshot = access.compile({ grants: [{ permission: "record" }] });
    expect(access.can(snapshot, "record.read")).toBe(true);
    expect(access.can(snapshot, "record.write")).toBe(true);
    expect(access.can(snapshot, "billing.read")).toBe(false);
    expect(hierarchicalPermissionIncludes("record", "record.read", "*")).toBe(true);
    expect(hierarchicalPermissionIncludes("record", "billing.read", "*")).toBe(false);
  });

  it("offers a one-object define, compile, and evaluate facade", () => {
    const access = createAccess<Permission, Leaf, Dimension, Attribute>({
      catalogId: "facade-test",
      catalogVersion: 1,
      compilerVersion: 1,
      permissions: ["*", "record", "record.read", "record.write", "billing.read"],
      leaves: ["record.read", "record.write", "billing.read"],
      scopeDimensions: {
        "record.read": ["location", "resource"],
        "record.write": ["location", "resource"],
        "billing.read": ["location", "assignee"],
      },
      includes(granted, requested) {
        return granted === "*" || granted === requested ||
          (granted === "record" && requested.startsWith("record."));
      },
    });
    const snapshot = access.compile({
      grants: [{ permission: "record.read", scope: { location: { kind: "ids", ids: ["site-a"] } } }],
    });

    expect(access.can(snapshot, "record.read", { location: "site-a" })).toBe(true);
    expect(access.deny().grants).toEqual([]);
    expect(access.catalog.catalogId).toBe("facade-test");
  });

  it("keeps correlated location/resource grants as separate query clauses", () => {
    const snapshot = compile([
      {
        permission: "record.read",
        scope: {
          location: { kind: "ids", ids: ["a"] },
          resource: { kind: "ids", ids: ["x"] },
        },
      },
      {
        permission: "record.read",
        scope: {
          location: { kind: "ids", ids: ["b"] },
          resource: { kind: "ids", ids: ["y"] },
        },
      },
    ]);
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(catalog);
    expect(access.queryPlan(snapshot, "record.read")).toEqual({
      kind: "some",
      clauses: [
        { location: ["a"], resource: ["x"] },
        { location: ["b"], resource: ["y"] },
      ],
    });
  });

  it("drops explicit empty scopes and trusts adapter-validated extra narrowing scopes", () => {
    const empty = compile([
      { permission: "record.read", scope: { location: { kind: "ids", ids: [] } } },
    ]);
    expect(empty.grants).toEqual([]);

    // Catalog scope metadata drives editors. Typed/adapted source grants are not revalidated here;
    // an unexpected extra scope is fail-closed narrowing rather than accidental broader access.
    const narrowed = compileAccessSnapshot(catalog, {
      grants: [{ permission: "billing.read", scope: { resource: { kind: "ids", ids: ["x"] } } }],
    });
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(catalog);
    expect(access.can(narrowed, "billing.read")).toBe(false);
    expect(access.can(narrowed, "billing.read", { resource: "x" })).toBe(true);
  });

  it("fails closed when the snapshot catalog generation is stale", () => {
    const snapshot = { ...compile([{ permission: "record.read" }]), compilerVersion: 999 };
    const access = createAccessEvaluator<Permission, Leaf, Dimension, Attribute>(catalog);
    expect(access.can(snapshot, "record.read")).toBe(false);
  });

  it("compiles temporal grants into compact transitions while keeping timeless can() unchanged", () => {
    const access = createAccess<Permission, Leaf, Dimension, Attribute>({
      catalogId: "temporal-test",
      catalogVersion: 1,
      compilerVersion: 1,
      permissions: ["*", "record", "record.read", "record.write", "billing.read"],
      leaves: ["record.read", "record.write", "billing.read"],
      scopeDimensions: {
        "record.read": ["location", "resource"],
        "record.write": ["location", "resource"],
        "billing.read": ["location", "assignee"],
      },
      includes(granted, requested) {
        return granted === "*" || granted === requested ||
          (granted === "record" && requested.startsWith("record."));
      },
    });
    const snapshot = access.compile({
      grants: [{
        permission: "record.read",
        scope: { location: { kind: "ids", ids: ["site-a"] } },
        validity: [
          { startsAtEpochMs: 10, endsAtEpochMs: 20 },
          { startsAtEpochMs: 30 },
        ],
      }],
    });

    expect(snapshot.grants).toEqual([]);
    expect(snapshot.temporal?.grants).toHaveLength(1);
    expect(snapshot.temporal?.grantPositions).toEqual([0]);
    expect(Object.isFrozen(snapshot.temporal)).toBe(true);
    expect(Object.isFrozen(snapshot.temporal?.grants)).toBe(true);
    expect(Object.isFrozen(snapshot.temporal?.transitions)).toBe(true);
    expect(Object.isFrozen(snapshot.temporal?.transitions[0])).toBe(true);
    expect(snapshot.temporal?.transitions).toEqual([
      { atEpochMs: 10, addGrantIndexes: [0], removeGrantIndexes: [] },
      { atEpochMs: 20, addGrantIndexes: [], removeGrantIndexes: [0] },
      { atEpochMs: 30, addGrantIndexes: [0], removeGrantIndexes: [] },
    ]);
    expect(access.can(snapshot, "record.read", { location: "site-a" })).toBe(false);
    expect(access.evaluate(snapshot).can("record.read", { location: "site-a" })).toBe(false);

    const before = access.evaluateAt(snapshot, 9);
    expect(before.can("record.read", { location: "site-a" })).toBe(false);
    expect(before.validFromEpochMs).toBeUndefined();
    expect(before.validUntilEpochMs).toBe(10);

    const first = access.evaluateAt(snapshot, 10);
    expect(first.can("record.read", { location: "site-a" })).toBe(true);
    expect(first.validFromEpochMs).toBe(10);
    expect(first.validUntilEpochMs).toBe(20);
    expect(access.evaluateAt(snapshot, 19)).toBe(first);

    expect(access.evaluateAt(snapshot, 20).can("record.read", { location: "site-a" })).toBe(false);
    const indefinite = access.evaluateAt(snapshot, 30);
    expect(indefinite.can("record.read", { location: "site-a" })).toBe(true);
    expect(indefinite.validFromEpochMs).toBe(30);
    expect(indefinite.validUntilEpochMs).toBeUndefined();

    // Historical callers reverse only crossed deltas and recover the exact earlier state.
    expect(access.evaluateAt(snapshot, 15).can("record.read", { location: "site-a" })).toBe(true);
    expect(access.evaluateAt(snapshot, 25).can("record.read", { location: "site-a" })).toBe(false);
  });

  it("merges overlapping temporal contributions and lets timeless authority dominate the same clause", () => {
    const access = createHierarchicalAccess({
      catalogId: "temporal-union-test",
      catalogVersion: 1,
      compilerVersion: 1,
      permissions: ["record.read"],
      leaves: ["record.read"],
      scopeDimensions: { "record.read": ["location"] },
    });
    const temporal = access.compile({ grants: [
      { permission: "record.read", validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 } },
      { permission: "record.read", validity: { startsAtEpochMs: 15, endsAtEpochMs: 30 } },
    ] });
    expect(temporal.temporal?.grants).toHaveLength(1);
    expect(temporal.temporal?.transitions).toEqual([
      { atEpochMs: 10, addGrantIndexes: [0], removeGrantIndexes: [] },
      { atEpochMs: 30, addGrantIndexes: [], removeGrantIndexes: [0] },
    ]);
    expect(access.evaluateAt(temporal, 25).can("record.read")).toBe(true);

    const timeless = access.compile({ grants: [
      { permission: "record.read" },
      { permission: "record.read", validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 } },
    ] });
    expect(timeless.grants).toHaveLength(1);
    expect(timeless.temporal).toBeUndefined();
    expect(access.can(timeless, "record.read")).toBe(true);
  });

  it("supports open-ended windows and preserves temporal validity through parents and implications", () => {
    const access = createAccess<Permission, Leaf, Dimension, Attribute>({
      catalogId: "temporal-parent-test",
      catalogVersion: 1,
      compilerVersion: 1,
      permissions: ["*", "record", "record.read", "record.write", "billing.read"],
      leaves: ["record.read", "record.write", "billing.read"],
      scopeDimensions: {
        "record.read": ["location"],
        "record.write": ["location"],
        "billing.read": ["location"],
      },
      includes(granted, requested) {
        return granted === "*" || granted === requested ||
          (granted === "record" && requested.startsWith("record."));
      },
      implies: { "record.write": ["billing.read"] },
    });
    const snapshot = access.compile({ grants: [{
      permission: "record",
      scope: { location: { kind: "ids", ids: ["site-a"] } },
      validity: { endsAtEpochMs: 50 },
    }] });

    expect(snapshot.temporal?.initialGrantIndexes).toEqual([0, 1, 2]);
    const active = access.evaluateAt(snapshot, 49);
    expect(active.can("record.read", { location: "site-a" })).toBe(true);
    expect(active.can("record.write", { location: "site-a" })).toBe(true);
    expect(active.can("billing.read", { location: "site-a" })).toBe(true);
    const expired = access.evaluateAt(snapshot, 50);
    expect(expired.can("record.read", { location: "site-a" })).toBe(false);
    expect(expired.can("record.write", { location: "site-a" })).toBe(false);
    expect(expired.can("billing.read", { location: "site-a" })).toBe(false);
  });

  it("fails closed for malformed temporal snapshot indexes", () => {
    const access = createHierarchicalAccess({
      catalogId: "temporal-malformed-test",
      catalogVersion: 1,
      compilerVersion: 1,
      permissions: ["record.read"],
      leaves: ["record.read"],
      scopeDimensions: { "record.read": [] },
    });
    const snapshot = access.compile({ grants: [{
      permission: "record.read",
      validity: { endsAtEpochMs: 10 },
    }] });
    const malformed = {
      ...snapshot,
      temporal: {
        grants: snapshot.temporal!.grants,
        initialGrantIndexes: [99],
        transitions: snapshot.temporal!.transitions,
      },
    };
    expect(access.evaluateAt(malformed, 0).can("record.read")).toBe(false);
  });

});
