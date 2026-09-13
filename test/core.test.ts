import { describe, expect, it } from "vitest";
import {
  compileAccessSnapshot,
  createAccess,
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
});
