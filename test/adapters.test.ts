import { describe, expect, it } from "vitest";
import {
  applyAccessQueryPlan,
  createAdaptedAccessEvaluator,
  defineAccessCatalog,
  type CompiledAccessConstraint,
} from "../src/index.js";

type Permission = "*" | "record.read" | "billing.read";
type Leaf = "record.read" | "billing.read";
type Dimension = "location" | "assignee";
type Attribute = "assigneeId";

type LegacyGrant = {
  permission: Leaf;
  locationIds?: readonly string[];
  ownAssignee?: boolean;
  /** Test-only malformed wire flag that emits the same location dimension twice. */
  duplicateLocationScope?: boolean;
};

type LegacySnapshot = {
  epoch: number;
  actorAssigneeId?: string;
  grants: readonly LegacyGrant[];
};

/** Catalog used to prove old compact application snapshots can be retained through a BYO adapter. */
const catalog = defineAccessCatalog<Permission, Leaf, Dimension>({
  catalogId: "adapter-test",
  catalogVersion: 1,
  compilerVersion: 2,
  permissions: ["*", "record.read", "billing.read"],
  leaves: ["record.read", "billing.read"],
  scopeDimensions: { "record.read": ["location"], "billing.read": ["location", "assignee"] },
  includes(granted, requested) {
    return granted === "*" || granted === requested;
  },
});

/** Translate one fake old grant to the generic constraints only when the snapshot is first indexed. */
function constraints(grant: LegacyGrant): readonly CompiledAccessConstraint<Dimension, Attribute>[] {
  const result: CompiledAccessConstraint<Dimension, Attribute>[] = [];
  if (grant.locationIds) result.push({ dimension: "location", kind: "ids", ids: grant.locationIds });
  if (grant.duplicateLocationScope) {
    result.push({ dimension: "location", kind: "ids", ids: ["duplicate"] });
  }
  if (grant.ownAssignee) result.push({ dimension: "assignee", kind: "subject", attribute: "assigneeId" });
  return result;
}

describe("BYO adapters", () => {
  it("keeps an existing compiled wire/storage shape without moving hot-path policy into the adapter", () => {
    const access = createAdaptedAccessEvaluator(catalog, {
      accepts(snapshot: LegacySnapshot) {
        return snapshot.epoch === 2;
      },
      grants(snapshot) {
        return snapshot.grants;
      },
      permission(grant) {
        return grant.permission;
      },
      constraints,
      subjectValue(snapshot, attribute) {
        return attribute === "assigneeId" ? snapshot.actorAssigneeId : undefined;
      },
    });
    const snapshot: LegacySnapshot = {
      epoch: 2,
      actorAssigneeId: "p1",
      grants: [{ permission: "billing.read", locationIds: ["a"], ownAssignee: true }],
    };
    expect(access.can(snapshot, "billing.read", { location: "a", assignee: "p1" })).toBe(true);
    expect(access.can(snapshot, "billing.read", { location: "a", assignee: "p2" })).toBe(false);
  });

  it("fails closed when malformed BYO fixed-id scope is empty", () => {
    const access = createAdaptedAccessEvaluator(catalog, {
      accepts: (snapshot: LegacySnapshot) => snapshot.epoch === 2,
      grants: (snapshot) => snapshot.grants,
      permission: (grant) => grant.permission,
      constraints,
      subjectValue: () => undefined,
    });
    const snapshot: LegacySnapshot = {
      epoch: 2,
      grants: [{ permission: "record.read", locationIds: [] }],
    };
    expect(access.can(snapshot, "record.read", { location: "a" })).toBe(false);
    expect(access.queryPlan(snapshot, "record.read")).toEqual({ kind: "none" });
  });

  it("fails closed when malformed BYO wire data repeats one scope dimension", () => {
    const access = createAdaptedAccessEvaluator(catalog, {
      accepts: (snapshot: LegacySnapshot) => snapshot.epoch === 2,
      grants: (snapshot) => snapshot.grants,
      permission: (grant) => grant.permission,
      constraints,
      subjectValue: () => undefined,
    });
    const snapshot: LegacySnapshot = {
      epoch: 2,
      grants: [
        {
          permission: "record.read",
          locationIds: ["a"],
          duplicateLocationScope: true,
        },
      ],
    };
    expect(access.can(snapshot, "record.read", { location: "a" })).toBe(false);
    expect(access.queryPlan(snapshot, "record.read")).toEqual({ kind: "none" });
  });

  it("fails closed when the application adapter rejects a stale generation", () => {
    const access = createAdaptedAccessEvaluator(catalog, {
      accepts: (snapshot: LegacySnapshot) => snapshot.epoch === 2,
      grants: (snapshot) => snapshot.grants,
      permission: (grant) => grant.permission,
      constraints,
      subjectValue: () => undefined,
    });
    expect(access.can({ epoch: 1, grants: [{ permission: "record.read" }] }, "record.read")).toBe(false);
  });

  it("lets a database adapter translate query plans without AccessOnce importing that database", () => {
    const result = applyAccessQueryPlan(
      { where: [] as string[] },
      { kind: "some", clauses: [{ location: ["a"] }, { location: ["b"] }] },
      {
        deny(query) {
          query.where.push("FALSE");
          return query;
        },
        allowAll(query) {
          return query;
        },
        applyClauses(query, clauses) {
          query.where.push(`OR:${clauses.length}`);
          return query;
        },
      },
    );
    expect(result.where).toEqual(["OR:2"]);
  });
});
