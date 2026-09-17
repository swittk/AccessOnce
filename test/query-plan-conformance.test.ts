import { describe, expect, it } from "vitest";
import {
  compileAccessSnapshot,
  createAccessEvaluator,
  defineAccessCatalog,
  type AccessQueryPlan,
} from "../src/index.js";

type Permission = "read";
type Dimension = "location" | "resource" | "assignee";
type Attribute = "assigneeId";

/** Small catalog whose combinations exhaust correlation, wildcard, and own-subject query planning. */
const catalog = defineAccessCatalog<Permission, Permission, Dimension>({
  catalogId: "query-conformance",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["read"],
  leaves: ["read"],
  scopeDimensions: { read: ["location", "resource", "assignee"] },
  includes: (granted, requested) => granted === requested,
});

/** Evaluate the generic OR-of-AND plan as a tiny reference database would. */
function queryPlanAllows(
  plan: AccessQueryPlan<Dimension>,
  context: Readonly<Record<Dimension, string>>,
): boolean {
  if (plan.kind === "all") return true;
  if (plan.kind === "none") return false;
  for (const clause of plan.clauses) {
    let clauseAllows = true;
    for (const dimension of ["location", "resource", "assignee"] as const) {
      const allowed = clause[dimension];
      if (allowed && !allowed.includes(context[dimension])) {
        clauseAllows = false;
        break;
      }
    }
    if (clauseAllows) return true;
  }
  return false;
}

describe("query-plan executable conformance", () => {
  it("never broadens correlated grants or disagrees with direct runtime checks", () => {
    const sourceGrants = [
      { permission: "read" as const },
      {
        permission: "read" as const,
        scope: { location: { kind: "ids" as const, ids: ["l1"] } },
      },
      {
        permission: "read" as const,
        scope: { resource: { kind: "ids" as const, ids: ["r1"] } },
      },
      {
        permission: "read" as const,
        scope: {
          location: { kind: "ids" as const, ids: ["l1"] },
          resource: { kind: "ids" as const, ids: ["r1"] },
        },
      },
      {
        permission: "read" as const,
        scope: {
          location: { kind: "ids" as const, ids: ["l2"] },
          resource: { kind: "ids" as const, ids: ["r2"] },
          assignee: { kind: "subject" as const, attribute: "assigneeId" as const },
        },
      },
    ];
    const access = createAccessEvaluator<Permission, Permission, Dimension, Attribute>(catalog);

    // Every subset of these source grants gets checked against every small-domain row.
    for (let mask = 0; mask < 1 << sourceGrants.length; mask += 1) {
      const grants = [];
      for (let index = 0; index < sourceGrants.length; index += 1) {
        if ((mask & (1 << index)) !== 0) grants.push(sourceGrants[index]!);
      }
      const snapshot = compileAccessSnapshot(catalog, {
        grants,
        subject: { assigneeId: "p1" },
      });
      const plan = access.queryPlan(snapshot, "read");
      for (const location of ["l1", "l2", "l3"]) {
        for (const resource of ["r1", "r2", "r3"]) {
          for (const assignee of ["p1", "p2"]) {
            const context = { location, resource, assignee };
            expect(queryPlanAllows(plan, context)).toBe(
              access.can(snapshot, "read", context),
            );
          }
        }
      }
    }
  });
});
