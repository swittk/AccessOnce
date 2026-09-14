import { describe, expect, it } from "vitest";
import { createHierarchicalAccess, type AccessGrant, type AccessValidity } from "../src/index.js";

type Permission = "record.read" | "record.write";
type Dimension = "location" | "resource";
type Grant = AccessGrant<Permission, Dimension>;

/** Small scoped model used to compare temporal materialization against a naive active-grant oracle. */
const access = createHierarchicalAccess({
  catalogId: "temporal-conformance",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["record.read", "record.write"] as const,
  leaves: ["record.read", "record.write"] as const,
  scopeDimensions: {
    "record.read": ["location", "resource"],
    "record.write": ["location", "resource"],
  },
  implies: { "record.write": ["record.read"] },
});

/** Return whether one half-open validity value contributes authority at the requested instant. */
function validityAllows(validity: AccessValidity | readonly AccessValidity[] | undefined, at: number): boolean {
  if (validity === undefined) return true;
  const windows = Array.isArray(validity) ? validity : [validity];
  for (const window of windows) {
    if (window.startsAtEpochMs !== undefined && at < window.startsAtEpochMs) continue;
    if (window.endsAtEpochMs !== undefined && at >= window.endsAtEpochMs) continue;
    return true;
  }
  return false;
}

/** Strip temporal metadata from the source grants active at one instant to form an independent oracle snapshot. */
function oracleSnapshot(grants: readonly Grant[], at: number) {
  const active: Grant[] = [];
  for (const grant of grants) {
    if (!validityAllows(grant.validity, at)) continue;
    active.push({
      permission: grant.permission,
      ...(grant.scope === undefined ? {} : { scope: grant.scope }),
    });
  }
  return access.compile({ grants: active });
}

describe("temporal evaluator conformance", () => {
  it("matches naive recompilation across forward and backward time for decisions and projections", () => {
    const grants: Grant[] = [
      {
        permission: "record.read",
        scope: { location: { kind: "ids", ids: ["a"] } },
        validity: { endsAtEpochMs: 5 },
      },
      {
        permission: "record.write",
        scope: {
          location: { kind: "ids", ids: ["b"] },
          resource: { kind: "ids", ids: ["x"] },
        },
        validity: [
          { startsAtEpochMs: 3, endsAtEpochMs: 8 },
          { startsAtEpochMs: 10, endsAtEpochMs: 14 },
        ],
      },
      {
        permission: "record.read",
        scope: { location: { kind: "ids", ids: ["c"] } },
        validity: { startsAtEpochMs: 6 },
      },
      { permission: "record.read", scope: { location: { kind: "ids", ids: ["always"] } } },
    ];
    const snapshot = access.compile({ grants });
    const times = [0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 20, 14, 10, 9, 6, 3, 0];
    const contexts = [
      { location: "a" },
      { location: "b", resource: "x" },
      { location: "b", resource: "wrong" },
      { location: "c" },
      { location: "always" },
      { location: "none" },
    ] as const;

    for (const at of times) {
      const temporal = access.evaluateAt(snapshot, at);
      const oracle = oracleSnapshot(grants, at);
      for (const permission of ["record.read", "record.write"] as const) {
        for (const context of contexts) {
          expect(temporal.can(permission, context), `${permission} at ${at} ${JSON.stringify(context)}`).toBe(
            access.can(oracle, permission, context),
          );
        }
        expect(temporal.allowedValues(permission, "location")).toEqual(
          access.allowedValues(oracle, permission, "location"),
        );
        expect(temporal.queryPlan(permission)).toEqual(access.queryPlan(oracle, permission));
      }
    }
  });
});
