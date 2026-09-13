import { performance } from "node:perf_hooks";
import {
  compileAccessSnapshot,
  createAccessEvaluator,
  createAdaptedAccessEvaluator,
  defineAccessCatalog,
} from "../dist/index.js";

const leaves = Array.from({ length: 48 }, (_, index) => `p.${index}`);
const permissions = ["*", ...leaves];
const scopeDimensions = Object.fromEntries(leaves.map((leaf) => [leaf, ["location", "resource"]]));
const catalog = defineAccessCatalog({
  catalogId: "benchmark",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions,
  leaves,
  scopeDimensions,
  includes(granted, requested) {
    return granted === "*" || granted === requested;
  },
});
const grants = [];
for (let index = 0; index < leaves.length; index += 1) {
  grants.push({
    permission: leaves[index],
    scope: {
      location: { kind: "ids", ids: [`l${index % 8}`, `l${(index + 1) % 8}`] },
      resource: { kind: "ids", ids: [`r${index % 16}`] },
    },
  });
}
const snapshot = compileAccessSnapshot(catalog, { grants });
const canonical = createAccessEvaluator(catalog);
const externalSnapshot = { generation: 1, grants: snapshot.grants };
const adapted = createAdaptedAccessEvaluator(catalog, {
  accepts(value) {
    return value.generation === 1;
  },
  grants(value) {
    return value.grants;
  },
  permission(grant) {
    return grant.permission;
  },
  constraints(grant) {
    return grant.constraints;
  },
  subjectValue() {
    return undefined;
  },
});
const context = { location: "l4", resource: "r4" };

/** Warm and measure one synchronous evaluator path with the same allowed workload. */
function measure(label, check) {
  for (let index = 0; index < 100_000; index += 1) check();
  const iterations = 3_000_000;
  let allowed = 0;
  const started = performance.now();
  for (let index = 0; index < iterations; index += 1) {
    if (check()) allowed += 1;
  }
  const elapsedSeconds = (performance.now() - started) / 1000;
  const checksPerSecond = iterations / elapsedSeconds;
  const result = {
    label,
    iterations,
    allowed,
    elapsedSeconds,
    checksPerSecond: Math.round(checksPerSecond),
  };
  console.log(JSON.stringify(result, null, 2));
  if (allowed !== iterations) throw new Error(`${label} benchmark decision changed`);
  if (checksPerSecond < 2_000_000) {
    throw new Error(`${label} evaluator below 2,000,000 checks/s gate: ${Math.round(checksPerSecond)}`);
  }
  return checksPerSecond;
}

/** Keep BYO snapshot support close enough to canonical throughput that adapter ergonomics never hide a hot-path tax. */
function requireAdaptedRatio(label, canonicalRate, adaptedRate) {
  if (adaptedRate >= canonicalRate * 0.75) return;
  throw new Error(
    `${label} adapted evaluator fell below 75% of canonical throughput: ${Math.round(adaptedRate)} vs ${Math.round(canonicalRate)}`,
  );
}

const canonicalRate = measure("canonical", () => canonical.can(snapshot, "p.4", context));
const adaptedRate = measure("adapted", () => adapted.can(externalSnapshot, "p.4", context));
requireAdaptedRatio("single-grant", canonicalRate, adaptedRate);

/** Several grants for one permission exercise the cold candidate-bucket index used by scoped business permissions. */
const correlatedGrants = [];
for (let index = 0; index < 8; index += 1) {
  correlatedGrants.push({
    permission: "p.0",
    scope: {
      location: { kind: "ids", ids: [`bucket-l${index}`] },
      resource: { kind: "ids", ids: [`bucket-r${index}`] },
    },
  });
}
const correlatedSnapshot = compileAccessSnapshot(catalog, { grants: correlatedGrants });
const correlatedExternalSnapshot = { generation: 1, grants: correlatedSnapshot.grants };
const correlatedContext = { location: "bucket-l6", resource: "bucket-r6" };
const correlatedCanonicalRate = measure("correlated-canonical", () =>
  canonical.can(correlatedSnapshot, "p.0", correlatedContext),
);
const correlatedAdaptedRate = measure("correlated-adapted", () =>
  adapted.can(correlatedExternalSnapshot, "p.0", correlatedContext),
);
requireAdaptedRatio("correlated", correlatedCanonicalRate, correlatedAdaptedRate);
