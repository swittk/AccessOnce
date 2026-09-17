import { performance } from "node:perf_hooks";
import {
  compileAccessSnapshot,
  createAccessEvaluator,
  createAccessEvaluationFactory,
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

/** Return the middle value from an odd-sized numeric sample without mutating the caller's array. */
function median(values) {
  const ordered = [...values].sort((left, right) => left - right);
  return ordered[Math.floor(ordered.length / 2)];
}

/**
 * Compare canonical and adapted hot paths with paired samples so one noisy CI scheduling slice cannot
 * fail an otherwise healthy relative-throughput gate. Alternating order also avoids consistently
 * advantaging whichever path happens to run first on a fresh CPU boost window.
 */
function measureAdaptedComparison(label, canonicalCheck, adaptedCheck) {
  const sampleCount = 3;
  const canonicalRates = [];
  const adaptedRates = [];
  const ratios = [];
  for (let sample = 0; sample < sampleCount; sample += 1) {
    let canonicalRate;
    let adaptedRate;
    if (sample % 2 === 0) {
      canonicalRate = measure(`${label}-canonical-${sample + 1}`, canonicalCheck);
      adaptedRate = measure(`${label}-adapted-${sample + 1}`, adaptedCheck);
    } else {
      adaptedRate = measure(`${label}-adapted-${sample + 1}`, adaptedCheck);
      canonicalRate = measure(`${label}-canonical-${sample + 1}`, canonicalCheck);
    }
    canonicalRates.push(canonicalRate);
    adaptedRates.push(adaptedRate);
    ratios.push(adaptedRate / canonicalRate);
  }

  const canonicalRate = median(canonicalRates);
  const adaptedRate = median(adaptedRates);
  const adaptedRatio = median(ratios);
  console.log(JSON.stringify({
    label: `${label}-comparison`,
    canonicalChecksPerSecond: Math.round(canonicalRate),
    adaptedChecksPerSecond: Math.round(adaptedRate),
    adaptedToCanonicalRatio: Number(adaptedRatio.toFixed(4)),
    pairedRatios: ratios.map((ratio) => Number(ratio.toFixed(4))),
  }, null, 2));

  if (adaptedRatio < 0.75) {
    throw new Error(
      `${label} adapted evaluator median fell below 75% of canonical throughput: ` +
      `${Math.round(adaptedRatio * 10000) / 100}% median ratio`,
    );
  }
  return { canonicalRate, adaptedRate };
}

const singleComparison = measureAdaptedComparison(
  "single-grant",
  () => canonical.can(snapshot, "p.4", context),
  () => adapted.can(externalSnapshot, "p.4", context),
);
const canonicalRate = singleComparison.canonicalRate;

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
measureAdaptedComparison(
  "correlated",
  () => canonical.can(correlatedSnapshot, "p.0", correlatedContext),
  () => adapted.can(correlatedExternalSnapshot, "p.0", correlatedContext),
);


/** Temporal evaluation must not tax the timeless evaluator; same-interval resolution stays request-cheap. */
const temporalSnapshot = compileAccessSnapshot(catalog, {
  grants: [{
    permission: "p.4",
    scope: {
      location: { kind: "ids", ids: ["l4", "l5"] },
      resource: { kind: "ids", ids: ["r4"] },
    },
    validity: [
      { startsAtEpochMs: 100, endsAtEpochMs: 200 },
      { startsAtEpochMs: 300, endsAtEpochMs: 400 },
    ],
  }],
});
const temporal = createAccessEvaluationFactory(canonical);
const boundTemporal = temporal.evaluateAt(temporalSnapshot, 150);
const temporalBoundRate = measure("temporal-bound", () =>
  boundTemporal.can("p.4", context),
);
const temporalResolveRate = measure("temporal-same-interval", () =>
  temporal.evaluateAt(temporalSnapshot, 150).can("p.4", context),
);
if (temporalBoundRate < canonicalRate * 0.75) {
  throw new Error(
    `bound temporal evaluator fell below 75% of canonical throughput: ${Math.round(temporalBoundRate)} vs ${Math.round(canonicalRate)}`,
  );
}
if (temporalResolveRate < 5_000_000) {
  throw new Error(
    `same-interval evaluateAt fell below 5,000,000 checks/s: ${Math.round(temporalResolveRate)}`,
  );
}
