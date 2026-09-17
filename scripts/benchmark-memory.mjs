import v8 from "node:v8";
import {
  compileAccessSnapshot,
  createAccessEvaluationFactory,
  createAccessEvaluator,
  defineAccessCatalog,
} from "../dist/index.js";

if (typeof globalThis.gc !== "function") {
  throw new Error("Memory benchmark requires node --expose-gc");
}

const leaves = Array.from({ length: 64 }, (_, index) => `p.${index}`);
const catalog = defineAccessCatalog({
  catalogId: "memory-benchmark",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["*", ...leaves],
  leaves,
  scopeDimensions: Object.fromEntries(
    leaves.map((leaf) => [leaf, ["location", "resource"]]),
  ),
  includes(granted, requested) {
    return granted === "*" || granted === requested;
  },
});
const evaluator = createAccessEvaluator(catalog);
const evaluationFactory = createAccessEvaluationFactory(evaluator);
const snapshotCount = 6_000;

/** Force several complete collections so retained-object measurements dominate short-lived noise. */
function collectGarbage() {
  for (let index = 0; index < 6; index += 1) globalThis.gc();
}

/** Capture the process and V8 allocator counters relevant to authorization snapshot retention. */
function memorySample() {
  return { process: process.memoryUsage(), heap: v8.getHeapStatistics() };
}

collectGarbage();
const baseline = memorySample();
let snapshots = [];
for (let snapshotIndex = 0; snapshotIndex < snapshotCount; snapshotIndex += 1) {
  const grants = [];
  for (let grantIndex = 0; grantIndex < 8; grantIndex += 1) {
    grants.push({
      permission: leaves[(snapshotIndex + grantIndex) % leaves.length],
      scope: {
        location: {
          kind: "ids",
          ids: [`l${snapshotIndex % 32}`, `l${(snapshotIndex + 1) % 32}`],
        },
        resource: {
          kind: "ids",
          ids: [`r${grantIndex}`, `r${grantIndex + 1}`],
        },
      },
    });
  }
  snapshots.push(compileAccessSnapshot(catalog, { grants }));
}

// Keep the array globally reachable so V8 liveness analysis cannot collect it before sampling.
globalThis.__accessOnceMemoryBenchmarkHold = snapshots;
collectGarbage();
const compiled = memorySample();
let sampledWireBytes = 0;
for (let index = 0; index < 500; index += 1) {
  sampledWireBytes += Buffer.byteLength(JSON.stringify(snapshots[index]));
}

for (let index = 0; index < snapshots.length; index += 1) {
  evaluator.can(snapshots[index], leaves[index % leaves.length], {
    location: `l${index % 32}`,
    resource: "r0",
  });
}
globalThis.__accessOnceMemoryBenchmarkHold = snapshots;
collectGarbage();
const indexed = memorySample();

globalThis.__accessOnceMemoryBenchmarkHold = undefined;
snapshots = [];
collectGarbage();
const timelessReleased = memorySample();

/** Populate the temporal caches and return only measurements so local snapshot references die on return. */
function populateTemporalCache() {
  const temporalSnapshots = [];
  const temporalEvaluations = [];
  for (let snapshotIndex = 0; snapshotIndex < snapshotCount; snapshotIndex += 1) {
    temporalSnapshots.push(
      compileAccessSnapshot(catalog, {
        grants: Array.from({ length: 8 }, (_, grantIndex) => ({
          permission: leaves[(snapshotIndex + grantIndex) % leaves.length],
          scope: {
            location: { kind: "ids", ids: [`l${(snapshotIndex + grantIndex) % 32}`] },
          },
          validity: [
            { startsAtEpochMs: 100 + grantIndex, endsAtEpochMs: 200 + grantIndex },
            { startsAtEpochMs: 300 + grantIndex, endsAtEpochMs: 400 + grantIndex },
            { startsAtEpochMs: 500 + grantIndex },
          ],
        })),
      }),
    );
  }
  const temporalWireBytes = Buffer.byteLength(JSON.stringify(temporalSnapshots[0]));
  for (let index = 0; index < temporalSnapshots.length; index += 1) {
    temporalEvaluations.push(
      evaluationFactory.evaluateAt(temporalSnapshots[index], [150, 350, 550][index % 3]),
    );
  }
  globalThis.__accessOnceMemoryBenchmarkHold = {
    snapshots: temporalSnapshots,
    evaluations: temporalEvaluations,
  };
  collectGarbage();
  const temporalIndexed = memorySample();
  globalThis.__accessOnceMemoryBenchmarkHold = undefined;
  return { temporalWireBytes, temporalIndexed };
}

// Keep the factory alive while releasing its WeakMap keys; otherwise collecting the factory could hide a strong-key regression.
globalThis.__accessOnceMemoryBenchmarkFactory = evaluationFactory;
const { temporalWireBytes, temporalIndexed } = populateTemporalCache();
collectGarbage();
const released = memorySample();
globalThis.__accessOnceMemoryBenchmarkFactory = undefined;
const wireBytesPerSnapshot = Math.round(sampledWireBytes / 500);
const compiledHeapBytesPerSnapshot = Math.max(
  0,
  Math.round((compiled.process.heapUsed - baseline.process.heapUsed) / snapshotCount),
);
const indexHeapBytesPerSnapshot = Math.max(
  0,
  Math.round((indexed.process.heapUsed - compiled.process.heapUsed) / snapshotCount),
);
const temporalRuntimeHeapBytesPerSnapshot = Math.max(
  0,
  Math.round(
    (temporalIndexed.process.heapUsed - timelessReleased.process.heapUsed) / snapshotCount,
  ),
);
const peakRssDeltaBytes =
  Math.max(compiled.process.rss, indexed.process.rss, temporalIndexed.process.rss) -
  baseline.process.rss;
const retainedHeapAfterReleaseBytes = Math.max(
  0,
  released.process.heapUsed - baseline.process.heapUsed,
);
const peakMallocedMemoryBytes = Math.max(
  baseline.heap.peak_malloced_memory,
  compiled.heap.peak_malloced_memory,
  indexed.heap.peak_malloced_memory,
  temporalIndexed.heap.peak_malloced_memory,
);

const result = {
  snapshotCount,
  grantsPerSnapshot: 8,
  wireBytesPerSnapshot,
  temporalWireBytes,
  compiledHeapBytesPerSnapshot,
  indexHeapBytesPerSnapshot,
  temporalRuntimeHeapBytesPerSnapshot,
  peakRssDeltaBytes,
  peakMallocedMemoryBytes,
  retainedHeapAfterReleaseBytes,
};
console.log(JSON.stringify(result, null, 2));

// These bounds are intentionally loose enough for CI/V8 variance but tight enough to catch structural bloat/leaks.
if (wireBytesPerSnapshot > 2_048) {
  throw new Error(`Compiled snapshot wire size exceeded 2 KiB gate: ${wireBytesPerSnapshot}`);
}
if (temporalWireBytes > 4_096) {
  throw new Error(`Representative temporal snapshot wire size exceeded 4 KiB gate: ${temporalWireBytes}`);
}
if (compiledHeapBytesPerSnapshot > 8_192) {
  throw new Error(
    `Compiled snapshot retained heap exceeded 8 KiB gate: ${compiledHeapBytesPerSnapshot}`,
  );
}
if (indexHeapBytesPerSnapshot > 16_384) {
  throw new Error(
    `Runtime index retained heap exceeded 16 KiB gate: ${indexHeapBytesPerSnapshot}`,
  );
}
if (temporalRuntimeHeapBytesPerSnapshot > 32_768) {
  throw new Error(
    `Temporal runtime retained heap exceeded 32 KiB gate: ${temporalRuntimeHeapBytesPerSnapshot}`,
  );
}
if (retainedHeapAfterReleaseBytes > 4 * 1024 * 1024) {
  throw new Error(
    `Released snapshots left more than 4 MiB retained heap: ${retainedHeapAfterReleaseBytes}`,
  );
}
