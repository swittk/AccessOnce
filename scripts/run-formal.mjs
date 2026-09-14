import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync } from "node:fs";
import { availableParallelism } from "node:os";
import { resolve } from "node:path";

const jar = resolve(process.env.TLA2TOOLS_JAR ?? ".artifacts/tla2tools.jar");
if (!existsSync(jar)) {
  throw new Error("Set TLA2TOOLS_JAR or place the pinned official jar at .artifacts/tla2tools.jar; see docs/assurance.md");
}
const formalDir = resolve("formal");
const outputDir = resolve(".formal-output");
mkdirSync(outputDir, { recursive: true });
const workers = String(Math.max(1, Math.min(8, availableParallelism())));

/** Run one bounded TLC model and require an exhaustive successful state-graph check. */
function runModel(moduleName, configName) {
  const result = spawnSync(
    "java",
    [
      "-Xmx512m",
      "-XX:+UseParallelGC",
      "-cp",
      jar,
      "tlc2.TLC",
      "-cleanup",
      "-workers",
      workers,
      "-metadir",
      resolve(outputDir, moduleName),
      "-config",
      configName,
      `${moduleName}.tla`,
    ],
    { cwd: formalDir, encoding: "utf8", timeout: 30_000, maxBuffer: 8 * 1024 * 1024 },
  );
  if (result.status !== 0 || result.error) {
    process.stdout.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`TLC failed for ${moduleName}`, result.error ? { cause: result.error } : undefined);
  }
  process.stdout.write(result.stdout ?? "");
}

/** Run the deliberately unsafe model and require the publication safety invariant to reject it. */
function requireUnsafePublicationRejected() {
  const result = spawnSync(
    "java",
    [
      "-Xmx256m",
      "-XX:+UseParallelGC",
      "-cp",
      jar,
      "tlc2.TLC",
      "-workers",
      "1",
      "-metadir",
      resolve(outputDir, "PublicationUnsafe"),
      "-config",
      "PublicationUnsafe.cfg",
      "PublicationUnsafe.tla",
    ],
    { cwd: formalDir, encoding: "utf8", timeout: 30_000, maxBuffer: 8 * 1024 * 1024 },
  );
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (!/Invariant SnapshotNeverBroaderThanSource is violated/u.test(output)) {
    process.stdout.write(output);
    throw new Error("Unsafe publication mutation did not violate SnapshotNeverBroaderThanSource");
  }
  console.log("TLC mutation guard: deny-before-source invariant rejects direct source replacement.");
}

runModel("Publication", "Publication.cfg");
runModel("TemporalEvaluation", "TemporalEvaluation.cfg");
runModel("RequestApproval", "RequestApproval.cfg");
requireUnsafePublicationRejected();
