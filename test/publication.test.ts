import { describe, expect, it } from "vitest";
import {
  compileAccessSnapshot,
  createAccessEvaluator,
  defineAccessCatalog,
  publishAccessChange,
  recoverAccessSnapshot,
  type AccessPublicationAdapter,
  type EffectiveAccessSnapshot,
} from "../src/index.js";

type Permission = "read" | "write";
type Source = { grants: Permission[] };
type Snapshot = EffectiveAccessSnapshot<Permission, never, string>;

/** Tiny catalog used to inject crashes at every durable publication boundary. */
const catalog = defineAccessCatalog<Permission, Permission, never>({
  catalogId: "publication-test",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["read", "write"],
  leaves: ["read", "write"],
  scopeDimensions: { read: [], write: [] },
  includes: (granted, requested) => granted === requested,
});

/** Build one in-memory durable adapter that can crash immediately after a selected durable write. */
function createAdapter(crashAfter: "deny" | "source" | "final" | undefined) {
  let source = { revision: "1", source: { grants: ["read", "write"] as Permission[] } };
  let snapshot: Snapshot = compileAccessSnapshot(catalog, {
    grants: source.source.grants.map((permission) => ({ permission })),
    sourceRevision: source.revision,
  });
  let snapshotWrites = 0;
  const adapter: AccessPublicationAdapter<Source, Snapshot> = {
    async withSubjectLock(_subjectId, work) {
      return work();
    },
    async readSource() {
      return source;
    },
    async compareAndSetSource(_subjectId, expectedRevision, nextSource) {
      if (source.revision !== expectedRevision) throw new Error("revision mismatch");
      source = { revision: String(Number(source.revision) + 1), source: nextSource };
      if (crashAfter === "source") throw new Error("crash after source write");
      return source;
    },
    async writeSnapshot(_subjectId, nextSnapshot) {
      snapshot = nextSnapshot;
      snapshotWrites += 1;
      if (crashAfter === "deny" && snapshotWrites === 1) throw new Error("crash after deny write");
      if (crashAfter === "final" && snapshotWrites === 2) throw new Error("crash after final write");
    },
  };
  return {
    adapter,
    state() {
      return { source, snapshot };
    },
  };
}

/** Convert the application source into the source grants consumed by the generic compiler. */
function compileSource(source: Source) {
  return { grants: source.grants.map((permission) => ({ permission })) };
}

describe("fail-closed publication", () => {
  for (const crashAfter of ["deny", "source", "final"] as const) {
    it(`never exposes removed write authority after a ${crashAfter} crash`, async () => {
      const fixture = createAdapter(crashAfter);
      await expect(
        publishAccessChange({
          catalog,
          adapter: fixture.adapter,
          subjectId: "u1",
          expectedSourceRevision: "1",
          nextSource: { grants: ["read"] },
          compileSource,
        }),
      ).rejects.toThrow(/crash/);

      const state = fixture.state();
      expect(
        state.snapshot.grants.every((grant) =>
          state.source.source.grants.includes(grant.permission),
        ),
      ).toBe(true);
    });
  }

  it("recovers a deny snapshot from the current durable source", async () => {
    const fixture = createAdapter("source");
    await expect(
      publishAccessChange({
        catalog,
        adapter: fixture.adapter,
        subjectId: "u1",
        expectedSourceRevision: "1",
        nextSource: { grants: ["read"] },
        compileSource,
      }),
    ).rejects.toThrow();

    const recovered = await recoverAccessSnapshot(catalog, fixture.adapter, "u1", compileSource);
    const evaluator = createAccessEvaluator(catalog);
    expect(evaluator.can(recovered, "read")).toBe(true);
    expect(evaluator.can(recovered, "write")).toBe(false);
  });
});
