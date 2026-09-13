import { describe, expect, it } from "vitest";
import {
  createAccess,
  createAccessControlPlane,
  type AccessPublicationAdapter,
  type EffectiveAccessSnapshot,
} from "../src/index.js";

type Permission = "read" | "write";
type Source = { grants: Permission[] };
type Snapshot = EffectiveAccessSnapshot<Permission, never, string>;

/** Access model used to show the control plane needs no database-specific assignment shape. */
const access = createAccess<Permission, Permission, never>({
  catalogId: "control-test",
  catalogVersion: 1,
  compilerVersion: 1,
  permissions: ["read", "write"],
  leaves: ["read", "write"],
  scopeDimensions: { read: [], write: [] },
  includes(granted, requested) {
    return granted === requested;
  },
});

/** Create one in-memory source/snapshot store implementing the BYO durable control-plane contract. */
function createStore() {
  let versioned = { revision: "1", source: { grants: ["read"] as Permission[] } };
  let snapshot: Snapshot | undefined;
  const adapter: AccessPublicationAdapter<Source, Snapshot> = {
    async withSubjectLock(_subjectId, work) {
      return work();
    },
    async readSource() {
      return versioned;
    },
    async compareAndSetSource(_subjectId, expectedRevision, source) {
      if (versioned.revision !== expectedRevision) throw new Error("revision mismatch");
      versioned = { revision: String(Number(versioned.revision) + 1), source };
      return versioned;
    },
    async writeSnapshot(_subjectId, nextSnapshot) {
      snapshot = nextSnapshot;
    },
  };
  return {
    adapter,
    state() {
      return { versioned, snapshot };
    },
  };
}

describe("access control plane", () => {
  it("wraps read, safe replacement, and rematerialization without prescribing source storage", async () => {
    const store = createStore();
    const control = createAccessControlPlane({
      access,
      adapter: store.adapter,
      compileSource(source: Source) {
        return { grants: source.grants.map((permission) => ({ permission })) };
      },
    });

    await expect(control.read("alice")).resolves.toEqual({
      revision: "1",
      source: { grants: ["read"] },
    });
    const replaced = await control.replace({
      subjectId: "alice",
      expectedRevision: "1",
      source: { grants: ["write"] },
    });
    expect(access.can(replaced, "read")).toBe(false);
    expect(access.can(replaced, "write")).toBe(true);

    const repaired = await control.materialize("alice");
    expect(access.can(repaired, "write")).toBe(true);
    expect(store.state().snapshot).toBe(repaired);
  });
});
