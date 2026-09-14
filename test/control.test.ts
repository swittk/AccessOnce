import { describe, expect, it } from "vitest";
import {
  createAccess,
  createAccessControlPlane,
  createAccessPublicationControlPlane,
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
    expect(replaced.revision).toBe("2");
    expect(access.can(replaced.snapshot, "read")).toBe(false);
    expect(access.can(replaced.snapshot, "write")).toBe(true);

    const repaired = await control.materialize("alice");
    expect(repaired.revision).toBe("2");
    expect(access.can(repaired.snapshot, "write")).toBe(true);
    expect(store.state().snapshot).toBe(repaired.snapshot);
  });

  it("publishes an application-owned snapshot shape through the same deny-first control plane", async () => {
    type CustomSnapshot = {
      kind: "app-snapshot";
      revision: string;
      grants: readonly string[];
      denied: boolean;
    };
    let source: { revision: string; source: Source } = {
      revision: "7",
      source: { grants: ["read", "write"] },
    };
    let snapshot: CustomSnapshot = {
      kind: "app-snapshot",
      revision: "7",
      grants: ["read", "write"],
      denied: false,
    };
    const control = createAccessPublicationControlPlane<Source, CustomSnapshot>({
      adapter: {
        async withSubjectLock(_subjectId, work) {
          return work();
        },
        async readSource() {
          return source;
        },
        async compareAndSetSource(_subjectId, expectedRevision, nextSource) {
          if (source.revision !== expectedRevision) {
            throw new Error("revision mismatch");
          }
          source = { revision: "8", source: nextSource };
          return source;
        },
        async writeSnapshot(_subjectId, nextSnapshot) {
          snapshot = nextSnapshot;
        },
      },
      publication: {
        deny({ current }) {
          return {
            kind: "app-snapshot",
            revision: `pending:${current.revision}`,
            grants: [],
            denied: true,
          };
        },
        compile({ source: nextSource, sourceRevision }) {
          return {
            kind: "app-snapshot",
            revision: sourceRevision,
            grants: nextSource.grants,
            denied: false,
          };
        },
      },
    });

    const replaced = await control.replace({
      subjectId: "alice",
      expectedRevision: "7",
      source: { grants: ["read"] },
    });
    expect(replaced).toEqual({
      revision: "8",
      snapshot: {
        kind: "app-snapshot",
        revision: "8",
        grants: ["read"],
        denied: false,
      },
    });
    expect(snapshot).toEqual(replaced.snapshot);
    const repaired = await control.materialize("alice");
    expect(repaired.revision).toBe("8");
    expect(repaired.snapshot.revision).toBe("8");
  });
});
