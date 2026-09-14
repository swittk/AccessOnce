import { describe, expect, it } from "vitest";
import {
  createAccessGrantControlClient,
  createAccessGrantChanges,
  applyAccessGrantMutations,
  composeAccessGrants,
  createAccessGrantControlPlane,
  createHierarchicalAccess,
  type AccessControlMutationRequest,
  type AccessGrant,
  type AccessGrantMutation,
  type AccessGrantControlState,
  type AccessPublicationAdapter,
  type EffectiveAccessSnapshot,
} from "../src/index.js";

type Permission = "*" | "record" | "record.read" | "record.write" | "billing.read";
type Leaf = "record.read" | "record.write" | "billing.read";
type Dimension = "location" | "resource";
type Grant = AccessGrant<Permission, Dimension>;
type Source = { grants: readonly Grant[] };
type Snapshot = EffectiveAccessSnapshot<Leaf, Dimension, string>;

/** Small hierarchical model used to exercise frontend/backend grant mutation wire semantics. */
const access = createHierarchicalAccess({
  catalogId: "control-wire-test",
  catalogVersion: 1,
  compilerVersion: 1,
  wildcard: "*",
  permissions: ["*", "record", "record.read", "record.write", "billing.read"] as const,
  leaves: ["record.read", "record.write", "billing.read"] as const,
  scopeDimensions: {
    "record.read": ["location", "resource"],
    "record.write": ["location", "resource"],
    "billing.read": ["location"],
  },
});

/** Create one in-memory durable source/snapshot store with monotonic string revisions. */
function createFixture(initialGrants: readonly Grant[]) {
  let source = { revision: "1", source: { grants: initialGrants } };
  let snapshot: Snapshot = access.compile({
    grants: initialGrants,
    sourceRevision: source.revision,
  });
  const publication: AccessPublicationAdapter<Source, Snapshot> = {
    async withSubjectLock(_subjectId, work) {
      return work();
    },
    async readSource() {
      return source;
    },
    async compareAndSetSource(_subjectId, expectedRevision, nextSource) {
      if (source.revision !== expectedRevision) throw new Error("revision mismatch");
      source = {
        revision: String(Number(source.revision) + 1),
        source: nextSource,
      };
      return source;
    },
    async writeSnapshot(_subjectId, nextSnapshot) {
      snapshot = nextSnapshot;
    },
  };
  const control = createAccessGrantControlPlane({
    access,
    adapter: publication,
    compileSource(nextSource) {
      return { grants: nextSource.grants };
    },
    source: {
      grants(nextSource) {
        return nextSource.grants;
      },
      withGrants(nextSource, grants) {
        return { ...nextSource, grants };
      },
    },
  });
  return {
    control,
    state() {
      return { source, snapshot };
    },
  };
}

/** Create one scoped grant with concise test syntax. */
function grant(permission: Permission, location?: string): Grant {
  return location
    ? { permission, scope: { location: { kind: "ids", ids: [location] } } }
    : { permission };
}

describe("grant control wire", () => {
  it("applies ordered add/remove-permissions mutations atomically and returns the next revision", async () => {
    const fixture = createFixture([
      grant("record.read", "a"),
      grant("billing.read"),
    ]);

    await expect(fixture.control.grants.read({ subjectId: "alice" })).resolves.toEqual({
      revision: "1",
      grants: [grant("record.read", "a"), grant("billing.read")],
    });

    const result = await fixture.control.grants.mutate({
      subjectId: "alice",
      expectedRevision: "1",
      mutations: [
        {
          operation: "add",
          grants: [
            grant("record.write", "b"),
            { permission: "record.read", scope: { location: { kind: "ids", ids: ["a", "a"] } } },
          ],
        },
        { operation: "remove-permissions", permissions: ["billing.read"] },
      ],
    });

    expect(result.revision).toBe("2");
    expect(result.grants).toEqual([
      grant("record.read", "a"),
      grant("record.write", "b"),
    ]);
    expect(fixture.state().source.source.grants).toEqual(result.grants);
    expect(access.can(fixture.state().snapshot, "record.write", { location: "b" })).toBe(true);
    expect(access.can(fixture.state().snapshot, "billing.read")).toBe(false);
  });

  it("removes only the exact scoped grant while preserving the same permission at another scope", async () => {
    const fixture = createFixture([
      grant("record.read", "a"),
      grant("record.read", "b"),
    ]);

    const result = await fixture.control.grants.mutate({
      subjectId: "alice",
      expectedRevision: "1",
      mutations: [{ operation: "remove", grants: [grant("record.read", "a")] }],
    });

    expect(result.grants).toEqual([grant("record.read", "b")]);
  });

  it("rejects stale or malformed frontend mutation input before broadening authority", async () => {
    const fixture = createFixture([grant("record.read", "a")]);
    await expect(
      fixture.control.grants.mutate({
        subjectId: "alice",
        expectedRevision: "stale",
        mutations: [{ operation: "add", grants: [grant("record.write", "b")] }],
      }),
    ).rejects.toThrow(/changed since this edit loaded/);

    await expect(
      fixture.control.grants.mutate({
        subjectId: "alice",
        expectedRevision: "1",
        mutations: [{ operation: "add", grants: [{ permission: "made.up" }] }],
      }),
    ).rejects.toThrow(/assignable catalog permission/);

    expect(fixture.state().source.revision).toBe("1");
    expect(fixture.state().source.source.grants).toEqual([grant("record.read", "a")]);
  });

  it("lets frontend helpers send single, multi, exact-remove, permission-remove, and replace operations", async () => {
    type Mutation = AccessGrantMutation<Permission, Dimension>;
    type Response = AccessGrantControlState<Permission, Dimension>;
    const requests: AccessControlMutationRequest<Mutation>[] = [];
    const client = createAccessGrantControlClient<Permission, Dimension>({
      transport: {
        async read() {
          return { revision: "1", grants: [] } satisfies Response;
        },
        async mutate(request) {
          requests.push(request);
          return { revision: "next", grants: [] } satisfies Response;
        },
      },
    });

    await expect(client.read({ subjectId: "alice" })).resolves.toEqual({
      revision: "1",
      grants: [],
    });
    await client.add({
      subjectId: "alice",
      expectedRevision: "1",
      values: grant("record.read", "a"),
    });
    await client.add({
      subjectId: "alice",
      expectedRevision: "2",
      values: [grant("record.read", "a"), grant("record.write", "b")],
    });
    await client.remove({
      subjectId: "alice",
      expectedRevision: "3",
      values: grant("record.read", "a"),
    });
    await client.removePermissions({
      subjectId: "alice",
      expectedRevision: "4",
      values: ["record.read", "record.write"],
    });
    await client.replace({
      subjectId: "alice",
      expectedRevision: "5",
      grants: [grant("billing.read")],
    });

    expect(requests.map((request) => request.mutations[0]?.operation)).toEqual([
      "add",
      "add",
      "remove",
      "remove-permissions",
      "replace",
    ]);
    expect(requests[0]?.mutations[0]).toEqual({
      operation: "add",
      grants: [grant("record.read", "a")],
    });
    expect(requests[1]?.mutations[0]).toEqual({
      operation: "add",
      grants: [grant("record.read", "a"), grant("record.write", "b")],
    });
  });

  it("supports several different mutations in one frontend request", async () => {
    type Mutation = AccessGrantMutation<Permission, Dimension>;
    const requests: AccessControlMutationRequest<Mutation>[] = [];
    const client = createAccessGrantControlClient<Permission, Dimension>({
      transport: {
        async read() {
          return { revision: "1", grants: [] };
        },
        async mutate(request) {
          requests.push(request);
          return { revision: "2", grants: [] };
        },
      },
    });

    await client.mutate({
      subjectId: "alice",
      expectedRevision: "1",
      mutations: [
        { operation: "remove-permissions", permissions: ["billing.read"] },
        { operation: "add", grants: [grant("record.write", "b")] },
      ],
    });

    expect(requests).toHaveLength(1);
    expect(requests[0]?.mutations).toHaveLength(2);
  });
});

/** Extra source operation used to prove the grant wire does not force applications into a grant-only editor. */
type ProfileMutation = {
  /** Replace the app's profile membership alongside the grant changes. */
  operation: "set-profiles";
  /** Selected profile ids. */
  profileIds: readonly string[];
};

/** App fields returned intact by the standard mutation client. */
type AssignmentState = AccessGrantControlState<Permission, Dimension> & {
  /** Profile ids are app source data, not something the kernel interprets. */
  profileIds: readonly string[];
};

it("keeps app mutations and app response fields in the same frontend batch", async () => {
  const requests: AccessControlMutationRequest<AccessGrantMutation<Permission, Dimension> | ProfileMutation>[] = [];
  const state: AssignmentState = { revision: "2", grants: [], profileIds: ["approver"] };
  const client = createAccessGrantControlClient<Permission, Dimension, string, ProfileMutation, AssignmentState>({
    transport: {
      async read() { return state; },
      async mutate(request) { requests.push(request); return state; },
    },
  });
  const result = await client.mutate({
    subjectId: "alice", expectedRevision: "1", mutations: [
      { operation: "set-profiles", profileIds: ["approver"] },
      { operation: "add", grants: [grant("record.read", "a")] },
    ],
  });
  expect(result.profileIds).toEqual(["approver"]);
  expect((await client.read({ subjectId: "alice" })).profileIds).toEqual(["approver"]);
  expect(requests).toHaveLength(1);
  expect(requests[0]?.mutations).toHaveLength(2);
});

it("creates a scoped editor diff, ignores reordered ids, and composes additive bundles", () => {
  const first: Grant = { permission: "record.read", scope: { location: { kind: "ids", ids: ["b", "a"] } } };
  const reordered: Grant = { permission: "record.read", scope: { location: { kind: "ids", ids: ["a", "b", "a"] } } };
  expect(createAccessGrantChanges([first], [reordered])).toEqual([]);
  const oldGrants = [first, grant("record.write", "a")];
  const next = [reordered, grant("record.write", "b")];
  const changes = createAccessGrantChanges(oldGrants, next);
  expect(changes.map(change => change.operation)).toEqual(["remove", "add"]);
  expect(applyAccessGrantMutations(oldGrants, changes)).toEqual([first, grant("record.write", "b")]);
  expect(composeAccessGrants([first], [reordered], [grant("billing.read")])).toEqual([first, grant("billing.read")]);
  expect(oldGrants).toEqual([first, grant("record.write", "a")]);
});


it("round-trips temporal grant edits and compares reordered validity windows semantically", async () => {
  const first: Grant = {
    permission: "record.read",
    validity: [
      { startsAtEpochMs: 10, endsAtEpochMs: 20 },
      { startsAtEpochMs: 30, endsAtEpochMs: 40 },
    ],
  };
  const reordered: Grant = {
    permission: "record.read",
    validity: [
      { startsAtEpochMs: 30, endsAtEpochMs: 40 },
      { startsAtEpochMs: 10, endsAtEpochMs: 20 },
    ],
  };
  expect(createAccessGrantChanges([first], [reordered])).toEqual([]);

  const fixture = createFixture([]);
  await fixture.control.grants.mutate({
    subjectId: "alice",
    expectedRevision: "1",
    mutations: [{ operation: "add", grants: [first] }],
  });
  expect(fixture.state().source.source.grants).toEqual([first]);
  expect(access.evaluateAt(fixture.state().snapshot, 15).can("record.read")).toBe(true);
  expect(access.evaluateAt(fixture.state().snapshot, 25).can("record.read")).toBe(false);

  await expect(fixture.control.grants.mutate({
    subjectId: "alice",
    expectedRevision: "2",
    mutations: [{
      operation: "add",
      grants: [{
        permission: "record.read",
        validity: { startsAtEpochMs: 50, endsAtEpochMs: 49 },
      }],
    }],
  })).rejects.toThrow(/start must not be after end/);
});

it("preserves order when mixed batches remove, replace, and add duplicate grants", () => {
  expect(applyAccessGrantMutations([grant("record.read")], [
    { operation: "add", grants: [grant("record.write"), grant("record.write")] },
    { operation: "remove", grants: [grant("record.read")] },
    { operation: "replace", grants: [grant("billing.read")] },
    { operation: "add", grants: [grant("record.read")] },
  ])).toEqual([grant("billing.read"), grant("record.read")]);
});
