import { describe, expect, it, vi } from "vitest";
import { createAccessSnapshotClient } from "../src/client.js";

/** Promise whose completion is controlled by the test so stale-session ordering can be proven. */
function deferred<Value>() {
  let resolve!: (value: Value) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<Value>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

describe("access snapshot client", () => {
  it("loads one subject and exposes fail-closed bootstrap states", async () => {
    const client = createAccessSnapshotClient({
      transport: {
        async read(subject: string) {
          return { subject, revision: 1 };
        },
      },
    });
    const listener = vi.fn();
    client.subscribe(listener);

    expect(client.getState()).toEqual({ status: "idle" });
    const pending = client.setSubject("alice");
    expect(client.getState()).toEqual({ status: "loading" });
    expect(client.getSnapshot()).toBeUndefined();
    await expect(pending).resolves.toEqual({ subject: "alice", revision: 1 });
    expect(client.getState()).toEqual({
      status: "ready",
      snapshot: { subject: "alice", revision: 1 },
    });
    expect(listener).toHaveBeenCalledTimes(2);
  });

  it("notifies each subscriber present at a publish start at most once", async () => {
    const client = createAccessSnapshotClient({
      transport: {
        async read(subject: string) {
          return { subject };
        },
      },
    });
    let unsubscribe: () => void = () => undefined;
    const listener = vi.fn(() => {
      if (listener.mock.calls.length !== 1) return;
      unsubscribe();
      unsubscribe = client.subscribe(listener);
    });
    unsubscribe = client.subscribe(listener);

    await client.setSubject("alice");

    expect(listener).toHaveBeenCalledTimes(2);
    unsubscribe();
  });

  it("ignores a late response from the previous login even when the transport ignores abort", async () => {
    const alice = deferred<{ subject: string } | undefined>();
    const bob = deferred<{ subject: string } | undefined>();
    const client = createAccessSnapshotClient({
      transport: {
        read(subject: string) {
          return subject === "alice" ? alice.promise : bob.promise;
        },
      },
    });

    const aliceLoad = client.setSubject("alice");
    const bobLoad = client.setSubject("bob");
    alice.resolve({ subject: "alice" });
    await expect(aliceLoad).resolves.toBeUndefined();
    expect(client.getState()).toEqual({ status: "loading" });
    bob.resolve({ subject: "bob" });
    await expect(bobLoad).resolves.toEqual({ subject: "bob" });
    expect(client.getSnapshot()).toEqual({ subject: "bob" });
  });

  it("fails closed on transport errors but keeps the error inspectable", async () => {
    const failure = new Error("offline");
    const client = createAccessSnapshotClient({
      transport: {
        async read() {
          throw failure;
        },
      },
    });

    await expect(client.setSubject("alice")).resolves.toBeUndefined();
    expect(client.getSnapshot()).toBeUndefined();
    expect(client.getState()).toEqual({ status: "error", error: failure });
  });

  it("refreshes on optional push invalidation and detaches the old subject subscription", async () => {
    let invalidate: (() => void) | undefined;
    const unsubscribe = vi.fn();
    let revision = 0;
    const client = createAccessSnapshotClient({
      transport: {
        async read(subject: string) {
          revision += 1;
          return { subject, revision };
        },
        subscribeInvalidations(_subject, listener) {
          invalidate = listener;
          return unsubscribe;
        },
      },
    });

    await client.setSubject("alice");
    expect(client.getSnapshot()).toEqual({ subject: "alice", revision: 1 });
    invalidate?.();
    await vi.waitFor(() => {
      expect(client.getSnapshot()).toEqual({ subject: "alice", revision: 2 });
    });
    await client.setSubject("bob");
    expect(unsubscribe).toHaveBeenCalledOnce();
    expect(client.getSnapshot()).toEqual({ subject: "bob", revision: 3 });
  });

  it("clears prior authority when subject identity calculation fails", async () => {
    const failure = new Error("invalid subject identity");
    const unsubscribe = vi.fn();
    const client = createAccessSnapshotClient({
      subjectKey(subject: string) {
        if (subject === "broken") throw failure;
        return subject;
      },
      transport: {
        async read(subject: string) {
          return { subject };
        },
        subscribeInvalidations() {
          return unsubscribe;
        },
      },
    });

    await client.setSubject("alice");
    expect(client.getSnapshot()).toEqual({ subject: "alice" });
    await expect(client.setSubject("broken")).resolves.toBeUndefined();
    expect(client.getSnapshot()).toBeUndefined();
    expect(client.getState()).toEqual({ status: "error", error: failure });
    expect(unsubscribe).toHaveBeenCalledOnce();
  });

  it("rejects refreshForSubject asynchronously when subject identity calculation fails", async () => {
    const failure = new Error("invalid edited subject identity");
    const client = createAccessSnapshotClient({
      subjectKey(subject: string) {
        if (subject === "broken") throw failure;
        return subject;
      },
      transport: {
        async read(subject: string) {
          return { subject };
        },
      },
    });

    await client.setSubject("alice");
    let refresh: Promise<{ subject: string } | undefined> | undefined;
    expect(() => {
      refresh = client.refreshForSubject("broken");
    }).not.toThrow();
    await expect(refresh).rejects.toBe(failure);
    expect(client.getSnapshot()).toEqual({ subject: "alice" });
  });

  it("retries push subscription setup for the same subject after a transient failure", async () => {
    const failure = new Error("subscription unavailable");
    let subscriptionAttempts = 0;
    const read = vi.fn(async (subject: string) => ({ subject }));
    const client = createAccessSnapshotClient({
      transport: {
        read,
        subscribeInvalidations() {
          subscriptionAttempts += 1;
          if (subscriptionAttempts === 1) throw failure;
          return () => undefined;
        },
      },
    });

    await expect(client.setSubject("alice")).resolves.toBeUndefined();
    expect(client.getState()).toEqual({ status: "error", error: failure });
    expect(read).not.toHaveBeenCalled();

    await expect(client.setSubject("alice")).resolves.toEqual({ subject: "alice" });
    expect(subscriptionAttempts).toBe(2);
    expect(read).toHaveBeenCalledOnce();
    expect(client.getSnapshot()).toEqual({ subject: "alice" });
  });

  it("clears authority immediately on logout", async () => {
    const client = createAccessSnapshotClient({
      transport: {
        async read(subject: string) {
          return { subject };
        },
      },
    });
    await client.setSubject("alice");
    await client.setSubject(undefined);
    expect(client.getState()).toEqual({ status: "idle" });
    expect(client.getSnapshot()).toBeUndefined();
  });
});


it("does not expose a loaded browser subject through the default server snapshot", async () => {
  const client = createAccessSnapshotClient({
    transport: { async read(subject: string) { return { subject }; } },
  });
  await client.setSubject("alice");
  expect(client.getSnapshot()).toEqual({ subject: "alice" });
  expect(client.getServerSnapshot?.()).toBeUndefined();
});


it("changes query identity before refresh, subject changes, and logout without keying on the whole snapshot", async () => {
  const client = createAccessSnapshotClient({
    transport: { async read(subject: string) { return { subject }; } },
  });
  const serverState = client.getServerState();
  const idleKey = client.getCacheKey();
  await client.setSubject("alice");
  const aliceKey = client.getCacheKey();
  expect(aliceKey).toBeGreaterThan(idleKey);
  expect(client.getCacheKey()).toBe(aliceKey);
  const refresh = client.refresh();
  expect(client.getCacheKey()).toBeGreaterThan(aliceKey);
  await refresh;
  const refreshedKey = client.getCacheKey();
  await client.setSubject(undefined);
  expect(client.getCacheKey()).toBeGreaterThan(refreshedKey);
  expect(client.getServerState()).toBe(serverState);
  expect(serverState).toEqual({ status: "idle" });
  expect(Object.isFrozen(client.getState())).toBe(true);
});

for (const failingStep of ["subscribe", "unsubscribe"] as const) {
  it(`clears the previous user's authority when ${failingStep} fails during a session change`, async () => {
    const failure = new Error("Live subscription disconnected");
    const client = createAccessSnapshotClient({
      transport: {
        async read(subject: string) { return { subject }; },
        subscribeInvalidations(subject: string) {
          if (failingStep === "subscribe" && subject === "bob") throw failure;
          return () => {
            if (failingStep === "unsubscribe" && subject === "alice") throw failure;
          };
        },
      },
    });
    await client.setSubject("alice");
    expect(client.getSnapshot()).toEqual({ subject: "alice" });
    // Both transports may throw synchronously. The old user's ready snapshot must already be gone.
    await client.setSubject("bob").catch(() => undefined);
    expect(client.getSnapshot()).toBeUndefined();
    expect(client.getState()).toMatchObject({ status: "error", error: failure });
  });
}
