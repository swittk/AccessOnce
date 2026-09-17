import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AccessEvaluator } from "../src/runtime.js";

const reactProbe = vi.hoisted(() => ({
  serverSnapshot: undefined as unknown,
  renderServerSnapshot: false,
}));

vi.mock("react", () => ({
  useMemo<Value>(factory: () => Value): Value {
    return factory();
  },
  useSyncExternalStore<Value>(
    subscribe: (listener: () => void) => () => void,
    getSnapshot: () => Value,
    getServerSnapshot: () => Value,
  ): Value {
    const unsubscribe = subscribe(() => undefined);
    unsubscribe();
    reactProbe.serverSnapshot = getServerSnapshot();
    return reactProbe.renderServerSnapshot ? getServerSnapshot() : getSnapshot();
  },
}));

const { createReactAccess } = await import("../src/react.js");

type Snapshot = { revision: number };
type Permission = "record.read";
type Dimension = "location";

/** Class-style transport source proves AccessOnce keeps method receivers instead of requiring arrow functions. */
class ReceiverCheckingSource {
  /** Current snapshot returned by both client and server getters. */
  current: Snapshot | undefined;
  /** Instance that every source callback must keep as its receiver. */
  expectedReceiver: ReceiverCheckingSource | undefined;

  constructor(snapshot: Snapshot) {
    this.current = snapshot;
  }

  /** Return the client snapshot only when the method receiver was preserved. */
  getSnapshot(): Snapshot | undefined {
    expect(this).toBe(this.expectedReceiver);
    return this.current;
  }

  /** Return the server snapshot only when the method receiver was preserved. */
  getServerSnapshot(): Snapshot | undefined {
    expect(this).toBe(this.expectedReceiver);
    return this.current;
  }

  /** Subscribe only when the method receiver was preserved. */
  subscribe(_listener: () => void): () => void {
    expect(this).toBe(this.expectedReceiver);
    return () => undefined;
  }
}

describe("React access binding", () => {
  beforeEach(() => {
    reactProbe.renderServerSnapshot = false;
    reactProbe.serverSnapshot = undefined;
  });

  it("fails closed during SSR when a custom source omits getServerSnapshot", () => {
    const snapshot = { revision: 1 };
    const source = {
      getSnapshot: () => snapshot,
      subscribe: () => () => undefined,
    };
    const evaluator: AccessEvaluator<Snapshot, Permission, Dimension> = {
      can: () => true,
      hasAny: () => true,
      allowedValues: () => ({ kind: "all" }),
      queryPlan: () => ({ kind: "all" }),
    };

    reactProbe.renderServerSnapshot = true;
    const access = createReactAccess(evaluator, source).useAccess();
    expect(reactProbe.serverSnapshot).toBeUndefined();
    expect(access.ready).toBe(false);
    expect(access.can("record.read", { location: "site-a" })).toBe(false);
  });

  it("preserves this for class/object snapshot sources", () => {
    const snapshot = { revision: 1 };
    const source = new ReceiverCheckingSource(snapshot);
    source.expectedReceiver = source;
    const evaluator: AccessEvaluator<Snapshot, Permission, Dimension> = {
      can() {
        return true;
      },
      hasAny() {
        return true;
      },
      allowedValues() {
        return { kind: "all" };
      },
      queryPlan() {
        return { kind: "all" };
      },
    };

    const access = createReactAccess(evaluator, source).useAccess();
    expect(access.ready).toBe(true);
    expect(access.can("record.read", { location: "site-a" })).toBe(true);
  });
});
