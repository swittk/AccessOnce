import {
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from "react";
import type { AccessSnapshotSource } from "./client.js";
import type { AccessEvaluator } from "./runtime.js";
import type { AccessContext } from "./types.js";

/** React-facing alias of the core framework-neutral effective-snapshot source contract. */
export type ReactAccessSnapshotSource<Snapshot> = AccessSnapshotSource<Snapshot>;

/** Tiny mutable source useful for REST, RPC, WebSocket, Electron IPC, or test bootstrap adapters. */
export type MutableReactAccessSource<Snapshot> = ReactAccessSnapshotSource<Snapshot> & {
  /** Replace the current snapshot and notify subscribers exactly once. */
  setSnapshot(snapshot: Snapshot | undefined): void;
};

/** Create a transport-neutral snapshot source without tying AccessOnce to Zustand or another state library. */
export function createMutableReactAccessSource<Snapshot>(
  initialSnapshot?: Snapshot,
): MutableReactAccessSource<Snapshot> {
  let snapshot = initialSnapshot;
  const listeners = new Set<() => void>();
  return {
    getSnapshot() {
      return snapshot;
    },
    getServerSnapshot() {
      // A mutable source can outlive one SSR request; never reuse its client authority on the server.
      return undefined;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    setSnapshot(nextSnapshot) {
      if (Object.is(snapshot, nextSnapshot)) return;
      snapshot = nextSnapshot;
      for (const listener of listeners) listener();
    },
  };
}

/** Props accepted by a React guard bound to one AccessOnce evaluator/source pair. */
export type AccessGuardProps<Leaf extends string, Dimension extends string> = {
  /** Concrete permission required to render children. */
  permission: Leaf;
  /** Optional trusted UI context such as selected location/assignee/resource. */
  context?: AccessContext<Dimension>;
  /** Content rendered when access is ready and allowed. */
  children: ReactNode;
  /** Content rendered while denied or before bootstrap completes. */
  fallback?: ReactNode;
};

/** Bind one evaluator and transport source into SSR-safe React hooks and a small guard component. */
export function createReactAccess<Snapshot, Leaf extends string, Dimension extends string>(
  evaluator: AccessEvaluator<Snapshot, Leaf, Dimension>,
  source: ReactAccessSnapshotSource<Snapshot>,
) {
  /** Subscribe through the source object so class/object transports keep their method receiver. */
  const subscribe = (listener: () => void) => source.subscribe(listener);
  /** Read the client snapshot through the source object without allocating inside render. */
  const getSnapshot = () => source.getSnapshot();
  /** Read the server snapshot with the same receiver-preserving rule and client fallback. */
  const getServerSnapshot = () =>
    source.getServerSnapshot ? source.getServerSnapshot() : source.getSnapshot();

  /** Subscribe once and expose a memoized multi-check facade for one render tree. */
  function useAccess() {
    const snapshot = useSyncExternalStore(
      subscribe,
      getSnapshot,
      getServerSnapshot,
    );
    return useMemo(
      () => ({
        ready: snapshot !== undefined,
        can(permission: Leaf, context?: AccessContext<Dimension>) {
          return snapshot !== undefined && evaluator.can(snapshot, permission, context);
        },
        hasAny(permission: Leaf) {
          return snapshot !== undefined && evaluator.hasAny(snapshot, permission);
        },
        allowedValues(
          permission: Leaf,
          dimension: Dimension,
          options?: import("./runtime.js").AccessProjectionOptions<Dimension>,
        ) {
          return snapshot === undefined
            ? ({ kind: "none" } as const)
            : evaluator.allowedValues(snapshot, permission, dimension, options);
        },
      }),
      [snapshot],
    );
  }

  /** Render children only when the bound snapshot permits this concrete action. */
  function AccessGuard(props: AccessGuardProps<Leaf, Dimension>): ReactNode {
    const access = useAccess();
    return access.can(props.permission, props.context) ? props.children : (props.fallback ?? null);
  }

  return { useAccess, AccessGuard };
}
