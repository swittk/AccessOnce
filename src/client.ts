/** Transport that obtains one server-produced effective snapshot for a stable application subject. */
export type AccessSnapshotTransport<Subject, Snapshot> = {
  /** Load the subject's current effective snapshot; undefined means loaded but no usable snapshot exists. */
  read(subject: Subject, signal: AbortSignal): Promise<Snapshot | undefined>;
  /** Optional push/live invalidation hook; call the listener when the subject should be reloaded. */
  subscribeInvalidations?(
    subject: Subject,
    invalidate: () => void,
  ): () => void;
};

/** No subject is selected, so the client exposes no authority. */
export type AccessSnapshotIdleState = {
  /** Stable discriminator for a cleared/unselected client. */
  status: "idle";
};

/** One selected subject is loading; snapshot access fails closed until completion. */
export type AccessSnapshotLoadingState = {
  /** Stable discriminator for an in-flight snapshot load. */
  status: "loading";
};

/** The selected subject finished loading, including the valid no-snapshot case. */
export type AccessSnapshotReadyState<Snapshot> = {
  /** Stable discriminator for a completed snapshot load. */
  status: "ready";
  /** Server-produced effective snapshot; undefined means the backend deliberately returned none. */
  snapshot: Snapshot | undefined;
};

/** The selected subject failed to load; no snapshot remains usable. */
export type AccessSnapshotErrorState = {
  /** Stable discriminator for a failed snapshot load. */
  status: "error";
  /** Transport/backend failure retained for diagnostics and UI messaging. */
  error: unknown;
};

/** Fail-closed client bootstrap state for one selected subject. */
export type AccessSnapshotClientState<Snapshot> =
  | AccessSnapshotIdleState
  | AccessSnapshotLoadingState
  | AccessSnapshotReadyState<Snapshot>
  | AccessSnapshotErrorState;

/** Minimal external-store shape exposing the current effective snapshot to UI/framework bindings. */
export type AccessSnapshotSource<Snapshot> = {
  /** Return the current usable snapshot, or undefined while unavailable/fail-closed. */
  getSnapshot(): Snapshot | undefined;
  /** Optional server-render snapshot getter; clients can use the same fail-closed value. */
  getServerSnapshot?(): Snapshot | undefined;
  /** Subscribe to effective-snapshot replacement. */
  subscribe(listener: () => void): () => void;
};

/** Framework-neutral effective-snapshot client usable by Zustand, React, Vue, Electron, or plain JS. */
export type AccessSnapshotClient<Subject, Snapshot> = AccessSnapshotSource<Snapshot> & {
  /** Return the current bootstrap state. */
  getState(): AccessSnapshotClientState<Snapshot>;
  /** Stable deny-by-default state for server rendering and the first hydration render. */
  getServerState(): AccessSnapshotClientState<Snapshot>;
  /** Include this small epoch in permission-dependent query keys; it changes before refresh/logout can expose old data. */
  getCacheKey(): number;
  /** Select a new subject and load it immediately; selecting undefined clears authority. */
  setSubject(subject: Subject | undefined): Promise<Snapshot | undefined>;
  /** Reload the currently selected subject. */
  refresh(): Promise<Snapshot | undefined>;
  /** Reload only when this edited subject is the current selection; editing somebody else performs no extra fetch. */
  refreshForSubject(subject: Subject): Promise<Snapshot | undefined>;
  /** Stop in-flight work and push invalidations; the client returns to idle. */
  dispose(): void;
};

/** Options controlling one transport-neutral effective-snapshot client. */
export type CreateAccessSnapshotClientOptions<Subject, Snapshot> = {
  /** Backend/wire adapter that loads snapshots and optionally signals invalidation. */
  transport: AccessSnapshotTransport<Subject, Snapshot>;
  /** Stable identity key; defaults to subject itself and therefore works best with primitive subject ids. */
  subjectKey?(subject: Subject): unknown;
};

/** Create a fail-closed snapshot client that suppresses stale responses across login/session changes. */
export function createAccessSnapshotClient<Subject, Snapshot>(
  options: CreateAccessSnapshotClientOptions<Subject, Snapshot>,
): AccessSnapshotClient<Subject, Snapshot> {
  const serverState: AccessSnapshotIdleState = Object.freeze({ status: "idle" });
  let state: AccessSnapshotClientState<Snapshot> = serverState;
  let subject: Subject | undefined;
  let subjectKey: unknown;
  let loadEpoch = 0;
  let abortController: AbortController | undefined;
  let unsubscribeInvalidations: (() => void) | undefined;
  let disposed = false;
  const listeners = new Set<() => void>();

  /** Notify subscribers only after the complete next state is visible. */
  function publish(next: AccessSnapshotClientState<Snapshot>) {
    if (state === next) return;
    state = Object.freeze(next);
    for (const listener of [...listeners]) listener();
  }

  /** Cancel the prior subject/read without assuming the transport honors AbortSignal. */
  function cancelCurrentWork() {
    loadEpoch += 1;
    abortController?.abort();
    abortController = undefined;
  }

  /** Remove the old subject's push invalidation hook before selecting another subject. */
  function unsubscribeCurrentSubject() {
    const unsubscribe = unsubscribeInvalidations;
    unsubscribeInvalidations = undefined;
    unsubscribe?.();
  }

  /** Load one exact subject selection; epoch+key checks suppress transports that resolve after abort. */
  async function loadSelectedSubject(): Promise<Snapshot | undefined> {
    if (disposed || subject === undefined) {
      if (!disposed) publish({ status: "idle" });
      return undefined;
    }

    cancelCurrentWork();
    const epoch = loadEpoch;
    const loadingSubject = subject;
    const loadingKey = subjectKey;
    const controller = new AbortController();
    abortController = controller;
    if (state.status !== "loading") publish({ status: "loading" });
    try {
      const snapshot = await options.transport.read(loadingSubject, controller.signal);
      if (
        disposed ||
        epoch !== loadEpoch ||
        !Object.is(loadingKey, subjectKey)
      ) {
        return undefined;
      }
      abortController = undefined;
      publish({ status: "ready", snapshot });
      return snapshot;
    } catch (error) {
      if (
        disposed ||
        epoch !== loadEpoch ||
        !Object.is(loadingKey, subjectKey)
      ) {
        return undefined;
      }
      abortController = undefined;
      publish({ status: "error", error });
      return undefined;
    }
  }

  /** Install push invalidation after selecting a subject; refresh remains transport-owned pull logic. */
  function subscribeSelectedSubject() {
    if (!options.transport.subscribeInvalidations || subject === undefined) return;
    const subscribedKey = subjectKey;
    unsubscribeInvalidations = options.transport.subscribeInvalidations(subject, () => {
      if (disposed || !Object.is(subscribedKey, subjectKey)) return;
      // Refresh reports failures through state, so an invalidation callback never needs its own catch path.
      void loadSelectedSubject();
    });
  }

  return {
    getState() {
      return state;
    },
    getServerState() {
      return serverState;
    },
    getCacheKey() {
      return loadEpoch;
    },
    getSnapshot() {
      return state.status === "ready" ? state.snapshot : undefined;
    },
    getServerSnapshot() {
      // A browser/session singleton must not hydrate another request with its last loaded user's authority.
      return undefined;
    },
    subscribe(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    async setSubject(nextSubject) {
      if (disposed) throw new Error("Access snapshot client is disposed");
      let nextKey: unknown;
      try {
        nextKey =
          nextSubject === undefined
            ? undefined
            : (options.subjectKey?.(nextSubject) ?? nextSubject);
      } catch (error) {
        cancelCurrentWork();
        subject = undefined;
        subjectKey = undefined;
        publish({ status: "error", error });
        try {
          unsubscribeCurrentSubject();
        } catch {
          // The stale callback is already detached locally; preserve the subject-key failure as the visible error.
        }
        return undefined;
      }
      if (nextSubject !== undefined && Object.is(nextKey, subjectKey)) {
        subject = nextSubject;
        return loadSelectedSubject();
      }

      cancelCurrentWork();
      subject = nextSubject;
      subjectKey = nextKey;
      // Drop the old user's snapshot before calling BYO subscription code: opening or closing it can throw.
      // The following read reuses this loading state, so a selection still emits only loading -> ready.
      publish(nextSubject === undefined ? serverState : { status: "loading" });
      try {
        unsubscribeCurrentSubject();
        if (nextSubject === undefined) return undefined;
        subscribeSelectedSubject();
      } catch (error) {
        cancelCurrentWork();
        // A retry of this same subject must reinstall push invalidation instead of taking the same-key fast path.
        subjectKey = undefined;
        publish({ status: "error", error });
        return undefined;
      }
      return loadSelectedSubject();
    },
    refresh() {
      if (disposed) return Promise.reject(new Error("Access snapshot client is disposed"));
      return loadSelectedSubject();
    },
    refreshForSubject(editedSubject) {
      if (disposed) return Promise.reject(new Error("Access snapshot client is disposed"));
      let editedKey: unknown;
      try {
        editedKey = options.subjectKey?.(editedSubject) ?? editedSubject;
      } catch (error) {
        return Promise.reject(error);
      }
      if (subject === undefined || !Object.is(editedKey, subjectKey)) return Promise.resolve(undefined);
      return loadSelectedSubject();
    },
    dispose() {
      if (disposed) return;
      disposed = true;
      cancelCurrentWork();
      subject = undefined;
      subjectKey = undefined;
      // Disposal clears authority even when an external unsubscribe function fails.
      publish(serverState);
      try {
        unsubscribeCurrentSubject();
      } finally {
        listeners.clear();
      }
    },
  };
}
