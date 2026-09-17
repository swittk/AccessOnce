import { describe, expect, it, vi } from "vitest";
import { createMutableReactAccessSource } from "../src/react.js";

describe("React snapshot source", () => {
  it("works as a transport-neutral external store and skips same-object churn", () => {
    const first = { revision: 1 };
    const second = { revision: 2 };
    const source = createMutableReactAccessSource(first);
    const listener = vi.fn();
    const unsubscribe = source.subscribe(listener);

    expect(source.getSnapshot()).toBe(first);
    expect(source.getServerSnapshot?.()).toBeUndefined();
    source.setSnapshot(first);
    expect(listener).not.toHaveBeenCalled();
    source.setSnapshot(second);
    expect(listener).toHaveBeenCalledOnce();
    expect(source.getSnapshot()).toBe(second);
    expect(source.getServerSnapshot?.()).toBeUndefined();

    unsubscribe();
    source.setSnapshot(undefined);
    expect(listener).toHaveBeenCalledOnce();
  });
  it("notifies each listener present at dispatch start at most once", () => {
    const source = createMutableReactAccessSource({ revision: 1 });
    let unsubscribe: () => void = () => undefined;
    const listener = vi.fn(() => {
      if (listener.mock.calls.length !== 1) return;
      unsubscribe();
      unsubscribe = source.subscribe(listener);
    });
    unsubscribe = source.subscribe(listener);

    source.setSnapshot({ revision: 2 });

    expect(listener).toHaveBeenCalledOnce();
    unsubscribe();
  });

});
