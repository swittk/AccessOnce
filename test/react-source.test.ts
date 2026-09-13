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
    source.setSnapshot(first);
    expect(listener).not.toHaveBeenCalled();
    source.setSnapshot(second);
    expect(listener).toHaveBeenCalledOnce();
    expect(source.getSnapshot()).toBe(second);

    unsubscribe();
    source.setSnapshot(undefined);
    expect(listener).toHaveBeenCalledOnce();
  });
});
