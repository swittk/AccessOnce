import { describe, expect, it, vi } from "vitest";
import {
  createAccessRelationshipChanges,
  createAccessRelationshipControlClient,
  parseAccessRelationshipMutationRequest,
  parseAccessRelationshipSubjectsRequest,
} from "../src/index.js";

describe("relationship control client", () => {
  it("lists one bounded object ACL and batches add/remove principals", async () => {
    const listSubjects = vi.fn(async () => ({
      unrestricted: false,
      subjects: [{ principal: { type: "user", id: "alice" } }],
      cursor: "next",
    }));
    const mutate = vi.fn(async (_request: unknown) => undefined);
    const client = createAccessRelationshipControlClient({
      listSubjects,
      mutate,
    });
    const resource = { type: "document", id: "doc-1" };

    await expect(
      client.listSubjects({ resource, relation: "reader", limit: 50 })
    ).resolves.toEqual({
      unrestricted: false,
      subjects: [{ principal: { type: "user", id: "alice" } }],
      cursor: "next",
    });

    await client.add({
      resource,
      relation: "reader",
      principals: [
        { type: "user", id: "bob" },
        { type: "role", id: "reviewers" },
      ],
      validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 },
    });
    expect(mutate.mock.calls[0]?.[0]).toEqual({
      mutations: [
        {
          operation: "add",
          principal: { type: "user", id: "bob" },
          resource,
          relation: "reader",
          validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 },
        },
        {
          operation: "add",
          principal: { type: "role", id: "reviewers" },
          resource,
          relation: "reader",
          validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 },
        },
      ],
    });

    await client.remove({
      resource,
      relation: "reader",
      principals: { type: "user", id: "alice" },
    });
    expect(mutate.mock.calls[1]?.[0]).toEqual({
      mutations: [
        {
          operation: "remove",
          principal: { type: "user", id: "alice" },
          resource,
          relation: "reader",
        },
      ],
    });

    await client.setUnrestricted({
      resource,
      relation: "reader",
      unrestricted: true,
    });
    expect(mutate.mock.calls[2]?.[0]).toEqual({
      mutations: [
        {
          operation: "set-unrestricted",
          resource,
          relation: "reader",
          unrestricted: true,
        },
      ],
    });
  });

  it("treats empty convenience mutation batches as local no-ops", async () => {
    const mutate = vi.fn(async () => undefined);
    const client = createAccessRelationshipControlClient({
      async listSubjects() {
        return { unrestricted: false, subjects: [] };
      },
      mutate,
    });
    const resource = { type: "document", id: "doc-1" };

    await expect(client.add({ resource, relation: "reader", principals: [] })).resolves.toBeUndefined();
    await expect(client.remove({ resource, relation: "reader", principals: [] })).resolves.toBeUndefined();
    await expect(client.mutate([])).resolves.toBeUndefined();
    expect(mutate).not.toHaveBeenCalled();
  });

  it("diffs a controlled ACL editor by semantic principal+validity source entries", () => {
    const resource = { type: "document", id: "doc-1" };
    expect(
      createAccessRelationshipChanges({
        resource,
        relation: "reader",
        before: {
          unrestricted: true,
          subjects: [{ principal: { type: "user", id: "alice" } }],
        },
        after: {
          unrestricted: false,
          subjects: [
            { principal: { type: "user", id: "alice" } },
            {
              principal: { type: "role", id: "reviewers" },
              validity: [
                { startsAtEpochMs: 10, endsAtEpochMs: 20 },
                { startsAtEpochMs: 15, endsAtEpochMs: 30 },
              ],
            },
          ],
        },
      })
    ).toEqual([
      {
        operation: "add",
        principal: { type: "role", id: "reviewers" },
        resource,
        relation: "reader",
        validity: [
          { startsAtEpochMs: 10, endsAtEpochMs: 20 },
          { startsAtEpochMs: 15, endsAtEpochMs: 30 },
        ],
      },
      {
        operation: "set-unrestricted",
        resource,
        relation: "reader",
        unrestricted: false,
      },
    ]);

    expect(
      createAccessRelationshipChanges({
        resource,
        relation: "reader",
        before: {
          unrestricted: false,
          subjects: [{
            principal: { type: "user", id: "alice" },
            validity: [
              { startsAtEpochMs: 20, endsAtEpochMs: 30 },
              { startsAtEpochMs: 10, endsAtEpochMs: 20 },
            ],
          }],
        },
        after: {
          unrestricted: false,
          subjects: [{
            principal: { type: "user", id: "alice" },
            validity: { startsAtEpochMs: 10, endsAtEpochMs: 30 },
          }],
        },
      })
    ).toEqual([]);
  });

  it("re-adds retained bounded entries after removing a timeless principal source", () => {
    const resource = { type: "document", id: "doc-1" };
    const bounded = {
      principal: { type: "user", id: "alice" },
      validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 },
    };

    expect(
      createAccessRelationshipChanges({
        resource,
        relation: "reader",
        before: {
          unrestricted: false,
          subjects: [{ principal: { type: "user", id: "alice" } }, bounded],
        },
        after: { unrestricted: false, subjects: [bounded] },
      }),
    ).toEqual([
      {
        operation: "remove",
        principal: { type: "user", id: "alice" },
        resource,
        relation: "reader",
      },
      {
        operation: "add",
        principal: { type: "user", id: "alice" },
        resource,
        relation: "reader",
        validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 },
      },
    ]);
  });

  it("distinguishes principal tuples even when either component contains a NUL", () => {
    const resource = { type: "document", id: "doc-1" };
    expect(
      createAccessRelationshipChanges({
        resource,
        relation: "reader",
        before: {
          unrestricted: false,
          subjects: [{ principal: { type: "a", id: "b\u0000c" } }],
        },
        after: {
          unrestricted: false,
          subjects: [{ principal: { type: "a\u0000b", id: "c" } }],
        },
      }),
    ).toEqual([
      {
        operation: "remove",
        principal: { type: "a", id: "b\u0000c" },
        resource,
        relation: "reader",
      },
      {
        operation: "add",
        principal: { type: "a\u0000b", id: "c" },
        resource,
        relation: "reader",
      },
    ]);
  });

  it("decodes bounded relationship editor wire without owning application vocabulary", () => {
    expect(
      parseAccessRelationshipSubjectsRequest({
        resource: { type: "document", id: "doc-1" },
        relation: "reader",
        limit: 50,
      })
    ).toEqual({
      resource: { type: "document", id: "doc-1" },
      relation: "reader",
      limit: 50,
    });
    expect(
      parseAccessRelationshipMutationRequest(
        {
          mutations: [
            {
              operation: "set-unrestricted",
              resource: { type: "document", id: "doc-1" },
              relation: "reader",
              unrestricted: false,
            },
            {
              operation: "add",
              principal: { type: "user", id: "alice" },
              resource: { type: "document", id: "doc-1" },
              relation: "reader",
              validity: [
                { startsAtEpochMs: 100, endsAtEpochMs: 200 },
                { startsAtEpochMs: 300 },
              ],
            },
          ],
        },
        { maximumMutations: 8, maximumValidityWindows: 2 }
      )
    ).toEqual({
      mutations: [
        {
          operation: "set-unrestricted",
          resource: { type: "document", id: "doc-1" },
          relation: "reader",
          unrestricted: false,
        },
        {
          operation: "add",
          principal: { type: "user", id: "alice" },
          resource: { type: "document", id: "doc-1" },
          relation: "reader",
          validity: [
            { startsAtEpochMs: 100, endsAtEpochMs: 200 },
            { startsAtEpochMs: 300 },
          ],
        },
      ],
    });
    expect(() =>
      parseAccessRelationshipMutationRequest(
        {
          mutations: [{
            operation: "add",
            principal: { type: "user", id: "alice" },
            resource: { type: "document", id: "doc-1" },
            relation: "reader",
            validity: [
              { startsAtEpochMs: 100, endsAtEpochMs: 200 },
              { startsAtEpochMs: 300 },
            ],
          }],
        },
        { maximumValidityWindows: 1 },
      )
    ).toThrow(/too many relationship validity windows/);
    expect(() =>
      parseAccessRelationshipMutationRequest({
        mutations: [{
          operation: "add",
          principal: { type: "user", id: "alice" },
          resource: { type: "document", id: "doc-1" },
          relation: "reader",
          validity: [],
        }],
      })
    ).toThrow(/at least one window/);
    expect(() =>
      parseAccessRelationshipMutationRequest({ mutations: [] })
    ).toThrow(/non-empty/);
    expect(() =>
      parseAccessRelationshipMutationRequest({
        mutations: [{
          operation: "add",
          principal: { type: "user", id: "alice" },
          resource: { type: "document", id: "doc-1" },
          relation: "reader",
          validity: { startsAtEpochMs: 20, endsAtEpochMs: 10 },
        }],
      })
    ).toThrow(/start must be before end/);
    expect(() =>
      parseAccessRelationshipMutationRequest({
        mutations: [{
          operation: "add",
          principal: { type: "user", id: "alice" },
          resource: { type: "document", id: "doc-1" },
          relation: "reader",
          validity: { startsAtEpochMs: 20, endsAtEpochMs: 20 },
        }],
      })
    ).toThrow(/start must be before end/);
  });
});
