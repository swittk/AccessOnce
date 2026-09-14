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
      principals: [{ type: "user", id: "alice" }],
      cursor: "next",
    }));
    const mutate = vi.fn(async () => undefined);
    const client = createAccessRelationshipControlClient({
      listSubjects,
      mutate,
    });
    const resource = { type: "document", id: "doc-1" };

    await expect(
      client.listSubjects({ resource, relation: "reader", limit: 50 })
    ).resolves.toEqual({
      unrestricted: false,
      principals: [{ type: "user", id: "alice" }],
      cursor: "next",
    });

    await client.add({
      resource,
      relation: "reader",
      principals: [
        { type: "user", id: "bob" },
        { type: "role", id: "reviewers" },
      ],
    });
    expect(mutate.mock.calls[0]?.[0]).toEqual({
      mutations: [
        {
          operation: "add",
          principal: { type: "user", id: "bob" },
          resource,
          relation: "reader",
        },
        {
          operation: "add",
          principal: { type: "role", id: "reviewers" },
          resource,
          relation: "reader",
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
  it("diffs a controlled ACL editor into minimal principal changes plus one visibility switch", () => {
    const resource = { type: "document", id: "doc-1" };
    expect(
      createAccessRelationshipChanges({
        resource,
        relation: "reader",
        before: {
          unrestricted: true,
          principals: [{ type: "user", id: "alice" }],
        },
        after: {
          unrestricted: false,
          principals: [
            { type: "user", id: "alice" },
            { type: "role", id: "reviewers" },
          ],
        },
      })
    ).toEqual([
      {
        operation: "add",
        principal: { type: "role", id: "reviewers" },
        resource,
        relation: "reader",
      },
      {
        operation: "set-unrestricted",
        resource,
        relation: "reader",
        unrestricted: false,
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
          principals: [{ type: "a", id: "b\u0000c" }],
        },
        after: {
          unrestricted: false,
          principals: [{ type: "a\u0000b", id: "c" }],
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
            },
          ],
        },
        { maximumMutations: 8 }
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
        },
      ],
    });
    expect(() =>
      parseAccessRelationshipMutationRequest({ mutations: [] })
    ).toThrow(/non-empty/);
  });
});
