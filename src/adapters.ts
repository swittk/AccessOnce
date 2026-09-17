/** Backend query adapter that turns an AccessOnce query plan into one database/query-builder shape. */
export type AccessQueryAdapter<Query, Dimension extends string> = {
  /** Return a query guaranteed to match nothing. */
  deny(query: Query): Query;
  /** Return the unchanged or explicitly unrestricted query. */
  allowAll(query: Query): Query;
  /** Apply OR-of-AND correlated scope clauses without broadening them into a cross product. */
  applyClauses(
    query: Query,
    clauses: readonly Readonly<Partial<Record<Dimension, readonly string[]>>>[],
  ): Query;
};

/** Apply a query plan with a bring-your-own database/query-builder adapter. */
export function applyAccessQueryPlan<Query, Dimension extends string>(
  query: Query,
  plan: import("./types.js").AccessQueryPlan<Dimension>,
  adapter: AccessQueryAdapter<Query, Dimension>,
): Query {
  if (plan.kind === "none") return adapter.deny(query);
  if (plan.kind === "all") return adapter.allowAll(query);
  return adapter.applyClauses(query, plan.clauses);
}
