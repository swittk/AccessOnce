import type {
  AccessPermission,
  AccessScopeDimension,
} from "./types.js";

/** Inputs used to define one application's permission catalog. */
export type AccessCatalogDefinition<
  Permission extends AccessPermission,
  Leaf extends Permission,
  Dimension extends AccessScopeDimension,
> = {
  /** Stable application/catalog id persisted into compiled snapshots. */
  catalogId: string;
  /** Application-owned catalog version. */
  catalogVersion: number;
  /** Compiler behavior version persisted into snapshots. */
  compilerVersion: number;
  /** Every assignable permission node, including parent shortcuts. */
  permissions: readonly Permission[];
  /** Concrete permissions accepted by runtime authorization calls. */
  leaves: readonly Leaf[];
  /** Scope dimensions supported by direct assignment to each leaf. */
  scopeDimensions:
    | Readonly<Record<Leaf, readonly Dimension[]>>
    | ((leaf: Leaf) => readonly Dimension[]);
  /** Cold-path rule saying whether one grant node covers one concrete leaf. */
  includes(granted: Permission, requested: Leaf): boolean;
  /** Extra permissions implied by a grant, before leaf expansion. */
  implies?: Readonly<Partial<Record<Permission, readonly Permission[]>>>;
};

/** Validated catalog used by compilation and runtime snapshot checks. */
export type AccessCatalog<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
> = Omit<AccessCatalogDefinition<Permission, Leaf, Dimension>, "scopeDimensions"> & {
  /** Return the immutable scope dimensions accepted by one concrete leaf. */
  scopeDimensions(leaf: Leaf): readonly Dimension[];
  /** Fast membership check for any assignable permission node. */
  isPermission(value: string): value is Permission;
  /** Fast membership check for a concrete runtime leaf. */
  isLeaf(value: string): value is Leaf;
  /** Scope dimensions accepted when assigning this node directly. */
  supportedScopeDimensions(permission: Permission): ReadonlySet<Dimension>;
};

/** Build and validate the cold-path permission graph once at application startup. */
export function defineAccessCatalog<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
>(
  definition: AccessCatalogDefinition<Permission, Leaf, Dimension>,
): AccessCatalog<Permission, Leaf, Dimension> {
  if (!definition.catalogId.trim()) throw new Error("catalogId must not be empty");
  if (!Number.isSafeInteger(definition.catalogVersion) || definition.catalogVersion < 1) {
    throw new Error("catalogVersion must be a positive safe integer");
  }
  if (!Number.isSafeInteger(definition.compilerVersion) || definition.compilerVersion < 1) {
    throw new Error("compilerVersion must be a positive safe integer");
  }

  /** Copy caller-owned arrays now so later application mutation cannot change catalog meaning. */
  const permissions = Object.freeze([...definition.permissions]);
  const leaves = Object.freeze([...definition.leaves]);

  /** All assignable nodes, kept as a Set so admin/cold validation stays cheap too. */
  const permissionSet = new Set<Permission>();
  for (const permission of permissions) {
    if (!permission || permissionSet.has(permission)) {
      throw new Error(`Duplicate or empty permission node: ${String(permission)}`);
    }
    permissionSet.add(permission);
  }

  /** Concrete leaves, separate from parents because runtime accepts leaves only. */
  const leafSet = new Set<Leaf>();
  for (const leaf of leaves) {
    if (!permissionSet.has(leaf) || leafSet.has(leaf)) {
      throw new Error(`Invalid or duplicate permission leaf: ${String(leaf)}`);
    }
    if (!definition.includes(leaf, leaf)) {
      throw new Error(`Permission leaf ${String(leaf)} must include itself`);
    }
    leafSet.add(leaf);
  }

  /** Snapshot each leaf's editor metadata so caller-owned scope arrays cannot drift after startup. */
  const scopeDimensionsByLeaf = new Map<Leaf, readonly Dimension[]>();
  for (const leaf of leaves) {
    const dimensions = typeof definition.scopeDimensions === "function"
      ? definition.scopeDimensions(leaf)
      : definition.scopeDimensions[leaf];
    if (!dimensions) throw new Error(`Missing scope dimensions for ${String(leaf)}`);
    scopeDimensionsByLeaf.set(leaf, Object.freeze([...dimensions]));
  }

  /** Parent dimension unions are cached because grant editors ask for them repeatedly. */
  const supportedByPermission = new Map<Permission, ReadonlySet<Dimension>>();
  for (const permission of permissions) {
    const dimensions = new Set<Dimension>();
    for (const leaf of leaves) {
      if (!definition.includes(permission, leaf)) continue;
      for (const dimension of scopeDimensionsByLeaf.get(leaf)!) dimensions.add(dimension);
    }
    supportedByPermission.set(permission, dimensions);
  }

  /** Copy implication lists too; these participate in compilation and must never drift after definition. */
  const copiedImplications: Partial<Record<Permission, readonly Permission[]>> = {};
  if (definition.implies) {
    for (const source of Object.keys(definition.implies)) {
      if (!permissionSet.has(source as Permission)) {
        throw new Error(`Unknown implication source permission ${source}`);
      }
    }
    for (const permission of permissions) {
      const targets = definition.implies[permission];
      if (!targets) continue;
      const copiedTargets = Object.freeze([...targets]);
      for (const target of copiedTargets) {
        if (!permissionSet.has(target)) {
          throw new Error(`${String(permission)} implies unknown permission ${String(target)}`);
        }
      }
      copiedImplications[permission] = copiedTargets;
    }
  }
  Object.freeze(copiedImplications);
  const implies = definition.implies ? copiedImplications : undefined;

  return Object.freeze({
    catalogId: definition.catalogId,
    catalogVersion: definition.catalogVersion,
    compilerVersion: definition.compilerVersion,
    permissions,
    leaves,
    scopeDimensions(leaf: Leaf): readonly Dimension[] {
      return scopeDimensionsByLeaf.get(leaf) ?? [];
    },
    includes: definition.includes,
    ...(implies ? { implies } : {}),
    isPermission(value: string): value is Permission {
      return permissionSet.has(value as Permission);
    },
    isLeaf(value: string): value is Leaf {
      return leafSet.has(value as Leaf);
    },
    supportedScopeDimensions(permission: Permission): ReadonlySet<Dimension> {
      const supported = supportedByPermission.get(permission);
      // Return a copy because JavaScript Set remains mutable even when exposed through ReadonlySet typing.
      return supported ? new Set(supported) : new Set<Dimension>();
    },
  });
}
/** Catalog definition for the common dotted/slashed permission-tree case. */
export type HierarchicalAccessCatalogDefinition<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
> = Omit<AccessCatalogDefinition<Permission, Leaf, Dimension>, "includes"> & {
  /** Root value that covers every leaf, for example `*`. */
  wildcard: Permission;
  /** Segment separator used by parent permission nodes; defaults to `.`. */
  separator?: string;
};

/** Test one string-path grant against a requested node using the same rule as hierarchical catalogs. */
export function hierarchicalPermissionIncludes(
  granted: string,
  requested: string,
  wildcard: string,
  separator = ".",
): boolean {
  if (!separator) throw new Error("permission hierarchy separator must not be empty");
  return (
    granted === wildcard ||
    granted === requested ||
    requested.startsWith(`${granted}${separator}`)
  );
}

/** Define a permission catalog whose parent nodes are ordinary string-path prefixes. */
export function defineHierarchicalAccessCatalog<
  Permission extends string,
  Leaf extends Permission,
  Dimension extends string,
>(
  definition: HierarchicalAccessCatalogDefinition<Permission, Leaf, Dimension>,
): AccessCatalog<Permission, Leaf, Dimension> {
  const separator = definition.separator ?? ".";
  if (!separator) throw new Error("permission hierarchy separator must not be empty");
  const { wildcard, separator: _separator, ...catalogDefinition } = definition;
  return defineAccessCatalog({
    ...catalogDefinition,
    includes(granted, requested) {
      return hierarchicalPermissionIncludes(granted, requested, wildcard, separator);
    },
  });
}
