import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const esm = await import("../dist/index.js");
const cjs = require("../dist-cjs/index.js");
const esmReact = await import("../dist/react.js");
const esmControl = await import("../dist/control-wire.js");
const cjsReact = require("../dist-cjs/react.js");
const cjsControl = require("../dist-cjs/control-wire.js");
const esmAuthZen = await import("../dist/authzen/index.js");
const cjsAuthZen = require("../dist-cjs/authzen/index.js");
const esmClient = await import("../dist/client.js");
const cjsClient = require("../dist-cjs/client.js");

/** Exercise one real authorization through either built module format. */
function checkCore(module, label) {
  const catalog = module.defineAccessCatalog({
    catalogId: `consumer-${label}`,
    catalogVersion: 1,
    compilerVersion: 1,
    permissions: ["read"],
    leaves: ["read"],
    scopeDimensions: { read: ["location"] },
    includes(granted, requested) {
      return granted === requested;
    },
  });
  const snapshot = module.compileAccessSnapshot(catalog, {
    grants: [{ permission: "read", scope: { location: { kind: "ids", ids: ["a"] } } }],
  });
  const access = module.createAccessEvaluator(catalog);
  if (!access.can(snapshot, "read", { location: "a" })) {
    throw new Error(`${label} build denied its consumer smoke authorization`);
  }
  const model = module.createAccess({
    catalogId: `consumer-sources-${label}`,
    catalogVersion: 1,
    compilerVersion: 1,
    permissions: ["read"],
    leaves: ["read"],
    scopeDimensions: { read: ["location"] },
    includes(granted, requested) {
      return granted === requested;
    },
  });
  const composed = model.compileSources({
    sources: [
      { id: "profile", grants: [{ permission: "read" }] },
      {
        id: "direct",
        grants: [{ permission: "read", scope: { location: { kind: "ids", ids: ["b"] } } }],
      },
    ],
  });
  if (!model.can(composed.snapshot, "read", { location: "outside" })) {
    throw new Error(`${label} build failed additive source composition`);
  }
  if (composed.contributions.length !== 2) {
    throw new Error(`${label} build lost source provenance`);
  }

  const temporalSnapshot = model.compile({
    grants: [{
      permission: "read",
      scope: { location: { kind: "ids", ids: ["timed"] } },
      validity: { startsAtEpochMs: 10, endsAtEpochMs: 20 },
    }],
  });
  if (model.can(temporalSnapshot, "read", { location: "timed" })) {
    throw new Error(`${label} build leaked temporal authority into timeless can()`);
  }
  if (!model.evaluateAt(temporalSnapshot, 10).can("read", { location: "timed" })) {
    throw new Error(`${label} build failed temporal evaluation at the inclusive boundary`);
  }
  if (model.evaluateAt(temporalSnapshot, 20).can("read", { location: "timed" })) {
    throw new Error(`${label} build failed temporal evaluation at the exclusive boundary`);
  }
}

checkCore(esm, "esm");
checkCore(cjs, "cjs");
if (typeof esmReact.createMutableReactAccessSource !== "function") {
  throw new Error("ESM React subpath is missing createMutableReactAccessSource");
}
if (typeof cjsReact.createMutableReactAccessSource !== "function") {
  throw new Error("CJS React subpath is missing createMutableReactAccessSource");
}
if (typeof esmControl.createAccessGrantControlClient !== "function") {
  throw new Error("ESM control subpath is missing createAccessGrantControlClient");
}
if (typeof esmControl.createAccessPublicationControlPlane !== "function") {
  throw new Error("ESM control subpath is missing createAccessPublicationControlPlane");
}
if (typeof esmControl.createAccessRelationshipControlClient !== "function") {
  throw new Error("ESM control subpath is missing createAccessRelationshipControlClient");
}
if (typeof esm.constrainRelationshipQuery !== "function") {
  throw new Error("ESM root is missing constrainRelationshipQuery");
}
if (typeof cjsControl.createAccessGrantControlClient !== "function") {
  throw new Error("CJS control subpath is missing createAccessGrantControlClient");
}
if (typeof cjsControl.createAccessPublicationControlPlane !== "function") {
  throw new Error("CJS control subpath is missing createAccessPublicationControlPlane");
}
if (typeof cjsControl.createAccessRelationshipControlClient !== "function") {
  throw new Error("CJS control subpath is missing createAccessRelationshipControlClient");
}
if (typeof cjs.constrainRelationshipQuery !== "function") {
  throw new Error("CJS root is missing constrainRelationshipQuery");
}
if (typeof esmAuthZen.createAccessOnceAuthZenPdp !== "function") {
  throw new Error("ESM AuthZEN subpath is missing createAccessOnceAuthZenPdp");
}
if (typeof cjsAuthZen.createAuthZenHttpClient !== "function") {
  throw new Error("CJS AuthZEN subpath is missing createAuthZenHttpClient");
}
if (typeof esmClient.createAccessSnapshotClient !== "function") {
  throw new Error("ESM client subpath is missing createAccessSnapshotClient");
}
if (typeof cjsClient.createAccessSnapshotClient !== "function") {
  throw new Error("CJS client subpath is missing createAccessSnapshotClient");
}
console.log("consumer-smoke: ESM, CJS, temporal evaluation, client, control, relationship ACL, React, and AuthZEN surfaces ok");
