import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import ts from "typescript";

const manifestUrl = new URL("../assurance/formal-implementation.json", import.meta.url);
const manifest = JSON.parse(await readFile(manifestUrl, "utf8"));
const write = process.argv.includes("--write");
const failures = [];

/** Return a stable digest for text after normalizing line endings and trailing whitespace. */
function textDigest(text) {
  const normalized = text
    .replace(/\r\n?/gu, "\n")
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .trim();
  return createHash("sha256").update(normalized).digest("hex");
}

/** Return the declaration name for top-level function/type/interface declarations we bind formally. */
function declarationName(node) {
  if (
    ts.isFunctionDeclaration(node) ||
    ts.isTypeAliasDeclaration(node) ||
    ts.isInterfaceDeclaration(node)
  ) {
    return node.name?.text;
  }
  return undefined;
}

/** Hash selected TypeScript declarations after reprinting them without comments or formatting trivia. */
function sourceDeclarationDigest(sourceText, fileName, names) {
  const sourceFile = ts.createSourceFile(
    fileName,
    sourceText,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  const byName = new Map();
  for (const statement of sourceFile.statements) {
    const name = declarationName(statement);
    if (name) byName.set(name, statement);
  }
  const printer = ts.createPrinter({
    newLine: ts.NewLineKind.LineFeed,
    removeComments: true,
  });
  const printed = [];
  for (const name of names) {
    const declaration = byName.get(name);
    if (!declaration) throw new Error(`${fileName} missing declaration ${name}`);
    printed.push(`${name}\n${printer.printNode(ts.EmitHint.Unspecified, declaration, sourceFile)}`);
  }
  return textDigest(printed.join("\n\n"));
}

/** Return whether a TLA+ model defines the exact required symbol at the start of a line. */
function modelDefines(model, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`^${escaped}\\s*==`, "mu").test(model);
}

for (const binding of manifest.bindings) {
  const source = await readFile(new URL(`../${binding.source}`, import.meta.url), "utf8");
  const model = await readFile(new URL(`../${binding.model}`, import.meta.url), "utf8");

  for (const action of binding.modelActions) {
    if (!modelDefines(model, action)) failures.push(`${binding.model} missing action ${action}`);
  }
  for (const invariant of binding.modelInvariants ?? []) {
    if (!modelDefines(model, invariant)) failures.push(`${binding.model} missing invariant ${invariant}`);
  }

  let sourceSha256;
  try {
    sourceSha256 = sourceDeclarationDigest(source, binding.source, binding.sourceDeclarations);
  } catch (error) {
    failures.push(error instanceof Error ? error.message : String(error));
    continue;
  }
  const modelSha256 = textDigest(model);

  if (write) {
    binding.sourceSha256 = sourceSha256;
    binding.modelSha256 = modelSha256;
  } else {
    if (binding.sourceSha256 !== sourceSha256) {
      failures.push(`${binding.source} formal-bound declarations changed; run pnpm assurance:update after reviewing model parity`);
    }
    if (binding.modelSha256 !== modelSha256) {
      failures.push(`${binding.model} changed; run pnpm assurance:update after reviewing implementation parity`);
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else if (write) {
  await writeFile(manifestUrl, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  console.log(`formal-implementation bindings updated: ${manifest.bindings.length}`);
} else {
  console.log(`formal-implementation bindings: ${manifest.bindings.length} ok`);
}
