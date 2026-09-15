import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

/** Collect TypeScript source files recursively without looking at generated output. */
async function collectSourceFiles(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) result.push(...(await collectSourceFiles(path)));
    else if (entry.name.endsWith(".ts") || entry.name.endsWith(".tsx")) result.push(path);
  }
  return result;
}

/** Return whether a declaration has a real JSDoc block directly attached to it. */
function hasJsDoc(node) {
  return Array.isArray(node.jsDoc) && node.jsDoc.length > 0;
}

/** Return whether a variable statement is part of the public API and therefore needs purpose docs. */
function isExportedVariableStatement(node) {
  return (
    ts.isVariableStatement(node) &&
    node.modifiers?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword)
  );
}

/** Check named declarations recursively so undocumented helpers do not creep into security-critical code. */
function inspectNode(sourceFile, node, failures) {
  const namedDeclaration =
    (ts.isFunctionDeclaration(node) && node.name) ||
    ts.isClassDeclaration(node) ||
    ts.isInterfaceDeclaration(node) ||
    ts.isTypeAliasDeclaration(node) ||
    ts.isEnumDeclaration(node);
  const documentedShapeMember = ts.isPropertySignature(node) || ts.isMethodSignature(node);
  if ((namedDeclaration || isExportedVariableStatement(node) || documentedShapeMember) && !hasJsDoc(node)) {
    const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    failures.push(`${relative(process.cwd(), sourceFile.fileName)}:${position.line + 1} missing /** */ purpose comment`);
  }
  if (node.kind === ts.SyntaxKind.AnyKeyword) {
    const position = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    failures.push(`${relative(process.cwd(), sourceFile.fileName)}:${position.line + 1} uses banned any type`);
  }
  ts.forEachChild(node, (child) => inspectNode(sourceFile, child, failures));
}

const failures = [];
for (const file of await collectSourceFiles(fileURLToPath(new URL("../src", import.meta.url)))) {
  const text = await readFile(file, "utf8");
  const source = ts.createSourceFile(file, text, ts.ScriptTarget.Latest, true, file.endsWith(".tsx") ? ts.ScriptKind.TSX : ts.ScriptKind.TS);
  inspectNode(source, source, failures);
}

const hotRuntime = await readFile(fileURLToPath(new URL("../src/runtime.ts", import.meta.url)), "utf8");
for (const method of ["map", "filter", "sort", "includes", "some", "every"]) {
  if (hotRuntime.includes(`.${method}(`)) failures.push(`src/runtime.ts hot path uses .${method}()`);
}

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exitCode = 1;
} else {
  console.log("source-quality: ok");
}
