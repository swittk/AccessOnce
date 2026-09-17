import { mkdir, writeFile } from "node:fs/promises";

const output = new URL("../dist-cjs/", import.meta.url);
await mkdir(output, { recursive: true });
await writeFile(new URL("package.json", output), '{"type":"commonjs"}\n');
