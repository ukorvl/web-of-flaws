import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { parseAllDocuments, parseDocument } from "yaml";
import { message, ROOT, runCli } from "./runtime.ts";

export function lintConfig(root: string): string[] {
  const files = spawnSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], {
    cwd: root,
    encoding: "utf8",
  });
  if (files.error || files.status !== 0)
    throw new Error(`Cannot enumerate repository files: ${files.error?.message ?? files.stderr}`);
  const errors: string[] = [];
  for (const path of new Set(files.stdout.split("\0").filter(Boolean))) {
    if (!existsSync(join(root, path))) continue;
    if (!/\.(?:json|ya?ml)$/.test(path)) continue;
    const content = readFileSync(join(root, path), "utf8");
    try {
      if (path.endsWith(".json")) JSON.parse(content);
      else {
        // pnpm 12 stores package-manager and application dependencies in separate YAML documents.
        const documents =
          path === "pnpm-lock.yaml"
            ? parseAllDocuments(content, { uniqueKeys: true, strict: true })
            : [parseDocument(content, { uniqueKeys: true, strict: true })];
        const problems = documents.flatMap((document) => [...document.errors, ...document.warnings]);
        if (problems.length) throw new Error(problems.map((error) => error.message).join("; "));
      }
    } catch (error) {
      errors.push(`${path}: ${message(error)}`);
    }
    if (!content.endsWith("\n")) errors.push(`${path}: missing final newline`);
    if (/[^\S\r\n]+$/m.test(content)) errors.push(`${path}: trailing whitespace`);
  }
  return errors;
}

export function main(args: string[], root = ROOT): number {
  if (args.length) throw new Error("Usage: lint-config.ts");
  const errors = lintConfig(root);
  if (errors.length) {
    console.error(errors.join("\n"));
    return 1;
  }
  console.log("JSON and YAML configuration validation passed.");
  return 0;
}
runCli(import.meta.url, main);
