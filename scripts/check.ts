import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { ROOT, runCli } from "./runtime.ts";

export interface Check {
  readonly name: string;
  readonly script: string;
  readonly arguments: readonly string[];
  readonly relevantPrefixes: readonly string[];
}
export const CHECKS: readonly Check[] = [
  {
    name: "catalog",
    script: "scripts/generate-catalog.ts",
    arguments: ["--check"],
    relevantPrefixes: ["catalog/rules.json", "guides/", "scripts/generate-catalog.ts", "scripts/guide-tools.ts"],
  },
  {
    name: "guides",
    script: "scripts/lint-repo.ts",
    arguments: [],
    relevantPrefixes: [
      "catalog/allowed-reference-domains.json",
      "guides/",
      "scripts/generate-catalog.ts",
      "scripts/guide-tools.ts",
      "scripts/lint-repo.ts",
    ],
  },
  {
    name: "standards",
    script: "scripts/validate-standards.ts",
    arguments: [],
    relevantPrefixes: ["catalog/standards/", "guides/", "scripts/guide-tools.ts", "scripts/validate-standards.ts"],
  },
  {
    name: "labels",
    script: "scripts/sync-guide-labels.ts",
    arguments: ["--check"],
    relevantPrefixes: [".github/labeler.yaml", ".github/labels.yaml", "guides/", "scripts/sync-guide-labels.ts"],
  },
];
const SHARED_INPUTS = new Set([
  "package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  ".node-version",
  "tsconfig.json",
  "tsconfig.base.json",
  "scripts/check.ts",
  "scripts/runtime.ts",
]);

export function changedPaths(root: string): Set<string> | undefined {
  const paths = new Set<string>();
  for (const args of [
    ["diff", "--name-only", "--no-renames", "-z", "HEAD", "--"],
    ["ls-files", "--others", "--exclude-standard", "-z"],
  ]) {
    const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
    if (result.error || result.status !== 0) return undefined;
    for (const path of result.stdout.split("\0")) if (path) paths.add(path);
  }
  return paths;
}

export function isRelevant(check: Check, paths: Iterable<string>): boolean {
  return [...paths].some(
    (path) =>
      SHARED_INPUTS.has(path) ||
      check.relevantPrefixes.some((prefix) => path === prefix || (prefix.endsWith("/") && path.startsWith(prefix))),
  );
}

export function selectedChecks(names: string[], changedOnly: boolean, root: string): readonly Check[] {
  const selected = names.length
    ? [...new Set(names)].map((name) => {
        const check = CHECKS.find((item) => item.name === name);
        if (!check)
          throw new Error(`Unknown check ${JSON.stringify(name)}; choose catalog, guides, standards, labels.`);
        return check;
      })
    : CHECKS;
  if (!changedOnly) return selected;
  const paths = changedPaths(root);
  if (!paths?.size) return selected;
  const matching = selected.filter((check) => isRelevant(check, paths));
  return matching.length ? matching : selected;
}

export function runCheck(check: Check, root: string): boolean {
  console.log(`==> Running ${check.name} check`);
  const result = spawnSync(process.execPath, [join(root, check.script), ...check.arguments], {
    cwd: root,
    stdio: "inherit",
  });
  if (result.error) console.error(result.error.message);
  return !result.error && result.status === 0;
}

export function main(args: string[], root = ROOT, runner = runCheck): number {
  const names: string[] = [];
  let changedOnly = false;
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--changed-only") changedOnly = true;
    else if (arg === "--check" && args[index + 1]) names.push(args[++index] as string);
    else if (arg?.startsWith("--check=")) names.push(arg.slice("--check=".length));
    else if (arg === "--help") {
      console.log("Usage: pnpm check [--check catalog|guides|standards|labels]... [--changed-only]");
      return 0;
    } else throw new Error(`Unknown or incomplete argument ${JSON.stringify(arg)}. Use --help.`);
  }
  const checks = selectedChecks(names, changedOnly, root);
  const failures = checks.filter((check) => !runner(check, root));
  if (failures.length) {
    console.error(`Repository checks failed: ${failures.map((check) => check.name).join(", ")}.`);
    return 1;
  }
  console.log(`Repository checks passed: ${checks.map((check) => check.name).join(", ")}.`);
  return 0;
}
runCli(import.meta.url, main);
