import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { message, ROOT, runCli } from "./runtime.ts";

export function mutationTargets(root: string, event: string, base?: string, head?: string): string[] {
  if (event !== "pull_request") return [];
  // Invalid SHAs must never become Git options or silently narrow validation.
  if (!base || !head || !/^[a-f0-9]{40}$/i.test(base) || !/^[a-f0-9]{40}$/i.test(head)) {
    throw new Error("Pull request mutation tests require full BASE_SHA and HEAD_SHA commit IDs.");
  }
  const diff = spawnSync("git", ["diff", "--name-only", "--no-renames", "-z", base, head, "--"], {
    cwd: root,
    encoding: "utf8",
  });
  if (diff.error || diff.status !== 0)
    throw new Error(`Cannot determine mutation targets: ${diff.error?.message ?? diff.stderr}`);
  const paths = diff.stdout.split("\0").filter(Boolean);
  // Test/config/dependency edits and deletions can invalidate coverage for every module.
  if (!paths.length || paths.some((path) => !/^scripts\/[a-z][a-z0-9-]*\.ts$/.test(path))) return [];
  const removed = spawnSync("git", ["diff", "--name-only", "--diff-filter=D", "-z", base, head, "--", "scripts/"], {
    cwd: root,
    encoding: "utf8",
  });
  if (removed.error || removed.status !== 0) throw new Error("Cannot determine deleted mutation targets.");
  return removed.stdout ? [] : paths.sort();
}

export function main(
  args: string[],
  root = ROOT,
  env: NodeJS.ProcessEnv = process.env,
  run = runMutationSuite,
): number {
  if (args.length) throw new Error("Usage: run-mutation-tests.ts");
  let targets: string[];
  try {
    targets = mutationTargets(root, env.GITHUB_EVENT_NAME ?? "", env.BASE_SHA, env.HEAD_SHA);
  } catch (error) {
    console.error(`${message(error)} Running the full mutation suite.`);
    targets = [];
  }
  console.log(targets.length ? `Mutating changed modules: ${targets.join(", ")}` : "Running the full mutation suite.");
  return run(root, targets);
}

export function runMutationSuite(root: string, targets: string[]): number {
  // Invoke the local, locked CLI directly; no shell and no package download fallback.
  const cli = join(root, "node_modules/@stryker-mutator/core/bin/stryker.js");
  const result = spawnSync(process.execPath, [cli, "run", ...(targets.length ? ["--mutate", targets.join(",")] : [])], {
    cwd: root,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  return result.status ?? 1;
}
runCli(import.meta.url, main);
