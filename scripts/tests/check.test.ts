import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { expect, test } from "vitest";
import { CHECKS, changedPaths, isRelevant, main, runCheck, selectedChecks } from "../check.ts";
import { main as mutationMain, mutationTargets, runMutationSuite } from "../run-mutation-tests.ts";
import { read, silence, tempRepo, write } from "./support.ts";

function git(root: string, ...args: string[]): string {
  const result = spawnSync("git", args, { cwd: root, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr);
  return result.stdout.trim();
}
function gitRepo(): string {
  const root = tempRepo();
  git(root, "init", "--initial-branch=main");
  git(root, "config", "user.name", "Test");
  git(root, "config", "user.email", "test@example.com");
  git(root, "config", "core.hooksPath", join(root, "no-hooks"));
  write(root, "README.md", "# Test\n");
  git(root, "add", ".");
  git(root, "commit", "-qm", "Initial fixture");
  return root;
}
test("defaults to all checks, falls back for clean/unavailable Git and honors explicit selection", () => {
  const root = tempRepo();
  expect(changedPaths(root)).toBeUndefined();
  expect(selectedChecks([], false, root)).toEqual(CHECKS);
  expect(selectedChecks([], true, root)).toEqual(CHECKS);
  expect(selectedChecks(["labels"], true, root).map((check) => check.name)).toEqual(["labels"]);
  expect(selectedChecks([], true, gitRepo())).toEqual(CHECKS);
  expect(() => selectedChecks(["unknown"], false, root)).toThrow("Unknown check");
});
test("discovers staged, unstaged, deleted and untracked paths with spaces/newlines", () => {
  const root = gitRepo();
  write(root, "README.md", "changed");
  write(root, "space name.md", "x");
  git(root, "add", "space name.md");
  write(root, "line\nbreak.md", "x");
  expect(changedPaths(root)).toEqual(new Set(["README.md", "space name.md", "line\nbreak.md"]));
});
test("filters relevant files, includes shared dependencies and avoids prefix false positives", () => {
  const root = gitRepo();
  write(root, ".github/labels.yaml", "changed");
  expect(selectedChecks([], true, root).map((check) => check.name)).toEqual(["labels"]);
  write(root, "pnpm-lock.yaml", "changed");
  expect(selectedChecks([], true, root)).toEqual(CHECKS);
  const check = CHECKS[0];
  if (!check) throw new Error("missing check fixture");
  expect(isRelevant(check, ["guides/a.md"])).toBe(true);
  expect(isRelevant(check, ["catalog/rules.json.bak"])).toBe(false);
  expect(isRelevant(check, ["scripts/runtime.ts"])).toBe(true);
});
test("no matching changes run requested checks, unknown arguments fail, checks aggregate failures", () => {
  const logs = silence();
  const root = gitRepo();
  write(root, "README.md", "changed");
  expect(selectedChecks([], true, root)).toEqual(CHECKS);
  const calls: string[] = [];
  expect(
    main([], root, (check) => {
      calls.push(check.name);
      return check.name === "guides";
    }),
  ).toBe(1);
  expect(calls).toEqual(["catalog", "guides", "standards", "labels"]);
  expect(logs.stderr).toHaveBeenCalledWith("Repository checks failed: catalog, standards, labels.");
  expect(main(["--check", "labels", "--check=labels", "--changed-only"], root, () => true)).toBe(0);
  expect(main(["--help"], root)).toBe(0);
  for (const args of [["--check"], ["--unknown"], ["--check", "invalid"]]) expect(() => main(args, root)).toThrow();
});
test("check runner propagates child failures and runs in explicit repository directory", () => {
  silence();
  const root = tempRepo();
  write(root, "marker", "expected");
  write(
    root,
    "scripts/pass.ts",
    'import { readFileSync } from "node:fs"; if (!process.argv.includes("--expected") || readFileSync("marker", "utf8") !== "expected") process.exit(1);',
  );
  expect(
    runCheck({ name: "test", script: "scripts/pass.ts", arguments: ["--expected"], relevantPrefixes: [] }, root),
  ).toBe(true);
  expect(runCheck({ name: "test", script: "scripts/pass.ts", arguments: [], relevantPrefixes: [] }, root)).toBe(false);
});
test("mutation selection is narrow only for valid production-only commits", () => {
  const root = gitRepo();
  const base = git(root, "rev-parse", "HEAD");
  expect(mutationTargets(root, "schedule")).toEqual([]);
  expect(() => mutationTargets(root, "pull_request", "--evil", base)).toThrow("full BASE_SHA");
  write(root, "scripts/check.ts", "export {};");
  git(root, "add", ".");
  git(root, "commit", "-qm", "Add script");
  const head = git(root, "rev-parse", "HEAD");
  expect(mutationTargets(root, "pull_request", base, head)).toEqual(["scripts/check.ts"]);
  write(root, "scripts/tests/check.test.ts", "test");
  git(root, "add", ".");
  git(root, "commit", "-qm", "Add tests");
  expect(mutationTargets(root, "pull_request", base, git(root, "rev-parse", "HEAD"))).toEqual([]);
  expect(mutationTargets(root, "pull_request", head, head)).toEqual([]);
  expect(() => mutationTargets(root, "pull_request", "0".repeat(40), head)).toThrow("Cannot determine");
  git(root, "rm", "scripts/check.ts");
  git(root, "commit", "-qm", "Remove script");
  expect(mutationTargets(root, "pull_request", head, git(root, "rev-parse", "HEAD"))).toEqual([]);
});

test("mutation CLI falls back on invalid Git metadata and propagates suite failures", () => {
  silence();
  const root = tempRepo();
  const calls: string[][] = [];
  const runner = (directory: string, targets: string[]): number => {
    expect(directory).toBe(root);
    calls.push(targets);
    return 17;
  };
  expect(mutationMain([], root, { GITHUB_EVENT_NAME: "pull_request" }, runner)).toBe(17);
  expect(mutationMain([], root, {}, runner)).toBe(17);
  expect(calls).toEqual([[], []]);
  expect(() => mutationMain(["--bad"], root, {}, runner)).toThrow("Usage");
});

test("mutation subprocess uses the locked local CLI and preserves arguments and failures", () => {
  const root = tempRepo();
  const cli = "node_modules/@stryker-mutator/core/bin/stryker.js";
  write(
    root,
    cli,
    'const fs = require("node:fs"); fs.writeFileSync("arguments.json", JSON.stringify(process.argv.slice(2)));',
  );
  expect(runMutationSuite(root, ["scripts/check.ts", "scripts/runtime.ts"])).toBe(0);
  expect(JSON.parse(read(root, "arguments.json"))).toEqual(["run", "--mutate", "scripts/check.ts,scripts/runtime.ts"]);
  expect(runMutationSuite(root, [])).toBe(0);
  expect(JSON.parse(read(root, "arguments.json"))).toEqual(["run"]);
  write(root, cli, "process.exit(17);");
  expect(runMutationSuite(root, [])).toBe(17);
});
