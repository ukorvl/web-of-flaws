import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, symlinkSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";
import { lintConfig, main as lintConfigMain } from "../lint-config.ts";
import { checkFlag, isMapping, message, nonEmptyString, ROOT, readJson, walk, writeGenerated } from "../runtime.ts";
import { silence, tempRepo, write } from "./support.ts";

test("guards unknown inputs precisely", () => {
  expect(isMapping({})).toBe(true);
  for (const value of [null, [], false, "x", 4]) expect(isMapping(value)).toBe(false);
  expect(nonEmptyString("  ")).toBe(false);
  expect(nonEmptyString("x")).toBe(true);
  expect(message(new Error("bad"))).toBe("bad");
  expect(message("raw")).toBe("raw");
  expect(checkFlag([])).toBe(false);
  expect(checkFlag(["--check"])).toBe(true);
  expect(() => checkFlag(["--bad"])).toThrow("Usage");
});
test("generated writes are deterministic, atomic, CRLF tolerant and check mode never writes", () => {
  const root = tempRepo();
  const path = join(root, "data.json");
  expect(() => writeGenerated(path, "{}\n", true, "regenerate")).toThrow("Run: regenerate");
  expect(readdirSync(root)).toEqual([]);
  expect(writeGenerated(path, "{}\n", false, "regenerate")).toBe(true);
  expect(writeGenerated(path, "{}\n", false, "regenerate")).toBe(false);
  expect(readFileSync(path, "utf8")).toBe("{}\n");
  write(root, "data.json", "{}\r\n");
  expect(writeGenerated(path, "{}\n", true, "regenerate")).toBe(false);
  expect(readdirSync(root)).toEqual(["data.json"]);
});
test("JSON failures carry paths, traversal is sorted and symbolic links fail closed", () => {
  const root = tempRepo();
  write(root, "z.json", "{}");
  write(root, "a/b.json", "bad");
  expect(readJson(join(root, "z.json"))).toEqual({});
  expect(() => readJson(join(root, "a/b.json"))).toThrow("invalid JSON");
  expect(() => readJson(join(root, "missing.json"))).toThrow("missing.json");
  expect(walk(root)).toEqual([join(root, "a/b.json"), join(root, "z.json")]);
  symlinkSync(join(root, "z.json"), join(root, "link.json"));
  expect(() => walk(root)).toThrow("symbolic links");
});
test("CLI runs from another working directory and rejects unexpected flags without traceback", () => {
  const root = tempRepo();
  const result = spawnSync(process.execPath, [join(ROOT, "scripts/generate-catalog.ts"), "--check"], {
    cwd: root,
    encoding: "utf8",
  });
  expect(result.status, result.stderr).toBe(0);
  const bad = spawnSync(process.execPath, [join(ROOT, "scripts/generate-catalog.ts"), "--typo"], {
    cwd: root,
    encoding: "utf8",
  });
  expect(bad.status).toBe(1);
  expect(bad.stderr).toContain("Usage");
  expect(bad.stderr).not.toContain("at main");
});
test("config validation checks tracked and untracked JSON/YAML, not ignored artifacts", () => {
  silence();
  const root = tempRepo();
  expect(() => lintConfig(root)).toThrow("Cannot enumerate");
  spawnSync("git", ["init", "--initial-branch=main"], { cwd: root });
  write(root, "valid.yaml", "on: push\n");
  write(root, "valid.json", "{}\n");
  write(root, "pnpm-lock.yaml", "---\nlockfileVersion: '9.0'\n---\nlockfileVersion: '9.0'\n");
  expect(lintConfig(root)).toEqual([]);
  expect(lintConfigMain([], root)).toBe(0);
  write(root, "bad.yaml", "key: one\nkey: two\n");
  write(root, "bad-documents.yaml", "---\nkey: one\n---\nkey: two\n");
  write(root, "bad.json", '{"x":1,} ');
  const errors = lintConfig(root).join("\n");
  expect(errors).toContain("bad.yaml");
  expect(errors).toContain("bad-documents.yaml");
  expect(errors).toContain("bad.json");
  expect(errors).toContain("missing final newline");
  expect(errors).toContain("trailing whitespace");
  expect(lintConfigMain([], root)).toBe(1);
  expect(() => lintConfigMain(["--bad"], root)).toThrow("Usage");
});
