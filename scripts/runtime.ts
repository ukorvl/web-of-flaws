import { randomUUID } from "node:crypto";
import { existsSync, readdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
export type Mapping = Record<string, unknown>;
export const isMapping = (value: unknown): value is Mapping =>
  typeof value === "object" && value !== null && !Array.isArray(value);
export const nonEmptyString = (value: unknown): value is string => typeof value === "string" && value.trim() !== "";
export const posixPath = (path: string): string => path.split(sep).join("/");
export const displayPath = (root: string, path: string): string => posixPath(relative(root, path));

export function walk(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error(`${path}: symbolic links are not supported in source data`);
      return entry.isDirectory() ? walk(path) : entry.isFile() ? [path] : [];
    })
    .sort();
}

export function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8")) as unknown;
  } catch (error) {
    throw new Error(`${path}: ${error instanceof SyntaxError ? "invalid JSON: " : ""}${message(error)}`);
  }
}

export function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function writeGenerated(path: string, content: string, check: boolean, command: string): boolean {
  if (existsSync(path) && readFileSync(path, "utf8").replaceAll("\r\n", "\n") === content) return false;
  if (check) throw new Error(`${path} is out of date. Run: ${command}`);
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    writeFileSync(temporary, content, { encoding: "utf8", flag: "wx" });
    renameSync(temporary, path);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
  return true;
}

export function runCli(url: string, main: (args: string[]) => number): void {
  if (!process.argv[1] || resolve(process.argv[1]) !== fileURLToPath(url)) return;
  try {
    process.exitCode = main(process.argv.slice(2));
  } catch (error) {
    console.error(message(error));
    process.exitCode = 1;
  }
}

export function checkFlag(args: string[]): boolean {
  if (args.some((argument) => argument !== "--check")) throw new Error("Usage: [--check]");
  return args.includes("--check");
}
