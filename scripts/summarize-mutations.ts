import { appendFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { isMapping, ROOT, readJson, runCli } from "./runtime.ts";

export function summarize(report: unknown): string {
  if (!isMapping(report) || !isMapping(report.files))
    throw new Error("Invalid mutation report: files must be an object.");
  const counts = new Map<string, number>();
  const statuses = new Set([
    "Killed",
    "Survived",
    "Timeout",
    "NoCoverage",
    "CompileError",
    "RuntimeError",
    "Ignored",
    "Pending",
  ]);
  for (const file of Object.values(report.files)) {
    if (!isMapping(file) || !Array.isArray(file.mutants))
      throw new Error("Invalid mutation report: mutants must be a list.");
    for (const mutant of file.mutants) {
      if (!isMapping(mutant) || typeof mutant.status !== "string" || !statuses.has(mutant.status))
        throw new Error("Invalid mutation report: unknown status.");
      counts.set(mutant.status, (counts.get(mutant.status) ?? 0) + 1);
    }
  }
  return `## Mutation testing\n\n| Status | Count |\n| --- | ---: |\n${[...counts]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([status, count]) => `| ${status} | ${count} |`)
    .join("\n")}\n`;
}

export function main(args: string[], root = ROOT, summaryPath = process.env.GITHUB_STEP_SUMMARY): number {
  if (args.length) throw new Error("Usage: summarize-mutations.ts");
  const path = join(root, "reports/mutation/mutation.json");
  const result = existsSync(path)
    ? summarize(readJson(path))
    : "Mutation testing did not produce a report; see the mutation step logs.\n";
  if (summaryPath) appendFileSync(summaryPath, result, "utf8");
  console.log(result);
  return 0;
}
runCli(import.meta.url, main);
