import { join } from "node:path";
import { expect, test } from "vitest";
import { main, summarize } from "../summarize-mutations.ts";
import { read, silence, tempRepo, write } from "./support.ts";

test("summarizes counts without including repository-controlled report text", () => {
  expect(
    summarize({
      files: { "<unsafe>": { mutants: [{ status: "Killed" }, { status: "Killed" }, { status: "Survived" }] } },
    }),
  ).toBe("## Mutation testing\n\n| Status | Count |\n| --- | ---: |\n| Killed | 2 |\n| Survived | 1 |\n");
  for (const data of [
    null,
    { files: [] },
    { files: { bad: {} } },
    { files: { bad: { mutants: [{ status: "<script>" }] } } },
  ])
    expect(() => summarize(data)).toThrow("Invalid mutation report");
});
test("reports missing output and appends a valid report to the workflow summary", () => {
  silence();
  const root = tempRepo();
  const summary = join(root, "summary.md");
  expect(main([], root, summary)).toBe(0);
  expect(read(root, "summary.md")).toContain("did not produce a report");
  write(
    root,
    "reports/mutation/mutation.json",
    JSON.stringify({ files: { "a.ts": { mutants: [{ status: "NoCoverage" }] } } }),
  );
  expect(main([], root, summary)).toBe(0);
  expect(read(root, "summary.md")).toContain("| NoCoverage | 1 |");
  expect(() => main(["--bad"], root, summary)).toThrow("Usage");
});
