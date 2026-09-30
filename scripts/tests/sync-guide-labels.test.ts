import { join } from "node:path";
import { expect, test } from "vitest";
import { parse } from "yaml";
import { color, displayName, groupDirs, guideLabels, main, render } from "../sync-guide-labels.ts";
import { read, silence, tempRepo, validRepo, write } from "./support.ts";

test("includes top-level groups and indexed subcategories, excluding unindexed notes", () => {
  const root = validRepo();
  write(root, "guides/injection/xss/notes/note.md", "# Note\n");
  expect(groupDirs(root)).toEqual(["injection", join("injection", "xss"), "sensitive-data-exposure"]);
  expect(guideLabels(root)).toEqual([
    ["injection", "Changes to guides in the Injection category", "guides/injection/**"],
    ["xss", "Changes to Cross-site scripting (XSS) guides", "guides/injection/xss/**"],
    [
      "sensitive-data-exposure",
      "Changes to guides in the Sensitive Data Exposure category",
      "guides/sensitive-data-exposure/**",
    ],
  ]);
});
test("prefers README names and falls back to capitalized slug/acronyms", () => {
  const root = validRepo();
  expect(displayName(root, "injection/xss")).toBe("Cross-site scripting (XSS)");
  expect(displayName(root, "new-xss-csrf-group")).toBe("New XSS CSRF Group");
  write(root, "guides/empty/README.md", "No heading\n");
  expect(displayName(root, "empty")).toBe("Empty");
});
test("disambiguates colliding leaf names and rejects residual full-path collisions", () => {
  const root = validRepo();
  write(root, "guides/other/xss/README.md", "# Other\n");
  const names = guideLabels(root).map(([name]) => name);
  expect(names).toContain("injection-xss");
  expect(names).toContain("other-xss");
  expect(names).not.toContain("xss");
  write(root, "guides/injection-xss/README.md", "# Collision\n");
  expect(() => guideLabels(root)).toThrow("duplicate label");
});
test("renders escaped YAML, stable colors and sorted descriptions without mutating input", () => {
  const root = tempRepo();
  const labels = [
    ["z", 'Quotes " and \\ backslash\nNewline', "guides/z/**"],
    ["a", "Alpha", "guides/a/**"],
  ] as const;
  const generated = render(root, labels);
  expect(color("xss")).toBe("8eaee4");
  const output = generated.get(join(root, ".github/labels.yaml")) as string;
  expect(parse(output)).toEqual([
    { name: "a", description: "Alpha", color: color("a") },
    { name: "z", description: labels[0][1], color: color("z") },
  ]);
  expect(output).toContain("pnpm generate:labels");
  expect(labels[0][0]).toBe("z");
  expect(generated).toEqual(render(root, labels));
});
test("CLI sync and check modes detect every stale file without writing", () => {
  const logs = silence();
  const root = validRepo();
  expect(main(["--check"], root)).toBe(1);
  expect(logs.stderr).toHaveBeenCalled();
  expect(main([], root)).toBe(0);
  expect(main(["--check"], root)).toBe(0);
  expect(main([], root)).toBe(0);
  const previous = read(root, ".github/labels.yaml");
  write(root, "guides/new/README.md", "# New\n");
  expect(main(["--check"], root)).toBe(1);
  expect(read(root, ".github/labels.yaml")).toBe(previous);
  expect(() => main(["--bad"], root)).toThrow("Usage");
});
