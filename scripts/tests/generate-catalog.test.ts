import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";
import {
  buildRules,
  canonicalReferenceUrl,
  expectedCweReference,
  expectedOwaspTop10Reference,
  main,
  renderCatalog,
} from "../generate-catalog.ts";
import { ROOT } from "../runtime.ts";
import { BODY, GUIDE, guide, metadata, read, replace, silence, validRepo, write } from "./support.ts";

test("catalog migration preserves the real catalog byte for byte", () => {
  expect(renderCatalog(ROOT)).toBe(readFileSync(join(ROOT, "catalog/rules.json"), "utf8"));
});
test("builds deterministic rules with metadata, paths and reference labels", () => {
  const root = validRepo();
  const rules = buildRules(root);
  expect(rules).toHaveLength(2);
  expect(rules[0]).toMatchObject({
    ...metadata(),
    path: GUIDE,
    references: [
      { label: "CWE-79", url: "https://cwe.mitre.org/data/definitions/79.html" },
      { label: "OWASP Injection", url: "https://owasp.org/Top10/2025/A05_2025-Injection/" },
    ],
  });
  expect(renderCatalog(root)).toBe(renderCatalog(root));
  expect(renderCatalog(root)).toMatch(/\n$/);
  write(root, "guides/injection/xss/notes/note.md", "# A note\n");
  expect(buildRules(root)).toEqual(rules);
});
test("duplicate IDs report both paths", () => {
  const root = validRepo();
  write(root, "guides/injection/xss/duplicate.md", guide());
  expect(() => buildRules(root)).toThrow(/duplicate rule id.*duplicate.md.*example.md/);
});
test.each([
  ["CWE-79", "CWE-89", "matching reference"],
  ["A05:2025 Injection", "A01:2025 Broken Access Control", "matching reference"],
  ["## References", "## Other", "at least one reference"],
  ["default_severity: high", "default_severity: invalid", "default_severity"],
])("rejects catalog metadata/reference mismatch %s", (from, to, diagnostic) => {
  const root = validRepo();
  replace(root, GUIDE, from, to);
  expect(() => buildRules(root)).toThrow(diagnostic);
});
test("normalizes scheme/hostname and removes query/fragment for canonical references", () => {
  expect(canonicalReferenceUrl("HTTPS://CWE.MITRE.ORG/data/definitions/79.html?x=1#part")).toBe(
    "https://cwe.mitre.org/data/definitions/79.html",
  );
  expect(canonicalReferenceUrl("invalid")).toBe("invalid");
  expect(expectedCweReference("CWE-79")).toBe("https://cwe.mitre.org/data/definitions/79.html");
  expect(expectedCweReference("CWE-no")).toBeUndefined();
  expect(expectedOwaspTop10Reference("A07:2025 Authentication Failures")).toBe(
    "https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/",
  );
  expect(expectedOwaspTop10Reference("invalid")).toBeUndefined();
});
test("writes only when valid, detects missing/stale output and leaves check mode read-only", () => {
  silence();
  const root = validRepo();
  expect(() => main(["--check"], root)).toThrow("out of date");
  expect(existsSync(join(root, "catalog/rules.json"))).toBe(false);
  expect(main([], root)).toBe(0);
  const catalog = read(root, "catalog/rules.json");
  expect(main(["--check"], root)).toBe(0);
  expect(main([], root)).toBe(0);
  replace(root, GUIDE, "URL-derived Input", "Changed Input");
  expect(() => main(["--check"], root)).toThrow("out of date");
  expect(read(root, "catalog/rules.json")).toBe(catalog);
  write(root, GUIDE, guide({ ...metadata(), title: "" }, BODY));
  expect(() => main([], root)).toThrow("title");
  expect(read(root, "catalog/rules.json")).toBe(catalog);
  expect(() => main(["--typo"], root)).toThrow("Usage");
});
test("aggregates malformed guide diagnostics", () => {
  const root = validRepo();
  write(root, GUIDE, "bad");
  write(root, "guides/injection/bad.md", '---\ntitle: "unterminated\n---');
  expect(() => buildRules(root)).toThrow(/invalid YAML[\s\S]*missing YAML frontmatter/);
});
