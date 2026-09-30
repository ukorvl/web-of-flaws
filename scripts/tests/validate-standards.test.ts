import { rmSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";
import { loadOwasp2025, main, validate } from "../validate-standards.ts";
import { GUIDE, replace, STANDARDS, silence, validRepo, write } from "./support.ts";

test("accepts declared direct relationships", () => {
  expect(validate(validRepo())).toEqual([]);
});
test.each([
  ["CWE-79", "CWE-999", 'standards.cwe entry "CWE-999" is not declared'],
  ["A05:2025 Injection", "A10:2025 Mishandled Exceptions", "standards.owasp_top_10 entry"],
  ["A05:2025 Injection", "A07:2025 Authentication Failures", "direct CWE/OWASP relationship"],
])("rejects invalid mapping %s", (from, to, message) => {
  const root = validRepo();
  replace(root, GUIDE, from, to);
  const errors = validate(root);
  expect(errors).toHaveLength(1);
  expect(errors[0]).toContain(message);
});
test.each([
  ["{bad", "invalid JSON"],
  ["{}", "non-empty JSON object"],
  ["[]", "non-empty JSON object"],
  ['{"bad":{"cwes":["CWE-79"]}}', "OWASP entry"],
  ['{"A05:2025 Injection":[]}', "containing only cwes"],
  ['{"A05:2025 Injection":{"cwes":[],"extra":true}}', "containing only cwes"],
  ['{"A05:2025 Injection":{"cwes":[]}}', "non-empty list"],
  ['{"A05:2025 Injection":{"cwes":[null]}}', "invalid CWE values"],
  ['{"A05:2025 Injection":{"cwes":["CWE-79","CWE-79"]}}', "duplicates"],
])("rejects malformed standards dataset %s", (input, diagnostic) => {
  const root = validRepo();
  write(root, STANDARDS, input);
  expect(() => loadOwasp2025(root)).toThrow(diagnostic);
  expect(validate(root).join("\n")).toContain(diagnostic);
});
test("reports missing dataset and invalid guide parsing", () => {
  const root = validRepo();
  write(root, GUIDE, "invalid");
  expect(validate(root).join("\n")).toContain("missing YAML");
  rmSync(join(root, STANDARDS));
  expect(validate(root).join("\n")).toContain(STANDARDS);
});
test("CLI succeeds for valid input and fails for invalid input", () => {
  silence();
  const root = validRepo();
  expect(main([], root)).toBe(0);
  write(root, STANDARDS, "bad");
  expect(main([], root)).toBe(1);
  expect(() => main(["--bad"], root)).toThrow("Usage");
});
