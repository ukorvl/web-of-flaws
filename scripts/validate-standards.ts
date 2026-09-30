import { join } from "node:path";
import { CWE_ID_RE, GuideValidationError, iterGuideRulePaths, loadGuide, OWASP_TOP_10_RE } from "./guide-tools.ts";
import { isMapping, message, ROOT, readJson, runCli } from "./runtime.ts";

export const OWASP_2025_PATH = "catalog/standards/owasp-2025.json";
export class StandardsValidationError extends Error {}

export function loadOwasp2025(root: string): Map<string, Set<string>> {
  const raw = readJson(join(root, OWASP_2025_PATH));
  if (!isMapping(raw) || !Object.keys(raw).length)
    throw new StandardsValidationError(`${OWASP_2025_PATH}: root must be a non-empty JSON object`);
  const errors: string[] = [];
  const mappings = new Map<string, Set<string>>();
  for (const [owasp, entry] of Object.entries(raw)) {
    const prefix = `${OWASP_2025_PATH}: ${JSON.stringify(owasp)}`;
    if (!OWASP_TOP_10_RE.test(owasp)) {
      errors.push(`${prefix}: OWASP entry must match ${OWASP_TOP_10_RE.source}`);
      continue;
    }
    if (!isMapping(entry) || Object.keys(entry).length !== 1 || !Object.hasOwn(entry, "cwes")) {
      errors.push(`${prefix} must be an object containing only cwes`);
      continue;
    }
    if (!Array.isArray(entry.cwes) || !entry.cwes.length) {
      errors.push(`${prefix}.cwes must be a non-empty list`);
      continue;
    }
    if (!entry.cwes.every((cwe: unknown): cwe is string => typeof cwe === "string" && CWE_ID_RE.test(cwe))) {
      errors.push(`${prefix}.cwes contains invalid CWE values`);
      continue;
    }
    if (new Set(entry.cwes).size !== entry.cwes.length) {
      errors.push(`${prefix}.cwes must not contain duplicates`);
      continue;
    }
    mappings.set(owasp, new Set(entry.cwes));
  }
  if (errors.length) throw new StandardsValidationError(errors.sort().join("\n"));
  return mappings;
}

export function validate(root: string): string[] {
  let mappings: Map<string, Set<string>>;
  try {
    mappings = loadOwasp2025(root);
  } catch (error) {
    return message(error).split("\n");
  }
  const errors: string[] = [];
  const declared = new Set([...mappings.values()].flatMap((values) => [...values]));
  for (const path of iterGuideRulePaths(root)) {
    try {
      const [metadata] = loadGuide(path);
      if (!isMapping(metadata.standards)) continue;
      const { cwe, owasp_top_10: owasp } = metadata.standards;
      if (!Array.isArray(cwe) || !Array.isArray(owasp)) continue;
      const cwes = cwe.filter((value: unknown): value is string => typeof value === "string" && CWE_ID_RE.test(value));
      const categories = owasp.filter(
        (value: unknown): value is string => typeof value === "string" && OWASP_TOP_10_RE.test(value),
      );
      for (const entry of cwes)
        if (!declared.has(entry))
          errors.push(`${path}: standards.cwe entry ${JSON.stringify(entry)} is not declared in ${OWASP_2025_PATH}`);
      for (const entry of categories) {
        const allowed = mappings.get(entry);
        if (!allowed) {
          errors.push(
            `${path}: standards.owasp_top_10 entry ${JSON.stringify(entry)} is not declared in ${OWASP_2025_PATH}`,
          );
          continue;
        }
        for (const id of cwes)
          if (declared.has(id) && !allowed.has(id))
            errors.push(
              `${path}: direct CWE/OWASP relationship ${JSON.stringify(id)} -> ${JSON.stringify(entry)} is not declared in ${OWASP_2025_PATH}`,
            );
      }
    } catch (error) {
      if (!(error instanceof GuideValidationError)) throw error;
      errors.push(message(error));
    }
  }
  return errors.sort();
}

export function main(args: string[], root = ROOT): number {
  if (args.length) throw new Error("Usage: validate-standards.ts");
  const errors = validate(root);
  if (errors.length) {
    console.error(errors.join("\n"));
    console.error(`Standards validation failed with ${errors.length} error(s).`);
    return 1;
  }
  console.log("Standards validation passed.");
  return 0;
}
runCli(import.meta.url, main);
