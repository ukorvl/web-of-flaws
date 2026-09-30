import { join } from "node:path";
import {
  CWE_ID_RE,
  GuideValidationError,
  iterGuideRulePaths,
  loadGuide,
  OWASP_TOP_10_RE,
  parseReferences,
  type Reference,
  validateFrontmatter,
} from "./guide-tools.ts";
import { checkFlag, displayPath, isMapping, type Mapping, message, ROOT, runCli, writeGenerated } from "./runtime.ts";

export function canonicalReferenceUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.protocol.toLowerCase()}//${parsed.host.toLowerCase()}${parsed.pathname}`;
  } catch {
    return url;
  }
}

export function expectedCweReference(id: string): string | undefined {
  return CWE_ID_RE.test(id) ? `https://cwe.mitre.org/data/definitions/${id.slice(4)}.html` : undefined;
}

export function expectedOwaspTop10Reference(entry: string): string | undefined {
  const match = OWASP_TOP_10_RE.exec(entry);
  if (!match) return undefined;
  return `https://owasp.org/Top10/${match[2]}/${match[1]}_${match[2]}-${match[3]?.trim().replace(/\s+/g, "_")}/`;
}

export function validateStandardReferences(frontmatter: Mapping, references: Reference[], path: string): string[] {
  if (!isMapping(frontmatter.standards)) return [];
  const urls = new Set(references.map((ref) => canonicalReferenceUrl(ref.url)));
  const errors: string[] = [];
  for (const [field, expectedUrl] of [
    ["cwe", expectedCweReference],
    ["owasp_top_10", expectedOwaspTop10Reference],
  ] as const) {
    const entries = frontmatter.standards[field];
    if (!Array.isArray(entries)) continue;
    for (const entry of entries) {
      if (typeof entry !== "string") continue;
      const expected = expectedUrl(entry);
      if (expected && !urls.has(expected))
        errors.push(
          `${path}: standards.${field} entry ${JSON.stringify(entry)} must have matching reference ${expected}`,
        );
    }
  }
  return errors;
}

export function buildRules(root: string): Mapping[] {
  const errors: string[] = [];
  const rules: Mapping[] = [];
  const seenIds = new Map<string, string>();
  for (const path of iterGuideRulePaths(root)) {
    let metadata: Mapping;
    let body: string;
    try {
      [metadata, body] = loadGuide(path);
    } catch (error) {
      if (!(error instanceof GuideValidationError)) throw error;
      errors.push(message(error));
      continue;
    }
    errors.push(...validateFrontmatter(metadata, path));
    const references = parseReferences(body);
    if (!references.length) errors.push(`${path}: guide must declare at least one reference under ## References`);
    else errors.push(...validateStandardReferences(metadata, references, path));
    const relative = displayPath(root, path);
    if (typeof metadata.id === "string") {
      const previous = seenIds.get(metadata.id);
      if (previous) errors.push(`duplicate rule id ${JSON.stringify(metadata.id)}: ${previous} and ${relative}`);
      else seenIds.set(metadata.id, relative);
    }
    const rule: Mapping = {};
    for (const [key, value] of Object.entries(metadata)) {
      rule[key] = value;
      if (key === "id") rule.path = relative;
    }
    rule.path = relative;
    rule.references = references;
    rules.push(rule);
  }
  if (errors.length) throw new GuideValidationError(errors.sort().join("\n"));
  return rules;
}

export function renderCatalog(root: string): string {
  return `${JSON.stringify({ schema_version: 1, rules: buildRules(root) }, null, 2)}\n`;
}

export function main(args: string[], root = ROOT): number {
  const check = checkFlag(args);
  const content = renderCatalog(root);
  const updated = writeGenerated(join(root, "catalog/rules.json"), content, check, "pnpm generate:catalog");
  console.log(`catalog/rules.json is ${updated ? "updated" : "up to date"}.`);
  return 0;
}
runCli(import.meta.url, main);
