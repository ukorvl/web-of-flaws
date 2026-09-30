import { readFileSync } from "node:fs";
import { basename, join, relative, sep } from "node:path";
import { isAlias, isCollection, isMap, isScalar, parseDocument, visit } from "yaml";
import { isMapping, type Mapping, nonEmptyString, walk } from "./runtime.ts";

export const CWE_ID_RE = /^CWE-\d+$/;
export const OWASP_TOP_10_RE = /^(A\d{2}):(\d{4}) (.+)$/;
export const MARKDOWN_LINK_RE = /\[([^\]]+)\]\(((?:https?:)?\/\/[^)\s]+)\)/gi;
export const URL_RE = /(?:https?:)?\/\/[^\s)>`]+/gi;
const RULE_KEYS = new Set([
  "id",
  "title",
  "kind",
  "default_severity",
  "exploitability",
  "standards",
  "platforms",
  "languages",
  "detection",
  "sources",
  "sinks",
  "indicators",
  "tags",
]);
const REQUIRED_KEYS = [
  "id",
  "title",
  "kind",
  "default_severity",
  "exploitability",
  "standards",
  "platforms",
  "languages",
  "detection",
  "tags",
];
export class GuideValidationError extends Error {}
export interface Reference {
  label: string;
  url: string;
}

export function isGuideNotePath(path: string, guidesRoot?: string): boolean {
  return (guidesRoot === undefined ? path : relative(guidesRoot, path)).split(sep).includes("notes");
}

export function iterGuideMarkdownPaths(root: string): string[] {
  return walk(join(root, "guides")).filter((path) => path.endsWith(".md") && basename(path) !== "AGENTS.md");
}

export function iterGuideRulePaths(root: string): string[] {
  return iterGuideMarkdownPaths(root).filter(
    (path) => basename(path) !== "README.md" && !isGuideNotePath(path, join(root, "guides")),
  );
}

export function splitFrontmatter(text: string, path: string): [string, string] {
  const lines = text.replaceAll("\r\n", "\n").split("\n");
  if (lines[0]?.trim() !== "---") throw new GuideValidationError(`${path}: guide is missing YAML frontmatter`);
  const end = lines.findIndex((line, index) => index > 0 && line.trim() === "---");
  if (end === -1) throw new GuideValidationError(`${path}: guide frontmatter is not closed`);
  return [lines.slice(1, end).join("\n"), lines.slice(end + 1).join("\n")];
}

export function parseYamlMapping(text: string, path: string): Mapping {
  // Failsafe scalars remain strings, preserving the catalog's metadata contract.
  const document = parseDocument(text, { schema: "failsafe", uniqueKeys: true, strict: true });
  if (document.errors.length || document.warnings.length) {
    throw new GuideValidationError(
      `${path}: invalid YAML: ${[...document.errors, ...document.warnings].map((e) => e.message).join("; ")}`,
    );
  }
  if (!isMap(document.contents)) throw new GuideValidationError(`${path}: frontmatter root must be a mapping`);
  visit(document, (_key, node, ancestors) => {
    if (ancestors.length > 32) throw new GuideValidationError(`${path}: YAML nesting exceeds 32 levels`);
    if (
      isAlias(node) ||
      ((isScalar(node) || isCollection(node)) &&
        (node.anchor ||
          node.tag ||
          (isCollection(node) && node.flow) ||
          (isScalar(node) && ["BLOCK_FOLDED", "BLOCK_LITERAL"].includes(node.type ?? ""))))
    ) {
      throw new GuideValidationError(
        `${path}: unsupported YAML syntax; use block collections and quoted parser-sensitive values`,
      );
    }
    if (isScalar(node) && node.type === "PLAIN" && node.comment) {
      throw new GuideValidationError(`${path}: unsupported plain YAML scalar; quote parser-sensitive values`);
    }
    if (isMap(node)) {
      for (const pair of node.items) {
        if (
          !isScalar(pair.key) ||
          !nonEmptyString(pair.key.value) ||
          ["__proto__", "constructor", "prototype"].includes(pair.key.value)
        ) {
          throw new GuideValidationError(`${path}: YAML keys must be safe non-empty strings`);
        }
      }
    }
  });
  const result: unknown = document.toJS({ maxAliasCount: 0 });
  if (!isMapping(result)) throw new GuideValidationError(`${path}: frontmatter root must be a mapping`);
  return result;
}

export function loadGuide(path: string): [Mapping, string] {
  const [metadata, body] = splitFrontmatter(readFileSync(path, "utf8"), path);
  return [parseYamlMapping(metadata, path), body];
}

export type Fence = readonly [string, number] | null;
export function updateCodeFenceState(stripped: string, fence: Fence): Fence {
  const marker = /^(`{3,}|~{3,})/.exec(stripped)?.[1];
  if (!marker) return fence;
  if (!fence) return [marker[0] as string, marker.length];
  if (marker[0] === fence[0] && marker.length >= fence[1] && stripped.slice(marker.length).trim() === "") return null;
  return fence;
}

export function* iterRenderedLines(markdown: string): Generator<readonly [number, string, string]> {
  let fence: Fence = null;
  for (const [index, line] of markdown.split(/\r?\n/).entries()) {
    const stripped = line.trim();
    const next = updateCodeFenceState(stripped, fence);
    if (next !== fence) {
      fence = next;
      continue;
    }
    if (fence) continue;
    yield [index + 1, stripped, line.replace(/(`+).*?\1/g, (code) => " ".repeat(code.length))];
  }
}

export function parseReferences(body: string): Reference[] {
  const references: Reference[] = [];
  const originalLines = body.split(/\r?\n/);
  let inReferences = false;
  for (const [number, stripped, scrubbed] of iterRenderedLines(body)) {
    if (stripped === "## References") {
      inReferences = true;
      continue;
    }
    if (inReferences && stripped.startsWith("## ")) break;
    if (!inReferences) continue;
    for (const match of scrubbed.matchAll(MARKDOWN_LINK_RE)) {
      const label = originalLines[number - 1]?.slice(match.index + 1, match.index + 1 + (match[1]?.length ?? 0));
      references.push({ label: label ?? "", url: match[2] as string });
    }
  }
  return references;
}

export function urlsInLine(line: string): string[] {
  return [...line.matchAll(MARKDOWN_LINK_RE)]
    .map((match) => match[2] as string)
    .concat([...line.replace(MARKDOWN_LINK_RE, "").matchAll(URL_RE)].map((match) => match[0]));
}

export function renderedUrls(markdown: string): [string, number][] {
  return [...iterRenderedLines(markdown)].flatMap(([number, , line]) =>
    urlsInLine(line).map((url): [string, number] => [url, number]),
  );
}

export function validateStringList(
  value: unknown,
  path: string,
  field: string,
  allowed?: readonly string[],
  missingMessage?: string,
): string[] {
  if (!Array.isArray(value) || !value.length)
    return [`${path}: ${missingMessage ?? `${field} must be a non-empty list`}`];
  return value.flatMap((item: unknown) => {
    if (!nonEmptyString(item)) return [`${path}: ${field} entries must be non-empty strings`];
    if (allowed && !allowed.includes(item))
      return [`${path}: ${field} value ${JSON.stringify(item)} must be one of ${[...allowed].sort().join(", ")}`];
    return [];
  });
}

export function validateFrontmatter(frontmatter: Mapping, path: string): string[] {
  const errors: string[] = [];
  const extra = (mapping: Mapping, allowed: ReadonlySet<string>, field: string): void => {
    const keys = Object.keys(mapping)
      .filter((key) => !allowed.has(key))
      .sort();
    if (keys.length) errors.push(`${path}: unexpected ${field} keys: ${keys.join(", ")}`);
  };
  extra(frontmatter, RULE_KEYS, "frontmatter");
  for (const key of REQUIRED_KEYS)
    if (!Object.hasOwn(frontmatter, key)) errors.push(`${path}: missing frontmatter key ${key}`);
  for (const field of ["id", "title", "kind", "default_severity", "exploitability"]) {
    if (!nonEmptyString(frontmatter[field])) errors.push(`${path}: ${field} must be a non-empty string`);
  }
  if (nonEmptyString(frontmatter.id) && !/^WOF-[A-Z0-9]+-\d{3}$/.test(frontmatter.id))
    errors.push(`${path}: id must match ^WOF-[A-Z0-9]+-\\d{3}$`);
  for (const [field, allowed] of Object.entries({
    kind: ["vulnerability", "weakness", "hardening-gap"],
    default_severity: ["low", "medium", "high", "critical"],
    exploitability: ["low", "medium", "high"],
  })) {
    const value = frontmatter[field];
    if (nonEmptyString(value) && !allowed.includes(value))
      errors.push(`${path}: ${field} must be one of ${allowed.sort().join(", ")}`);
  }
  errors.push(
    ...validateStringList(frontmatter.platforms, path, "platforms", [
      "browser",
      "server",
      "mobile",
      "desktop",
      "ci-cd",
      "infrastructure",
      "cloud",
      "container",
    ]),
  );
  errors.push(
    ...validateStringList(frontmatter.languages, path, "languages", [
      "html",
      "javascript",
      "typescript",
      "yaml",
      "dotenv",
      "json",
      "css",
      "python",
      "shell",
      "bash",
      "sql",
      "terraform",
    ]),
  );
  if (!Array.isArray(frontmatter.tags) || !frontmatter.tags.length)
    errors.push(`${path}: tags must be a non-empty list`);
  else
    for (const tag of frontmatter.tags) {
      if (typeof tag !== "string" || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(tag))
        errors.push(`${path}: tag ${JSON.stringify(tag)} must be lowercase-kebab-case`);
    }
  const standards = frontmatter.standards;
  if (!isMapping(standards)) errors.push(`${path}: standards must be a mapping`);
  else {
    extra(standards, new Set(["cwe", "owasp_top_10"]), "standards");
    for (const [field, pattern] of [
      ["cwe", CWE_ID_RE],
      ["owasp_top_10", OWASP_TOP_10_RE],
    ] as const) {
      const values = standards[field];
      if (!Array.isArray(values) || !values.length) errors.push(`${path}: standards.${field} must be a non-empty list`);
      else
        for (const value of values)
          if (typeof value !== "string" || !pattern.test(value))
            errors.push(`${path}: standards.${field} value ${JSON.stringify(value)} must match ${pattern.source}`);
    }
  }
  const detection = frontmatter.detection;
  if (!isMapping(detection)) return [...errors, `${path}: detection must be a mapping`];
  extra(detection, new Set(["type", "methods", "candidate_tokens"]), "detection");
  if (!["dataflow", "semantic-pattern"].includes(String(detection.type)))
    errors.push(`${path}: detection.type must be one of dataflow, semantic-pattern`);
  errors.push(
    ...validateStringList(detection.methods, path, "detection.methods", [
      "grep",
      "ast",
      "taint-analysis",
      "semantic-review",
      "entropy-analysis",
    ]),
  );
  if (Object.hasOwn(detection, "candidate_tokens"))
    errors.push(...validateStringList(detection.candidate_tokens, path, "detection.candidate_tokens"));
  if (detection.type === "dataflow" || detection.type === "semantic-pattern") {
    const required = detection.type === "dataflow" ? ["sources", "sinks"] : ["indicators"];
    const forbidden = detection.type === "dataflow" ? ["indicators"] : ["sources", "sinks"];
    for (const field of required)
      errors.push(
        ...validateStringList(
          frontmatter[field],
          path,
          field,
          undefined,
          `${detection.type} guides must declare non-empty ${field}`,
        ),
      );
    for (const field of forbidden)
      if (Object.hasOwn(frontmatter, field)) errors.push(`${path}: ${detection.type} guides must not declare ${field}`);
  }
  return errors;
}
