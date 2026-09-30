import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { buildRules } from "./generate-catalog.ts";
import {
  GuideValidationError,
  isGuideNotePath,
  iterGuideMarkdownPaths,
  iterRenderedLines,
  urlsInLine,
} from "./guide-tools.ts";
import { displayPath, isMapping, message, nonEmptyString, ROOT, readJson, runCli } from "./runtime.ts";

export const ALLOWED_REFERENCE_DOMAINS_PATH = "catalog/allowed-reference-domains.json";
const HOSTNAME_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const LOCAL_MARKDOWN_LINK_RE = /\[([^\]]+)\]\(((?![a-z][a-z0-9+.-]*:|\/\/)[^)\s]+\.md)(?:#[^)]+)?\)/gi;
export class AllowedDomainsValidationError extends Error {}

export function loadAllowedDomains(root: string): Map<string, Set<string>> {
  const path = ALLOWED_REFERENCE_DOMAINS_PATH;
  const raw = readJson(join(root, path));
  if (!isMapping(raw)) throw new AllowedDomainsValidationError(`${path}: root must be a JSON object`);
  const errors: string[] = [];
  const scopes = new Map<string, Set<string>>();
  if (raw.schema_version !== 1) errors.push(`${path}: schema_version must equal 1`);
  if (!Array.isArray(raw.domains) || !raw.domains.length) errors.push(`${path}: domains must be a non-empty list`);
  const domains: unknown[] = Array.isArray(raw.domains) ? raw.domains : [];
  for (const [index, entry] of domains.entries()) {
    const prefix = `${path}: domains[${index}]`;
    if (!isMapping(entry)) {
      errors.push(`${prefix} must be an object`);
      continue;
    }
    const { domain, scopes: scopeList, purpose } = entry;
    const validDomain = typeof domain === "string" && HOSTNAME_RE.test(domain);
    if (!nonEmptyString(domain)) errors.push(`${prefix}.domain must be a non-empty string`);
    else if (!validDomain) errors.push(`${prefix}.domain must be a non-empty lowercase hostname`);
    if (!nonEmptyString(purpose)) errors.push(`${prefix}.purpose must be a non-empty string`);
    if (!Array.isArray(scopeList) || !scopeList.length) {
      errors.push(`${prefix}.scopes must be a non-empty list`);
      continue;
    }
    for (const [scopeIndex, scope] of scopeList.entries()) {
      if (!nonEmptyString(scope)) {
        errors.push(`${prefix}.scopes[${scopeIndex}] must be a non-empty string`);
        continue;
      }
      if (!["guide-references", "example-urls"].includes(scope)) {
        errors.push(`${prefix}.scopes[${scopeIndex}] must be one of: example-urls, guide-references`);
        continue;
      }
      if (!validDomain || typeof domain !== "string") continue;
      const set = scopes.get(scope) ?? new Set<string>();
      if (set.has(domain))
        errors.push(
          `${path}: duplicate domain/scope combination for ${JSON.stringify(domain)} and ${JSON.stringify(scope)}`,
        );
      set.add(domain);
      scopes.set(scope, set);
    }
  }
  if (errors.length) throw new AllowedDomainsValidationError(errors.join("\n"));
  return scopes;
}

export function renderedUrlsWithScopes(markdown: string): [string, number, string][] {
  let section = "";
  return [...iterRenderedLines(markdown)].flatMap(([number, stripped, line]) => {
    if (stripped.startsWith("## ")) section = stripped.slice(3).trim();
    return urlsInLine(line).map((url): [string, number, string] => [
      url,
      number,
      section === "References" ? "guide-references" : "example-urls",
    ]);
  });
}

export function stripHtmlCommentsPreserveLines(markdown: string): string {
  return markdown.replace(/<!--[\s\S]*?-->/g, (comment) => comment.replace(/[^\n]/g, " "));
}

export function localMarkdownLinks(path: string): [string, number][] {
  return [...iterRenderedLines(stripHtmlCommentsPreserveLines(readFileSync(path, "utf8")))].flatMap(
    ([number, , line]) =>
      [...line.matchAll(LOCAL_MARKDOWN_LINK_RE)].map((match): [string, number] => [match[2] as string, number]),
  );
}

export function referenceStyleMarkdownLines(path: string): number[] {
  return [...iterRenderedLines(stripHtmlCommentsPreserveLines(readFileSync(path, "utf8")))]
    .filter(([, , line]) => /(?<!!)\[[^\]]+\]\[[^\]]*\]/.test(line) || /^\s*\[[^\]]+\]:\s+\S+/.test(line))
    .map(([number]) => number);
}

export function nearestReadmeFor(path: string, root: string): string | undefined {
  const guidesRoot = resolve(root, "guides");
  let current = dirname(resolve(path));
  while (current === guidesRoot || current.startsWith(`${guidesRoot}${sep}`)) {
    const candidate = join(current, "README.md");
    if (existsSync(candidate)) return candidate;
    if (current === guidesRoot) break;
    current = dirname(current);
  }
  return undefined;
}

export function lintGuideIndexes(root: string): string[] {
  const errors: string[] = [];
  const counts = new Map<string, number>();
  const paths = iterGuideMarkdownPaths(root);
  const key = (readme: string, path: string): string => JSON.stringify([realpathSync(readme), realpathSync(path)]);
  for (const readme of paths.filter((path) => basename(path) === "README.md")) {
    for (const number of referenceStyleMarkdownLines(readme))
      errors.push(`${readme}:${number}: category indexes must use inline Markdown links, not reference-style links`);
    for (const [target, number] of localMarkdownLinks(readme)) {
      const resolved = resolve(dirname(readme), target);
      if (!existsSync(resolved) || !statSync(resolved).isFile()) {
        errors.push(`${readme}:${number}: linked markdown target does not exist: ${target}`);
        continue;
      }
      const pair = key(readme, resolved);
      counts.set(pair, (counts.get(pair) ?? 0) + 1);
    }
  }
  // Parent indexes may omit nested categories; this preserves the existing index contract.
  for (const path of paths.filter((path) => basename(path) !== "README.md")) {
    const nearest = nearestReadmeFor(path, root);
    if (!nearest) {
      errors.push(`${path}: could not find nearest README.md index`);
      continue;
    }
    const count = counts.get(key(nearest, path)) ?? 0;
    const kind = isGuideNotePath(path, join(root, "guides")) ? "note" : "guide";
    if (count !== 1)
      errors.push(
        `${path}: nearest index ${displayPath(root, nearest)} must link to this ${kind} exactly once (found ${count})`,
      );
  }
  return errors;
}

export function lint(root: string): string[] {
  const errors: string[] = [];
  try {
    buildRules(root);
  } catch (error) {
    if (!(error instanceof GuideValidationError)) throw error;
    errors.push(...message(error).split("\n"));
  }
  errors.push(...lintGuideIndexes(root));
  let allowed: Map<string, Set<string>>;
  try {
    allowed = loadAllowedDomains(root);
  } catch (error) {
    return [...errors, ...message(error).split("\n")].sort();
  }
  for (const path of iterGuideMarkdownPaths(root)) {
    for (const [url, number, scope] of renderedUrlsWithScopes(readFileSync(path, "utf8"))) {
      let hostname: string;
      try {
        hostname = new URL(url.startsWith("//") ? `https:${url}` : url).hostname;
      } catch {
        errors.push(`${path}:${number}: could not determine hostname for ${url}`);
        continue;
      }
      if (!hostname) errors.push(`${path}:${number}: could not determine hostname for ${url}`);
      else if (!allowed.get(scope)?.has(hostname))
        errors.push(
          `${path}:${number}: hostname ${JSON.stringify(hostname)} is not allowlisted for scope ${JSON.stringify(scope)}`,
        );
    }
  }
  return [...new Set(errors)].sort();
}

export function main(args: string[], root = ROOT): number {
  if (args.length) throw new Error("Usage: lint-repo.ts");
  const errors = lint(root);
  if (errors.length) {
    console.error(errors.join("\n"));
    console.error(`Repository lint failed with ${errors.length} error(s).`);
    return 1;
  }
  console.log("Repository lint passed.");
  return 0;
}
runCli(import.meta.url, main);
