import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, vi } from "vitest";
import { stringify } from "yaml";
import type { Mapping } from "../runtime.ts";

const temporary: string[] = [];
afterEach(() => {
  for (const path of temporary.splice(0)) rmSync(path, { recursive: true, force: true });
  vi.restoreAllMocks();
});

export function tempRepo(): string {
  const path = mkdtempSync(join(tmpdir(), "web-of-flaws-"));
  temporary.push(path);
  return path;
}

export function write(root: string, path: string, content: string): void {
  const destination = join(root, path);
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, content, "utf8");
}
export function read(root: string, path: string): string {
  return readFileSync(join(root, path), "utf8");
}
export function replace(root: string, path: string, from: string, to: string): void {
  write(root, path, read(root, path).replace(from, to));
}

export const GUIDE = "guides/injection/xss/example.md";
export const README = "guides/injection/xss/README.md";
export const STANDARDS = "catalog/standards/owasp-2025.json";
export const DOMAINS = "catalog/allowed-reference-domains.json";
export function metadata(): Mapping {
  return {
    id: "WOF-XSS-001",
    title: "URL-derived Input to HTML Sink (innerHTML)",
    kind: "vulnerability",
    default_severity: "high",
    exploitability: "high",
    standards: { cwe: ["CWE-79"], owasp_top_10: ["A05:2025 Injection"] },
    platforms: ["browser"],
    languages: ["html", "javascript"],
    detection: { type: "dataflow", methods: ["grep", "ast"], candidate_tokens: ["innerHTML", "URLSearchParams"] },
    sources: ["window.location.search"],
    sinks: ["Element.innerHTML"],
    tags: ["xss", "dom-xss"],
  };
}

export const BODY = `## Rule

Example body.

## Example Attack

\`\`\`text
https://attacker.test/payload
\`\`\`

## References

- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)

## Quick Checklist
`;
export function guide(data = metadata(), body = BODY): string {
  return `---\n${stringify(data)}---\n\n${body}`;
}

export function validRepo(): string {
  const root = tempRepo();
  write(
    root,
    STANDARDS,
    JSON.stringify({
      "A05:2025 Injection": { cwes: ["CWE-79"] },
      "A07:2025 Authentication Failures": { cwes: ["CWE-798"] },
    }),
  );
  write(
    root,
    DOMAINS,
    JSON.stringify({
      schema_version: 1,
      domains: [
        { domain: "cwe.mitre.org", scopes: ["guide-references"], purpose: "CWE references" },
        { domain: "owasp.org", scopes: ["guide-references"], purpose: "OWASP references" },
        { domain: "example.com", scopes: ["example-urls"], purpose: "Example URLs" },
      ],
    }),
  );
  write(root, "guides/injection/README.md", "# Injection\n\n- [XSS](xss/README.md)\n");
  write(root, README, "# Cross-site scripting (XSS)\n\n- [Example](example.md)\n");
  write(root, GUIDE, guide());
  const secrets = metadata();
  Object.assign(secrets, {
    id: "WOF-SDE-001",
    title: "Hard-coded Secrets",
    exploitability: "medium",
    standards: { cwe: ["CWE-798"], owasp_top_10: ["A07:2025 Authentication Failures"] },
    platforms: ["server"],
    languages: ["javascript"],
    detection: { type: "semantic-pattern", methods: ["grep", "semantic-review"], candidate_tokens: ["SECRET"] },
    indicators: ["variables named SECRET"],
    tags: ["secrets"],
  });
  delete secrets.sources;
  delete secrets.sinks;
  write(root, "guides/sensitive-data-exposure/README.md", "# Sensitive Data Exposure\n\n- [Secrets](secrets.md)\n");
  write(
    root,
    "guides/sensitive-data-exposure/secrets.md",
    guide(
      secrets,
      BODY.replaceAll("CWE-79", "CWE-798")
        .replace("/79.html", "/798.html")
        .replace("A05_2025-Injection", "A07_2025-Authentication_Failures"),
    ),
  );
  mkdirSync(join(root, ".github"));
  return root;
}

export function silence(): { stdout: ReturnType<typeof vi.spyOn>; stderr: ReturnType<typeof vi.spyOn> } {
  return {
    stdout: vi.spyOn(console, "log").mockImplementation(() => {}),
    stderr: vi.spyOn(console, "error").mockImplementation(() => {}),
  };
}
