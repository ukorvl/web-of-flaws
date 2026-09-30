import { rmSync } from "node:fs";
import { join } from "node:path";
import { expect, test } from "vitest";
import {
  lint,
  lintGuideIndexes,
  loadAllowedDomains,
  main,
  nearestReadmeFor,
  renderedUrlsWithScopes,
  stripHtmlCommentsPreserveLines,
} from "../lint-repo.ts";
import { DOMAINS, GUIDE, README, read, replace, silence, validRepo, write } from "./support.ts";

test("valid repository passes and ignores URLs in code fences and inline code", () => {
  const root = validRepo();
  expect(lint(root)).toEqual([]);
  replace(root, GUIDE, "```text", "~~~text");
  replace(root, GUIDE, "```", "~~~");
  expect(lint(root)).toEqual([]);
});
test.each(["https://evil.test/x", "HTTPS://EVIL.TEST/x", "//evil.test/x"])(
  "rejects unallowlisted rendered URL %s",
  (url) => {
    const root = validRepo();
    replace(root, GUIDE, "## Quick Checklist", `- [Bad](${url})\n\n## Quick Checklist`);
    expect(lint(root).join("\n")).toContain('hostname "evil.test" is not allowlisted for scope "guide-references"');
  },
);
test("uses scopes, exact hostnames and actionable URL parse failures", () => {
  const root = validRepo();
  replace(
    root,
    GUIDE,
    "Example body.",
    "https://example.com/okay\nhttps://sub.example.com/no\nhttps://owasp.org/not-an-example\nhttps://[bad",
  );
  const errors = lint(root).join("\n");
  expect(errors).toContain("sub.example.com");
  expect(errors).toContain("example-urls");
  expect(errors).toContain("could not determine hostname");
  expect(errors).not.toContain('"example.com"');
  expect(
    renderedUrlsWithScopes("https://example.com\n## References\nhttps://owasp.org\n## Other\nhttps://example.com"),
  ).toEqual([
    ["https://example.com", 1, "example-urls"],
    ["https://owasp.org", 3, "guide-references"],
    ["https://example.com", 5, "example-urls"],
  ]);
});
test.each([
  ["broken", "invalid JSON"],
  ["[]", "root must be"],
  ['{"schema_version":true,"domains":[]}', "schema_version"],
  ['{"schema_version":1,"domains":[]}', "non-empty list"],
  ['{"schema_version":1,"domains":[null]}', "must be an object"],
  ...[
    [{ domain: "", scopes: ["guide-references"], purpose: "x" }, ".domain"],
    [{ domain: "Example.com", scopes: ["guide-references"], purpose: "x" }, "lowercase hostname"],
    [{ domain: "example.com ", scopes: ["guide-references"], purpose: "x" }, "lowercase hostname"],
    [{ domain: "https://example.com", scopes: ["guide-references"], purpose: "x" }, "lowercase hostname"],
    [{ domain: "example.com", scopes: [], purpose: "x" }, ".scopes"],
    [{ domain: "example.com", scopes: [""], purpose: "x" }, "non-empty string"],
    [{ domain: "example.com", scopes: ["unknown"], purpose: "x" }, "must be one of"],
    [{ domain: "example.com", scopes: ["guide-references"], purpose: "" }, ".purpose"],
    [
      { domain: "example.com", scopes: ["guide-references", "guide-references"], purpose: "x" },
      "duplicate domain/scope",
    ],
  ].map(([entry, error]) => [JSON.stringify({ schema_version: 1, domains: [entry] }), error]),
])("rejects malformed domain configuration %s", (input, diagnostic) => {
  const root = validRepo();
  write(root, DOMAINS, input as string);
  expect(() => loadAllowedDomains(root)).toThrow(diagnostic as string);
  expect(lint(root).join("\n")).toContain(diagnostic);
});
test("reports missing domain configuration", () => {
  const root = validRepo();
  rmSync(join(root, DOMAINS));
  expect(lint(root).join("\n")).toContain(DOMAINS);
});
test("returns schema and standard reference errors", () => {
  const root = validRepo();
  replace(root, GUIDE, "CWE-79", "CWE-89");
  replace(root, GUIDE, "kind: vulnerability", "kind: unknown");
  const errors = lint(root).join("\n");
  expect(errors).toContain("matching reference");
  expect(errors).toContain("kind must be");
});
test.each([
  ["# XSS\n", "found 0"],
  ["# XSS\n- [Rule](example.md)\n- [Again](example.md#rule)\n", "found 2"],
  ["# XSS\n<!--\n- [Rule](example.md)\n-->\n", "found 0"],
  ["# XSS\n```md\n- [Rule](example.md)\n```\n", "found 0"],
  ["# XSS\n- [Rule][rule]\n[rule]: example.md\n", "reference-style"],
  ["# XSS\n- [Rule](missing.md)\n", "target does not exist"],
])("checks nearest indexes %s", (content, diagnostic) => {
  const root = validRepo();
  write(root, README, content);
  expect(lintGuideIndexes(root).join("\n")).toContain(diagnostic);
});
test("requires notes in their nearest index exactly once", () => {
  const root = validRepo();
  write(root, "guides/injection/xss/notes/note.md", "# Note\n");
  expect(lintGuideIndexes(root).join("\n")).toContain("this note exactly once");
  write(root, README, `${read(root, README)}\n- [Note](notes/note.md)\n`);
  expect(lintGuideIndexes(root)).toEqual([]);
});
test("searches ancestor indexes but never leaves guides", () => {
  const root = validRepo();
  rmSync(join(root, README));
  expect(nearestReadmeFor(join(root, GUIDE), root)).toBe(join(root, "guides/injection/README.md"));
  rmSync(join(root, "guides/injection/README.md"));
  expect(nearestReadmeFor(join(root, GUIDE), root)).toBeUndefined();
  expect(lintGuideIndexes(root).join("\n")).toContain("could not find nearest README");
});
test("comment scrubbing preserves diagnostic lines", () => {
  expect(stripHtmlCommentsPreserveLines("a\n<!-- hi\nthere -->\nb")).toBe("a\n       \n         \nb");
});
test("CLI reports nonzero on invalid content", () => {
  silence();
  const root = validRepo();
  expect(main([], root)).toBe(0);
  write(root, GUIDE, "invalid");
  expect(main([], root)).toBe(1);
  expect(() => main(["--oops"], root)).toThrow("Usage");
});
