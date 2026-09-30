import { join } from "node:path";
import { describe, expect, test } from "vitest";
import {
  isGuideNotePath,
  iterGuideMarkdownPaths,
  iterGuideRulePaths,
  loadGuide,
  parseReferences,
  parseYamlMapping,
  renderedUrls,
  splitFrontmatter,
  updateCodeFenceState,
  validateFrontmatter,
} from "../guide-tools.ts";
import type { Mapping } from "../runtime.ts";
import { BODY, GUIDE, guide, metadata, tempRepo, validRepo, write } from "./support.ts";

describe("guide discovery and parsing", () => {
  test("excludes instructions, indexes and notes from catalog rules", () => {
    const root = tempRepo();
    for (const path of ["guides/AGENTS.md", "guides/x/README.md", "guides/x/rule.md", "guides/x/notes/note.md"])
      write(root, path, "# Text\n");
    expect(iterGuideRulePaths(root)).toEqual([join(root, "guides/x/rule.md")]);
    expect(iterGuideMarkdownPaths(root)).toHaveLength(3);
    expect(isGuideNotePath(join(root, "guides/x/notes/note.md"), join(root, "guides"))).toBe(true);
    expect(isGuideNotePath(join(root, "guides/x/rule.md"), join(root, "guides"))).toBe(false);
  });
  test("supports CRLF and keeps metadata values and body", () => {
    const [yaml, body] = splitFrontmatter(guide().replaceAll("\n", "\r\n"), "guide.md");
    expect(parseYamlMapping(yaml, "guide.md")).toEqual(metadata());
    expect(body.trim()).toBe(BODY.trim());
    const root = validRepo();
    expect(loadGuide(join(root, GUIDE))[0]).toEqual(metadata());
  });
  test.each([
    ["", "missing"],
    ["# no frontmatter", "missing"],
    ["---\nid: unclosed", "not closed"],
  ])("rejects invalid frontmatter %s", (input, error) => {
    expect(() => splitFrontmatter(input, "guide.md")).toThrow(error);
  });
  test.each([
    "title: Foo: Bar",
    'title: "unterminated',
    "title: [Foo]",
    "title: *alias",
    "title: &anchor Foo",
    "title: | block",
    "title: > folded",
    "title: permissions:",
    "title: Foo # misleading",
    "title: one\ntitle: two",
    "title: !!str Foo",
    "__proto__: value",
    "constructor: value",
    "title:\n  prototype: value",
    "- value",
    "",
    "title: okay\n---\ntitle: second document",
  ])("rejects ambiguous or unsupported YAML %s", (input) => {
    expect(() => parseYamlMapping(input, "guide.md")).toThrow("guide.md:");
  });
  test("decodes quoted escapes and preserves numeric/boolean-looking strings", () => {
    expect(parseYamlMapping('title: "Quote \\" and \\\\ slash"\nvalue: 123\nflag: true', "guide.md")).toEqual({
      title: 'Quote " and \\ slash',
      value: "123",
      flag: "true",
    });
    expect(parseYamlMapping("title: 'It''s quoted'", "guide.md")).toEqual({ title: "It's quoted" });
  });
  test("rejects deeply nested YAML", () => {
    const input = Array.from({ length: 40 }, (_, index) => `${"  ".repeat(index)}nested:`).join("\n");
    expect(() => parseYamlMapping(input, "guide.md")).toThrow("nesting");
  });
});

describe("metadata schema", () => {
  test("accepts a valid dataflow rule", () => expect(validateFrontmatter(metadata(), "guide.md")).toEqual([]));
  test.each([
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
  ])("requires %s", (field) => {
    const data = metadata();
    delete data[field];
    expect(validateFrontmatter(data, "guide.md")).toContain(`guide.md: missing frontmatter key ${field}`);
  });
  test.each(["id", "title", "kind", "default_severity", "exploitability"])(
    "rejects empty or non-string %s",
    (field) => {
      for (const value of ["", "  ", null, 7, {}, []]) {
        expect(validateFrontmatter({ ...metadata(), [field]: value }, "guide.md")).toContain(
          `guide.md: ${field} must be a non-empty string`,
        );
      }
    },
  );
  test.each(["id", "kind", "default_severity", "exploitability", "platforms", "languages", "tags"])(
    "rejects unsupported %s values",
    (field) => {
      const data = metadata();
      data[field] = Array.isArray(data[field]) ? ["invalid!"] : "invalid!";
      expect(validateFrontmatter(data, "guide.md").join("\n")).toContain(field === "tags" ? "tag " : field);
    },
  );
  test.each(["platforms", "languages", "sources", "sinks"])("requires non-empty string lists for %s", (field) => {
    for (const value of [[], {}, null, "", ["", 4]])
      expect(validateFrontmatter({ ...metadata(), [field]: value }, "guide.md").join("\n")).toContain(field);
  });
  test("rejects unexpected metadata, standards and detection keys", () => {
    const data = {
      ...metadata(),
      extra: true,
      standards: { cwe: ["bad"], owasp_top_10: ["bad"], other: [] },
      detection: { type: "dataflow", methods: ["bad"], query: "ignored" },
    };
    const errors = validateFrontmatter(data, "guide.md").join("\n");
    for (const text of [
      "unexpected frontmatter keys: extra",
      "unexpected standards keys: other",
      "standards.cwe",
      "standards.owasp_top_10",
      "unexpected detection keys: query",
      "detection.methods",
    ])
      expect(errors).toContain(text);
  });
  test.each([null, [], "", { cwe: [], owasp_top_10: [] }, { cwe: [1], owasp_top_10: [false] }])(
    "rejects malformed standards %j",
    (standards) => {
      expect(validateFrontmatter({ ...metadata(), standards }, "guide.md").length).toBeGreaterThan(0);
    },
  );
  test.each([
    null,
    [],
    {},
    { type: {}, methods: [] },
    { type: "dataflow", methods: ["", 3], candidate_tokens: [""] },
    { type: "dataflow", methods: ["grep"], candidate_tokens: null },
  ])("rejects malformed detection %j", (detection) => {
    expect(validateFrontmatter({ ...metadata(), detection }, "guide.md").join("\n")).toContain("detection");
  });
  test("accepts omitted candidate tokens", () => {
    expect(
      validateFrontmatter({ ...metadata(), detection: { type: "dataflow", methods: ["grep"] } }, "guide.md"),
    ).toEqual([]);
  });
  test("enforces mutually exclusive detection models", () => {
    expect(validateFrontmatter({ ...metadata(), indicators: ["innerHTML"] }, "guide.md")).toContain(
      "guide.md: dataflow guides must not declare indicators",
    );
    const data: Mapping = {
      ...metadata(),
      detection: { type: "semantic-pattern", methods: ["grep"] },
      indicators: ["innerHTML"],
    };
    const errors = validateFrontmatter(data, "guide.md");
    expect(errors).toContain("guide.md: semantic-pattern guides must not declare sources");
    expect(errors).toContain("guide.md: semantic-pattern guides must not declare sinks");
    delete data.sources;
    delete data.sinks;
    expect(validateFrontmatter(data, "guide.md")).toEqual([]);
    data.indicators = [""];
    expect(validateFrontmatter(data, "guide.md")).toContain("guide.md: indicators entries must be non-empty strings");
  });
});

describe("rendered Markdown", () => {
  test("finds uppercase/protocol-relative URLs and ignores matching code fences and inline spans", () => {
    const text =
      "[Reference](HTTPS://docs.example.com/guide)\n[Network](//docs.example.com/path)\n~~~js\nhttps://ignored.test\n~~~\n``https://ignored.test/with`tick``\nhttps://example.com/plain";
    expect(renderedUrls(text)).toEqual([
      ["HTTPS://docs.example.com/guide", 1],
      ["//docs.example.com/path", 2],
      ["https://example.com/plain", 7],
    ]);
  });
  test("shorter, mismatched, or annotated closing fences do not expose example URLs", () => {
    expect(renderedUrls("````js\n```\n~~~\n````text\nhttps://ignored.test\n````\nhttps://example.com")).toEqual([
      ["https://example.com", 7],
    ]);
    expect(updateCodeFenceState("ordinary", null)).toBeNull();
  });
  test("only collects references from the References section outside code", () => {
    expect(parseReferences(BODY)).toHaveLength(2);
    expect(parseReferences("```md\n## References\n[Fake](https://evil.test)\n```")).toEqual([]);
    expect(
      parseReferences("## References\n[A](https://a.test) [B](https://b.test)\n## Other\n[C](https://c.test)"),
    ).toEqual([
      { label: "A", url: "https://a.test" },
      { label: "B", url: "https://b.test" },
    ]);
  });
});
