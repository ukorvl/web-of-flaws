---
id: WOF-REDOS-001
title: "Attacker-controlled Input to Inefficient Regular Expression"
kind: vulnerability
default_severity: medium
exploitability: high
standards:
  cwe:
    - CWE-1333
  owasp_top_10:
    - "X01:2025 Lack of Application Resilience"
platforms:
  - browser
  - server
languages:
  - javascript
  - typescript
  - python
detection:
  type: dataflow
  methods:
    - grep
    - ast
    - taint-analysis
    - semantic-review
  candidate_tokens:
    - new RegExp(
    - re.compile(
    - re.match(
    - re.search(
    - re.fullmatch(
    - .test(
    - .exec(
    - .match(
    - .replace(
    - req.body
    - req.query
sources:
  - req.body
  - req.query
  - req.params
  - HTTP headers
  - form data
  - window.location.search
  - MessageEvent.data
sinks:
  - RegExp.prototype.test()
  - RegExp.prototype.exec()
  - String.prototype.match()
  - String.prototype.replace()
  - String.prototype.search()
  - String.prototype.split()
  - re.match()
  - re.search()
  - re.fullmatch()
  - Pattern.match()
  - Pattern.search()
  - Pattern.fullmatch()
tags:
  - denial-of-service
  - redos
  - regex
  - catastrophic-backtracking
  - availability
---

## Rule

Do not run attacker-controlled input through inefficient regular expressions that can trigger catastrophic backtracking.
If regular expressions must process untrusted input, keep the pattern linear in the worst case and enforce strict input length limits before matching.

## Mental Model

This is an availability dataflow rule.
The attacker does not need code execution.
They only need a crafted input that forces the regex engine into worst-case work.

```text
attacker-controlled input
          ↓
inefficient backtracking regex
          ↓
worst-case exponential work
          ↓
CPU exhaustion / event-loop stall
          ↓
request timeout or service degradation
```

## Why This Matters

Regular expressions often sit on request paths for validation, routing, parsing, filtering, and search.
If one of those expressions has ambiguous repetition or overlapping alternatives, a carefully chosen non-matching input can make the engine try huge numbers of backtracking paths.

On a server, that can tie up request workers or stall a single-threaded event loop.
In a browser, it can freeze the tab and make client-side defenses or workflows unresponsive.
The attack payload can be small compared with the amount of CPU time it forces the application to burn.

## Vulnerable Pattern

```js
const tagListPattern = /^([a-z0-9-]+\s?)*$/i;

app.post("/api/projects/search", express.json(), (req, res) => {
  const tags = String(req.body.tags || "");

  // Problem: attacker-controlled input reaches a regex with nested repetition.
  if (!tagListPattern.test(tags)) {
    return res.status(400).json({ error: "Invalid tag list" });
  }

  res.json(searchProjectsByTags(tags));
});
```

## Example Attack

```http
POST /api/projects/search
Content-Type: application/json

{
  "tags": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
}
```

The trailing `!` forces the match to fail after the engine has already explored huge numbers of backtracking paths through the repeated group.

## Why The Attack Works

1. The attacker controls the string that the server validates with a regular expression.
2. The pattern contains nested repetition, so there are many possible ways to partition the same input.
3. The crafted input mostly matches the repeated prefix and fails only near the end.
4. A backtracking engine keeps retrying alternative paths before it can conclude that the input does not match.
5. CPU time spikes, request handling slows down, and enough repeated requests can degrade or deny service.

## Safer Pattern

Prefer simple linear regexes, explicit tokenization, and input length limits.
Do not rely on a complex one-shot regex when a small parser or per-token validation is clearer and safer.

```js
const SIMPLE_TAG = /^[a-z0-9-]+$/i;
const MAX_TAG_INPUT_LENGTH = 128;

function isValidTagList(input) {
  if (typeof input !== "string" || input.length > MAX_TAG_INPUT_LENGTH) {
    return false;
  }

  const tags = input.trim().split(/\s+/).filter(Boolean);
  return tags.length > 0 && tags.every((tag) => SIMPLE_TAG.test(tag));
}

app.post("/api/projects/search", express.json(), (req, res) => {
  const tags = req.body.tags;

  if (!isValidTagList(tags)) {
    return res.status(400).json({ error: "Invalid tag list" });
  }

  res.json(searchProjectsByTags(tags));
});
```

This replacement removes the catastrophic backtracking shape and caps the amount of work the request can trigger.
Where the runtime supports it, additional regex timeouts or backtracking limits can provide defense in depth, but they should not be the only control.

## Detection

Detection type: `dataflow`.

- Candidate sources: request bodies, query parameters, path parameters, form fields, headers, message payloads, and other attacker-controlled strings.
- Candidate sinks: regex evaluation APIs such as `.test()`, `.exec()`, `.match()`, `.replace()`, `.search()`, `.split()`, Python `re.match()` or `re.search()` calls, compiled-pattern methods, framework validators, route matchers, and parser helpers that rely on backtracking regex engines.
- Confirmation: verify that attacker-controlled input can reach the regex and that the pattern has a catastrophic-backtracking shape such as nested quantifiers or overlapping alternatives inside repetition.
- Confirmation: verify that the input can be long enough and that the match can fail late enough to trigger worst-case behavior.
- High-confidence signals include public request paths, synchronous validation on the request thread, repeated-group patterns like `(...+)*`, and missing size limits before the match.
- A scanner should surface untrusted-input-to-regex candidates, but the agent or reviewer must confirm that the specific pattern is inefficient in the target engine rather than reporting every regex use as a vulnerability.

## False Positives

- Matching untrusted input is not automatically ReDoS; many regular expressions run in linear time for the relevant engine and input shape.
- A suspicious pattern may be effectively safe when strict input length caps make worst-case work too small to matter in practice.
- Some engines, libraries, or wrappers add regex timeouts or use non-backtracking implementations; those controls reduce risk, though the underlying pattern may still deserve cleanup.

## Framework Notes

ReDoS often appears inside shared validators, schema libraries, custom route matchers, markdown or template parsers, and search/filter helpers rather than in obviously security-sensitive code.
Node.js services are especially sensitive because one expensive regex can block the event loop for other requests.
Client-side regex validation can also freeze the page and create an availability problem even when the server is not directly affected.

## References

- [MITRE CWE-1333: Inefficient Regular Expression Complexity](https://cwe.mitre.org/data/definitions/1333.html)
- [OWASP Top 10 2025 X01: Lack of Application Resilience](https://owasp.org/Top10/2025/X01_2025-Next_Steps/)
- [OWASP Regular expression Denial of Service - ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)

## Quick Checklist

- Untrusted input length is capped before regex evaluation on performance-sensitive paths.
- Complex validation is split into simple linear checks or explicit parsing instead of one ambiguous regex.
- Reviewers look for nested repetition and overlapping alternatives in repeated groups.
- Request handlers, validators, and parsers do not let attacker input trigger unbounded synchronous regex work.
- Findings are confirmed with the actual pattern and engine behavior, not by the mere presence of a regex.
