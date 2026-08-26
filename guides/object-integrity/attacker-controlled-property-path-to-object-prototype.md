---
id: WOF-PP-001
title: "Attacker-controlled Property Path to Object Prototype"
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-1321
  owasp_top_10:
    - "A08:2025 Software or Data Integrity Failures"
platforms:
  - browser
  - server
languages:
  - javascript
  - typescript
  - json
detection:
  type: dataflow
  methods:
    - grep
    - ast
    - taint-analysis
    - semantic-review
  candidate_tokens:
    - __proto__
    - constructor.prototype
    - Object.assign(
    - deepMerge(
    - merge(
    - set(
    - path.split(".")
    - req.body
    - req.query
sources:
  - window.location.search
  - window.location.hash
  - URLSearchParams
  - req.query
  - req.body
  - JSON request body
  - form data
  - cookies
sinks:
  - target[key] = value
  - Object.assign(target, source)
  - deepMerge(target, source)
  - set(target, path, value)
  - object[path[i]][path[i + 1]] = value
tags:
  - prototype-pollution
  - object-integrity
  - property-path
  - deep-merge
  - dynamic-assignment
---

## Rule

Treat attacker-controlled object keys and property paths as untrusted.
Do not allow dynamic assignment, deep merge, or path-based setters to reach `__proto__`, `constructor.prototype`, `prototype`, or other prototype objects.

## Mental Model

Prototype pollution is usually the primitive, not the final exploit.

```text
attacker-controlled keys or paths
            ↓
deep merge / dynamic assignment / path setter
            ↓
__proto__ / constructor.prototype
            ↓
Object.prototype polluted
            ↓
unrelated objects inherit fake properties
            ↓
security-sensitive gadget
```

## Why This Matters

When application code treats attacker-controlled property names as harmless data, it can end up modifying object prototypes instead of ordinary object fields.
That pollution then changes how unrelated objects behave, which can flip authorization checks, alter request options, corrupt sanitizer settings, or trigger other security-sensitive behavior far away from the original write.

## Vulnerable Pattern

```js
function setValue(target, path, value) {
  const parts = path.split(".");
  let current = target;

  for (const part of parts.slice(0, -1)) {
    current[part] ??= {};
    current = current[part];
  }

  current[parts.at(-1)] = value;
}

function updateSettings(requestBody) {
  const settings = {};

  // Problem: attacker-controlled path reaches a generic path setter.
  setValue(settings, requestBody.path, requestBody.value);
  return settings;
}

updateSettings({
  path: "__proto__.isAdmin",
  value: true,
});

({}).isAdmin; // true
```

## Example Attack

```http
POST /api/preferences
Content-Type: application/json

{
  "path": "__proto__.isAdmin",
  "value": true
}
```

Somewhere completely unrelated:

```js
const user = {};

if (user.isAdmin) {
  showAdminPanel();
}
```

## Why The Attack Works

1. The attacker controls an object key or dot-separated property path.
2. A generic helper walks that path and performs dynamic writes without blocking prototype traversal primitives.
3. The write resolves to `Object.prototype` through `__proto__` or `constructor.prototype`.
4. New objects now inherit the injected property even though they never defined it themselves.
5. A later gadget trusts the inherited property during an authorization check, configuration lookup, request construction, or another sensitive operation.

## Safer Pattern

Prefer explicit schema-to-object mapping over generic deep merge or arbitrary path setters.
If a dynamic object writer is truly required, reject prototype traversal segments and use null-prototype objects for mutable dictionaries.

```js
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

function splitAndValidatePath(path) {
  const parts = String(path).split(".");

  if (!parts.length || parts.some((part) => FORBIDDEN_SEGMENTS.has(part))) {
    throw new Error("Unsafe property path");
  }

  return parts;
}

function setSafeValue(target, path, value) {
  const parts = splitAndValidatePath(path);
  let current = target;

  for (const part of parts.slice(0, -1)) {
    if (!Object.hasOwn(current, part)) {
      current[part] = Object.create(null);
    }

    const next = current[part];
    if (next === null || typeof next !== "object") {
      throw new Error("Path crosses a non-object value");
    }

    current = next;
  }

  current[parts.at(-1)] = value;
}

const settings = Object.create(null);
setSafeValue(settings, "profile.theme", "dark");

function isAdmin(user) {
  return Object.hasOwn(user, "isAdmin") && user.isAdmin === true;
}
```

Even safer: accept only known fields and map them into a fixed object shape instead of replaying arbitrary keys from attacker input.

## Detection

Detection type: `dataflow`.

- Candidate sources: URL query parameters, URL hash, JSON bodies, form data, cookies, configuration objects, and other attacker-controlled object keys or property paths.
- Candidate sinks: dynamic property assignment, recursive merge utilities, path-based setters, clone helpers, and wrappers around `Object.assign`, `merge`, or similar APIs.
- Confirmation: verify that attacker-controlled path segments can reach `__proto__`, `constructor.prototype`, `prototype`, or an equivalent prototype object during the write.
- High-confidence signals include helpers that split dot-separated paths, recursive `for...in` merge code, generic `set(target, path, value)` utilities, and code that creates nested objects while walking attacker-controlled keys.
- A scanner should prioritize source-to-sink flows into these generic mutation helpers, not just literal `__proto__` strings, because the real vulnerability is the abstraction that permits prototype traversal.

## False Positives

- Dynamic key assignment is usually not this issue when keys are selected from a strict allowlist before any write occurs.
- A merge or setter is typically safe when the destination is a null-prototype object or `Map`, reserved prototype segments are rejected, and the code never traverses into existing prototypes.
- Merely seeing `__proto__` in a test, denylist, or defensive guard should not be reported as a vulnerability by itself.

## Framework Notes

Prototype pollution often hides inside shared helpers, request parsers, state update utilities, and deep merge wrappers rather than in obvious one-off code.
Library upgrades matter, but local abstractions that recursively walk attacker-controlled keys can recreate the same sink even after known third-party bugs are patched.

## References

- [MITRE CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')](https://cwe.mitre.org/data/definitions/1321.html)
- [OWASP Top 10 2025 A08: Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/)
- [OWASP Prototype Pollution Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- [MDN: JavaScript prototype pollution](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Prototype_pollution)

## Quick Checklist

- Attacker-controlled keys and property paths never reach generic object mutation helpers without validation.
- Dynamic writers reject `__proto__`, `constructor`, `prototype`, and equivalent prototype traversal segments.
- Mutable dictionary-style objects use null prototypes or `Map` instead of plain `{}` where practical.
- Security-sensitive checks rely on explicit own properties or fixed defaults, not inherited truthy values.
- Findings are confirmed by real source-to-sink reachability into a prototype object, not by a string match alone.
