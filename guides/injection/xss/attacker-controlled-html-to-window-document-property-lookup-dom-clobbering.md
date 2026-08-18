---
id: WOF-XSS-003
title: "Attacker-controlled HTML to `window`/`document` Property Lookup (DOM Clobbering)"
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-79
  owasp_top_10:
    - "A05:2025 Injection"
platforms:
  - browser
languages:
  - html
  - javascript
  - typescript
detection:
  type: semantic-pattern
  methods:
    - grep
    - ast
    - semantic-review
  candidate_tokens:
    - innerHTML
    - outerHTML
    - insertAdjacentHTML
    - document.write
    - dangerouslySetInnerHTML
    - v-html
    - window.
    - document.
indicators:
  - attacker-controlled HTML reaches DOM parsing sinks such as `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, or framework raw-HTML escape hatches
  - code reads `window.NAME`, `document.NAME`, or bare global identifiers as if they were trusted configuration, navigation targets, or script URLs
  - security-sensitive names are reused as HTML `id` or `name` values
  - sanitization removes scripts but leaves named properties that can still collide with application state or browser APIs
tags:
  - xss
  - dom-clobbering
  - html-injection
  - named-properties
  - window
  - document
---

## Rule

Do not trust named properties on `window` or `document` after attacker-controlled HTML enters the DOM.
Keep security-sensitive values in local or module scope, and sanitize or namespace `id` and `name` attributes before rendering untrusted markup.

## Mental Model

Some browsers expose elements with `id` or `name` attributes as named properties on `window` and `document`.
If attacker-controlled HTML reaches the page, those named elements can shadow application variables or browser APIs and change what later code reads.

## Why This Matters

DOM clobbering can turn seemingly harmless HTML injection into code execution, open redirects, or attacker-controlled script loading.
It is especially easy to miss when script tags and event handlers are blocked, because the attacker only needs HTML with colliding `id` or `name` attributes.

## Vulnerable Pattern

```html
<div id="profile-card"></div>
<button id="continue-button" type="button">Continue</button>

<script>
  const params = new URLSearchParams(window.location.search);
  const cardHtml = params.get("card") || "";

  // Problem: attacker-controlled HTML is inserted into the DOM tree.
  document.getElementById("profile-card").innerHTML = cardHtml;

  document
    .getElementById("continue-button")
    .addEventListener("click", () => {
      // Problem: code trusts a named property on `window`.
      const next = window.redirectTo || "/account";
      location.assign(next);
    });
</script>
```

## Example Attack

```text
https://example.com/profile-preview?card=%3Ca%20id%3DredirectTo%20href%3D%22javascript%3Aalert(document.domain)%22%3EContinue%3C%2Fa%3E
```

## Why The Attack Works

1. The attacker controls HTML that the page inserts into the DOM.
2. The injected anchor uses `id="redirectTo"`, which becomes a named property on `window` in affected browsers.
3. The click handler reads `window.redirectTo` as if it were a trusted application value.
4. The navigation call uses the clobbered element instead of the intended fallback route.
5. The browser follows the attacker-controlled URL, leading to XSS or an open redirect.

## Safer Pattern

Avoid named property lookups for security-sensitive values, and keep untrusted content out of HTML parsing sinks unless it is sanitized to remove or namespace `id` and `name`.

```html
<div id="profile-card"></div>
<button id="continue-button" type="button">Continue</button>

<script type="module">
  const params = new URLSearchParams(window.location.search);
  const cardText = params.get("card") || "";
  const safeNext = "/account";

  // Safe for plain text: attacker input does not create named DOM properties.
  document.getElementById("profile-card").textContent = cardText;

  document
    .getElementById("continue-button")
    .addEventListener("click", () => {
      location.assign(safeNext);
    });
</script>
```

If rich HTML is required, sanitize it with a policy that strips or namespaces `id` and `name` attributes before insertion, and validate any resulting navigation or script URLs against a strict allowlist.

## Detection

Detection type: `semantic-pattern`.

- Candidate collection: find HTML parsing sinks such as `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, and `v-html`.
- Candidate collection: find reads from `window.NAME`, `document.NAME`, or implicit globals used as config objects, redirect targets, or resource URLs.
- Confirmation: verify that attacker-controlled HTML can reach the same DOM tree and that `id` or `name` attributes survive the sanitization or rendering path.
- Confirmation: check whether the clobbered property influences navigation, script loading, DOM API selection, code evaluation, or other security-sensitive behavior.
- A scanner should surface HTML-injection and named-property candidates; the agent or reviewer should confirm that a real collision can occur and that it changes a sensitive operation.

## False Positives

- Using `document.getElementById("known-id")` to select a specific element is not the same issue as trusting `window.knownId` or `document.knownId`.
- HTML rendering that converts attacker input to plain text, or sanitization that removes or namespaces `id` and `name`, usually blocks this attack path.
- Local variables, module-scoped constants, or explicitly imported config objects are not clobberable through DOM named properties.

## Framework Notes

React and Vue reduce this risk when applications keep state inside components and avoid raw HTML rendering.
The risk returns when code uses `dangerouslySetInnerHTML`, `v-html`, or similar escape hatches and later reads security-sensitive values from `window` or `document`.

## References

- [MITRE CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2025 A05: Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP DOM Clobbering Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html)
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN: `Element.innerHTML`](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML)
- [Vue Security Guide](https://vuejs.org/guide/best-practices/security.html)

## Quick Checklist

- Untrusted HTML does not enter the DOM tree without sanitization that removes or namespaces named properties.
- Security-sensitive values are not read from `window.*`, `document.*`, or implicit globals.
- Navigation targets, script URLs, and similar sinks are stored in local or module-scoped values and validated before use.
- Findings are confirmed by a real named-property collision that changes a sensitive operation.
