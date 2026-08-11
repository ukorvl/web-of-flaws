---
title: URL-derived Input to HTML Sink (innerHTML)
impact: HIGH
tags: xss, dom-xss, url-input, query-params, innerhtml
---

## Rule

Treat browser query parameters as untrusted input.
Do not pass data from `window.location.search`, `URLSearchParams`, or equivalent URL APIs into HTML sinks such as `innerHTML`, `outerHTML`, `insertAdjacentHTML`, or `document.write`.

## Why This Matters

Query parameters are fully attacker-controlled.
If the application inserts them into the DOM as HTML, the browser may parse attacker markup and execute JavaScript in the victim's session.

## Vulnerable Pattern

```html
<div id="message"></div>

<script>
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name") || "guest";

  document.getElementById("message").innerHTML = "Hello " + name;
</script>
```

## Example Attack

```text
https://example.com/welcome?name=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
```

## Why The Attack Works

1. The attacker controls the `name` query parameter.
2. The page reads it directly from the URL.
3. The value is written into `innerHTML`.
4. The browser parses the attacker-controlled string as markup.
5. The `onerror` handler executes JavaScript.

## Safer Pattern

If the page only needs to show text, write text instead of HTML.

```html
<div id="message"></div>

<script>
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name") || "guest";

  document.getElementById("message").textContent = "Hello " + name;
</script>
```

## Modern Frameworks (React, Vue, etc.)

Modern frameworks reduce this risk in many common cases, but they do not eliminate it completely.
React and Vue usually escape interpolated values by default, so code like `Hello {name}` in React or `{{ name }}` in Vue is typically rendered as text rather than executable HTML.
The risk returns when developers bypass those defaults with HTML rendering escape hatches such as React's `dangerouslySetInnerHTML` or Vue's `v-html`, especially if the content comes from query parameters or other URL-derived input.

## If HTML Is Truly Required

Only allow a small, explicit subset of markup and sanitize it with a well-reviewed sanitizer.
Do not build your own sanitizer with regexes.

## Review Hints

- Treat `window.location.search`, `window.location.href`, `location.hash`, `document.referrer`, and `URLSearchParams` as untrusted input sources.
- Flag any flow from URL-derived input into `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, or framework escape hatches such as `dangerouslySetInnerHTML`.
- Prefer `textContent`, `createTextNode`, strict allowlists, and validated attribute assignment.

## Quick Checklist

- URL-derived data is not rendered with HTML sinks.
- Plain text output uses `textContent` or an equivalent safe API.
- Any allowed HTML is sanitized by a trusted library and constrained by policy.
