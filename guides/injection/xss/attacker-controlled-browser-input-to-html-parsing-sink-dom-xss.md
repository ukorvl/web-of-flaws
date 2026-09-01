---
id: WOF-XSS-001
title: Attacker-controlled Browser Input to HTML Parsing Sink (DOM XSS)
kind: vulnerability
default_severity: high
exploitability: high
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
  type: dataflow
  methods:
    - grep
    - ast
    - taint-analysis
    - semantic-review
  candidate_tokens:
    - innerHTML
    - outerHTML
    - insertAdjacentHTML
    - document.write
    - dangerouslySetInnerHTML
    - v-html
    - location.search
    - location.hash
    - location.href
    - URLSearchParams
    - document.referrer
    - window.name
    - addEventListener("message"
    - event.data
    - localStorage.getItem(
    - sessionStorage.getItem(
sources:
  - window.location.search
  - window.location.hash
  - window.location.href
  - URLSearchParams
  - document.referrer
  - window.name
  - MessageEvent.data
  - localStorage.getItem()
  - sessionStorage.getItem()
sinks:
  - Element.innerHTML
  - Element.outerHTML
  - Element.insertAdjacentHTML()
  - Document.write()
tags:
  - xss
  - dom-xss
  - browser-input
  - html-parsing
  - raw-html
---

## Rule

Treat attacker-controlled browser data as untrusted input.
Do not pass URL values, cross-window messages, attacker-influenced client-side state, or equivalent browser input into HTML parsing sinks such as `innerHTML`, `outerHTML`, `insertAdjacentHTML`, or `document.write`.

## Mental Model

This is a client-side dataflow rule.
An attacker controls browser-provided data, and HTML parsing sinks are execution boundaries: once untrusted data crosses that boundary as HTML instead of text, the browser may create executable DOM.

## Why This Matters

Query strings, fragments, cross-window messages, and attacker-influenced client-side state can all carry attacker-controlled data.
If an application inserts that data into the DOM as HTML, the browser may parse attacker markup and execute JavaScript in the victim's session.

## Vulnerable Pattern

```html
<div id="message"></div>

<script>
  // URL input is attacker-controlled.
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name") || "guest";

  // Problem: `innerHTML` parses the string as HTML, not plain text.
  document.getElementById("message").innerHTML = "Hello " + name;
</script>
```

## Example Attack

```text
https://example.com/welcome?name=%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E
```

## Why The Attack Works

1. The attacker controls the `name` query parameter.
2. The page reads that attacker-controlled value from browser input.
3. The value is written into an HTML parsing sink.
4. The browser interprets the attacker-controlled string as markup, not as inert text.
5. The injected event handler executes JavaScript in the page context.

## Safer Pattern

If the page only needs to show text, write text instead of HTML.

```html
<div id="message"></div>

<script>
  const params = new URLSearchParams(window.location.search);
  const name = params.get("name") || "guest";

  // Safe for plain text: the browser creates a text node instead of parsing HTML.
  document.getElementById("message").textContent = "Hello " + name;
</script>
```

If HTML is truly required, sanitize it with a well-reviewed library and enforce a narrow policy for what markup is allowed.

## Detection

Detection type: `dataflow`.

- Candidate collection: use grep or AST queries to find `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, and framework escape hatches such as `dangerouslySetInnerHTML` or `v-html`.
- Candidate collection: find browser input sources such as URL values, message event payloads, `window.name`, and attacker-influenced storage.
- Confirmation: trace whether attacker-controlled browser data can reach the sink without being converted to safe text or sanitized under a trusted policy.
- Confirmation: for message event payloads, first check whether the handler rejects all but exact allowlisted `event.origin` values and, where applicable, the expected `event.source`. Missing or ineffective validation makes `event.data` attacker-controlled; if validation works, determine whether an allowed sender can independently forward attacker-controlled data.
- Higher-confidence findings usually show the source and sink in the same function, component, or render path.
- A scanner should find candidates; the agent or reviewer should confirm that untrusted data can actually reach the sink without being converted to safe text or sanitized under a trusted policy.

## False Positives

- Writing a constant template string such as `element.innerHTML = "<b>Welcome</b>"` is not the same issue because no attacker-controlled input crosses the sink.
- A sink that only accepts `TrustedHTML` or the output of a vetted sanitizer under an enforced Trusted Types policy may be acceptable, though the policy and sanitization still need review.
- Server-generated HTML fragments can still be dangerous, but they are not this client-side DOM XSS rule unless attacker-controlled browser data can influence the fragment.
- A message handler that validates an exact trusted origin and expected sender window before using `event.data` at the sink is not this issue unless the allowed sender can independently forward attacker-controlled content.

## Framework Notes

React and Vue reduce this risk for normal text interpolation because they escape content by default.
The risk returns when developers bypass those defaults with APIs such as React's `dangerouslySetInnerHTML` or Vue's `v-html`, especially if the value ultimately comes from attacker-controlled browser input.

## References

- [MITRE CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2025 A05: Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN: `Element.innerHTML`](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML)
- [MDN: `Node.textContent`](https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent)
- [React docs: `dangerouslySetInnerHTML`](https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html)
- [Vue Security Guide](https://vuejs.org/guide/best-practices/security.html)

## Quick Checklist

- Attacker-controlled browser data never flows into HTML parsing sinks as a raw string.
- Plain text output uses `textContent`, text nodes, or an equivalent safe API.
- Required HTML rendering uses sanitization and a narrowly scoped trust policy.
- Findings are confirmed by actual source-to-sink flow, not by sink name alone.
