---
id: WOF-XSS-002
title: "Attacker-controlled URL to Executable URL Sink (javascript: URL)"
kind: vulnerability
default_severity: medium
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
  type: dataflow
  methods:
    - grep
    - ast
    - taint-analysis
    - semantic-review
  candidate_tokens:
    - href
    - src
    - sandbox
    - setAttribute("href"
    - formAction
    - window.location
    - window.open
    - "javascript:"
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
    - fetch(
    - response.json()
    - response.text()
sources:
  - window.location.search
  - window.location.hash
  - window.location.href
  - URLSearchParams
  - document.referrer
  - window.name
  - MessageEvent.data
  - "`localStorage.getItem()` values previously written from attacker-controlled input"
  - "`sessionStorage.getItem()` values previously written from attacker-controlled input"
  - "`Response.json()` values from APIs that can return attacker-controlled data"
  - "`Response.text()` values from APIs that can return attacker-controlled data"
sinks:
  - HTMLAnchorElement.href
  - HTMLIFrameElement.src
  - Element.setAttribute("href", ...)
  - HTMLFormElement.action
  - HTMLButtonElement.formAction
  - window.location
  - window.open()
tags:
  - xss
  - dom-xss
  - javascript-protocol
  - browser-input
  - executable-url-sink
  - href
---

## Rule

Treat attacker-controlled URLs as dangerous input.
Do not pass browser input, form values, API response fields that can contain attacker-controlled data, or other attacker-controlled values into executable URL sinks unless strict validation rejects executable URL schemes such as `javascript:`.

## Mental Model

This is a client-side dataflow rule, but the dangerous boundary is executable URL navigation rather than HTML parsing.
If an attacker-controlled URL reaches a navigation sink, the browser may interpret `javascript:` as executable code instead of as a normal destination.

## Why This Matters

HTML escaping alone does not make URL attributes safe.
If an attacker can supply a `javascript:` URL, the browser may execute code when the victim clicks the link or otherwise follows the reflected navigation target.

## Vulnerable Pattern

```html
<a id="continue-link">Continue</a>

<script>
  // URL input is attacker-controlled.
  const params = new URLSearchParams(window.location.search);
  const next = params.get("next") || "/account";

  // Problem: the application trusts any protocol inside `next`.
  document.getElementById("continue-link").setAttribute("href", next);
</script>
```

## Example Attack

```text
https://example.com/complete-profile?next=javascript:alert(document.domain)
```

## Why The Attack Works

1. The attacker controls the `next` parameter.
2. The application reflects that value into a navigation target.
3. The browser recognizes `javascript:` as executable code, not as a regular page URL.
4. When the victim clicks the link, the injected script runs in the page context.

## Safer Pattern

If the destination is user-controlled, validate the allowed protocol before assigning it to an executable URL sink.

```html
<a id="continue-link" href="/account">Continue</a>

<script>
  const params = new URLSearchParams(window.location.search);
  const next = params.get("next");
  const link = document.getElementById("continue-link");

  if (next) {
    try {
      const candidate = new URL(next, window.location.origin);
      const isSafeProtocol =
        candidate.protocol === "http:" || candidate.protocol === "https:";

      if (isSafeProtocol) {
        // Safe for this rule: executable schemes such as javascript: are rejected.
        link.href = candidate.href;
      }
    } catch {
      // Ignore invalid URLs and keep the default safe destination.
    }
  }
</script>
```

## Detection

Detection type: `dataflow`.

- Candidate collection: search for assignments to `href`, `src`, `action`, `formAction`, `window.location`, and `window.open(...)`.
- Candidate collection: find browser input sources such as URL values, message event payloads, `window.name`, and client-side storage whose values can be traced to attacker-controlled writes.
- Candidate collection: find API response reads such as `fetch(...)`, `response.json()`, and `response.text()` when the response can contain attacker-controlled values.
- Confirmation: verify that attacker-controlled input can reach the sink and that an executable scheme such as `javascript:` can survive validation.
- Confirmation: for message event payloads, first check whether the handler rejects all but exact allowlisted `event.origin` values and, where applicable, the expected `event.source`. Missing or ineffective validation makes `event.data` attacker-controlled; if validation works, determine whether an allowed sender can independently forward attacker-controlled data.
- Confirmation: for `HTMLIFrameElement.src`, check the effective `sandbox` configuration. A sandbox without `allow-scripts` blocks script execution; when scripts are allowed, a missing `allow-same-origin` still prevents same-origin access to the parent.
- Give extra attention to code that copies a string directly into `href` or calls `setAttribute("href", value)` without URL parsing and allowlisting.
- A scanner should surface candidate executable URL sinks; the agent or reviewer should confirm whether a dangerous protocol can actually survive validation.

## False Positives

- Assigning a constant route such as `link.href = "/account"` is not this issue.
- Selecting from a fixed allowlist of known route IDs and then mapping those IDs to hard-coded paths is usually acceptable.
- A dynamic destination is not `javascript:` XSS if the code parses it as a URL and restricts it to non-executable protocols such as `http:` or `https:`. Whether an external destination is acceptable is a separate navigation or open-redirect policy decision.
- A message handler that validates an exact trusted origin and expected sender window before using `event.data` at the sink is not this issue unless the allowed sender can independently forward attacker-controlled content.
- Client-side storage that contains only internally generated preferences or route identifiers is not attacker-controlled input.
- An iframe with an effective sandbox that lacks `allow-scripts` cannot execute a `javascript:` URL, though later code can change the sandbox configuration.

## Framework Notes

Framework templating helps with HTML injection, but it does not automatically validate URL schemes.
Bindings such as `<a href={next}>` in React or `<a :href="next">` in Vue can still create dangerous links if `next` contains `javascript:` or another disallowed scheme.

## References

- [MITRE CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2025 A05: Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN: `<iframe>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/iframe)
- [MDN: `javascript:` URLs](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Schemes/javascript)
- [Vue Security Guide](https://vuejs.org/guide/best-practices/security.html)

## Quick Checklist

- Attacker-controlled input is not written directly into navigation sinks.
- Allowed protocols exclude `javascript:` and other executable schemes.
- `javascript:` and other unsafe schemes are rejected before navigation occurs.
- Findings are confirmed by actual source-to-sink flow, not by the presence of `href` alone.
