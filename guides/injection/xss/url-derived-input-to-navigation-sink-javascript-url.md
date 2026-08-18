---
id: WOF-XSS-002
title: "URL-derived Input to Navigation Sink (javascript: URL)"
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
sources:
  - window.location.search
  - window.location.hash
  - window.location.href
  - URLSearchParams
  - document.referrer
sinks:
  - HTMLAnchorElement.href
  - Element.setAttribute("href", ...)
  - HTMLFormElement.action
  - HTMLButtonElement.formAction
  - window.location
  - window.open()
tags:
  - xss
  - javascript-protocol
  - url-input
  - navigation-sink
  - href
---

## Rule

Treat untrusted data in URL-valued attributes as dangerous input.
Do not reflect query parameters, form values, or other attacker-controlled data into `href`, `formaction`, `action`, `window.location`, or similar navigation sinks without strict validation of the allowed protocol and destination.

## Mental Model

This is also a client-side dataflow rule, but the dangerous boundary is navigation rather than HTML parsing.
If untrusted input reaches a navigation sink, the browser may interpret `javascript:` as executable code instead of as a normal destination.

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

If the destination is user-controlled, validate the protocol and constrain navigation to trusted locations.

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
      const isSameOrigin = candidate.origin === window.location.origin;

      if (isSafeProtocol && isSameOrigin) {
        // Safe: reduce the final value to a same-origin path.
        link.href = candidate.pathname + candidate.search + candidate.hash;
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
- Confirmation: verify that attacker-controlled input can reach the sink and that the code does not strictly constrain protocol, destination, or route identity.
- Give extra attention to code that copies a string directly into `href` or calls `setAttribute("href", value)` without URL parsing and allowlisting.
- A scanner should surface candidate navigation sinks; the agent or reviewer should confirm whether a dangerous protocol or untrusted destination can actually survive validation.

## False Positives

- Assigning a constant route such as `link.href = "/account"` is not this issue.
- Selecting from a fixed allowlist of known route IDs and then mapping those IDs to hard-coded paths is usually acceptable.
- A dynamic destination may still be safe if the code parses it as a URL, restricts it to `http:` or `https:`, and constrains it to trusted origins or relative routes.

## Framework Notes

Framework templating helps with HTML injection, but it does not automatically validate URL schemes.
Bindings such as `<a href={next}>` in React or `<a :href="next">` in Vue can still create dangerous links if `next` contains `javascript:` or another disallowed scheme.

## References

- [MITRE CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2025 A05: Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP DOM based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- [MDN: `javascript:` URLs](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Schemes/javascript)
- [Vue Security Guide](https://vuejs.org/guide/best-practices/security.html)

## Quick Checklist

- Untrusted input is not written directly into navigation sinks.
- Allowed destinations are constrained by protocol and, when appropriate, by origin or route allowlist.
- `javascript:` and other unsafe schemes are rejected before navigation occurs.
- Findings are confirmed by actual source-to-sink flow, not by the presence of `href` alone.
