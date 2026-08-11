---
title: URL-derived Input to Navigation Sink (javascript: URL)
impact: MEDIUM
tags: xss, javascript-protocol, url-input, navigation-sink, href
---

## Rule

Treat untrusted data in URL-valued attributes as dangerous input.
Do not reflect query parameters, form values, or other attacker-controlled data into `href`, `formaction`, or similar navigation sinks without strict validation of the allowed protocol and destination.

## Why This Matters

HTML escaping alone does not make URL attributes safe.
If an attacker can supply a `javascript:` URL, the browser may execute code when the victim clicks the link or otherwise follows the reflected navigation target.

## Vulnerable Pattern

```html
<a id="continue-link">Continue</a>

<script>
  const params = new URLSearchParams(window.location.search);
  const next = params.get("next") || "/account";

  document.getElementById("continue-link").setAttribute("href", next);
</script>
```

## Example Attack

```text
https://example.com/complete-profile?next=javascript:alert(document.domain)
```

## Why The Attack Works

1. The attacker controls the `next` parameter.
2. The application reflects that value into a link destination.
3. The browser treats `javascript:` as executable code, not as a normal page URL.
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
        link.href = candidate.pathname + candidate.search + candidate.hash;
      }
    } catch {
      // Ignore invalid URLs and keep the default safe destination.
    }
  }
</script>
```

## Modern Frameworks (React, Vue, etc.)

Modern frameworks usually escape HTML text interpolation, but that is not enough here.
Code such as `<a href={next}>` in React or `<a :href="next">` in Vue may still create dangerous links if `next` contains `javascript:` or another unsafe scheme.
Framework templating helps with HTML injection, but protocol validation is still the application's responsibility.

## Review Hints

- Treat `href`, `src`, `action`, `formAction`, `window.open`, and navigation targets derived from URL parameters as sensitive sinks.
- Flag flows where attacker-controlled input reaches URL attributes even if the code does not use `innerHTML`.
- Remember that escaping `<` and `>` does not neutralize dangerous protocols such as `javascript:`.

## Quick Checklist

- Untrusted input is not written directly into URL-valued attributes.
- Allowed destinations are constrained by protocol and, when appropriate, origin.
- Dynamic navigation uses relative-path allowlists or centralized validation.
