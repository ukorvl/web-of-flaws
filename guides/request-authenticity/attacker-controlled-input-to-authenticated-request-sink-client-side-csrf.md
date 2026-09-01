---
id: WOF-CSRF-001
title: "Attacker-controlled Input to Authenticated Request Sink (Client-side CSRF)"
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-352
  owasp_top_10:
    - "A01:2025 Broken Access Control"
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
    - fetch(
    - XMLHttpRequest
    - axios(
    - jQuery.ajax
    - submit(
    - location.search
    - location.hash
    - MessageEvent.data
    - window.name
    - document.referrer
sources:
  - window.location.search
  - window.location.hash
  - MessageEvent.data
  - window.name
  - document.referrer
sinks:
  - fetch()
  - XMLHttpRequest.open()
  - XMLHttpRequest.send()
  - axios(...)
  - jQuery.ajax()
  - HTMLFormElement.submit()
tags:
  - csrf
  - client-side-csrf
  - confused-deputy
  - url-input
  - postmessage
  - authenticated-request
---

## Rule

Treat browser-controlled inputs as untrusted request instructions.
Do not let `window.location`, `postMessage`, `window.name`, `document.referrer`, or similar attacker-influenced data choose the URL, method, headers, or body of an authenticated state-changing request.

## Mental Model

This is a client-side dataflow rule.
The dangerous sink is not HTML parsing or code execution, but request generation: trusted first-party JavaScript becomes a confused deputy and sends a privileged request on the attacker's behalf.

## Why This Matters

Client-side CSRF bypasses the usual mental model of "cross-site form post versus server-side token check".
If the attacker's input drives the application's own JavaScript, the browser may send same-origin cookies and the application may attach CSRF headers or tokens automatically, so `SameSite` and token-based defenses do not reliably stop the request.

## Vulnerable Pattern

```html
<meta name="csrf-token" content="{{ serverGeneratedToken }}" />

<script>
  const params = new URLSearchParams(window.location.search);
  const endpoint = params.get("endpoint");
  const email = params.get("email");
  const csrfToken = document
    .querySelector('meta[name="csrf-token"]')
    .getAttribute("content");

  if (endpoint && email) {
    // Problem: attacker-controlled URL parameters drive an authenticated POST.
    fetch(endpoint, {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify({ email }),
    });
  }
</script>
```

## Example Attack

```text
https://example.com/settings?endpoint=%2Fapi/account/email&email=attacker%40example.com
```

## Why The Attack Works

1. The attacker controls the query parameters in the victim's browser URL.
2. The page treats those parameters as instructions for a state-changing request.
3. The request is sent by trusted same-origin JavaScript, not by an untrusted cross-site page.
4. The browser includes the victim's session cookies, and the application may also attach a valid CSRF token or custom header.
5. The server receives what looks like a legitimate authenticated request and cannot distinguish it from an intentional user action.

## Safer Pattern

Keep attacker-controlled inputs independent from authenticated request details.
If URL input must influence behavior, map it to a fixed allowlist of safe read-only requests and keep state-changing request details fixed in code.
An explicit user action can confirm product intent, but it is not the security boundary because script can synthesize application behavior.

```html
<meta name="csrf-token" content="{{ serverGeneratedToken }}" />
<input id="email" type="email" />
<button id="save-email" type="button">Save</button>

<script>
  const params = new URLSearchParams(window.location.search);
  const view = params.get("view");
  const csrfToken = document
    .querySelector('meta[name="csrf-token"]')
    .getAttribute("content");

  const readOnlyRequests = {
    profile: { endpoint: "/api/profile", method: "GET" },
    notifications: { endpoint: "/api/notifications", method: "GET" },
  };

  if (view && readOnlyRequests[view]) {
    const request = readOnlyRequests[view];

    // URL input may only select from a fixed list of safe read-only requests.
    fetch(request.endpoint, {
      method: request.method,
      credentials: "same-origin",
    });
  }

  document.getElementById("save-email").addEventListener("click", async () => {
    const email = document.getElementById("email").value;

    // State-changing request details are fixed in code; the click confirms user intent.
    await fetch("/api/account/email", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken,
      },
      body: JSON.stringify({ email }),
    });
  });
</script>
```

## Detection

Detection type: `dataflow`.

- Candidate sources: `window.location.search`, `window.location.hash`, `location.href`, `MessageEvent.data`, `window.name`, `document.referrer`, and similar attacker-influenced browser inputs.
- Candidate sinks: `fetch(...)`, `XMLHttpRequest`, Axios or jQuery request helpers, programmatic form submission, and framework request utilities.
- Confirmation: verify that untrusted client-side input can influence the request URL, method, headers, or body of an authenticated request, especially for `POST`, `PUT`, `PATCH`, `DELETE`, or state-changing `GET` routes.
- High-confidence signals include requests fired on page load, `hashchange`, or `message` events, request helpers that automatically attach CSRF headers, and code that copies a URL-derived string directly into a request endpoint.
- A scanner should surface source-to-request candidates; the agent or reviewer should confirm that the resulting request can mutate server-side state or invoke a privileged action.

## False Positives

- Selecting from a hard-coded allowlist of known-safe read-only requests is usually not this issue.
- A request is not client-side CSRF solely because it uses `fetch`; the problem is attacker influence over authenticated request details.
- `postMessage`-driven behavior may be acceptable if the handler strictly verifies `origin`, validates message shape, and maps approved message types to predefined safe actions instead of replaying raw request data.

## Framework Notes

Framework CSRF helpers, Axios interceptors, and shared request wrappers can intensify this flaw because they automatically add tokens or headers to attacker-influenced requests.
React, Vue, Angular, and similar frameworks do not prevent client-side CSRF on their own if application code still derives request parameters from attacker-controlled browser inputs.

## References

- [MITRE CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
- [OWASP Top 10 2025 A01: Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN: `Window.fetch()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/fetch)
- [MDN: `Window.postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)

## Quick Checklist

- Attacker-controlled browser inputs do not directly choose request URLs, methods, headers, or bodies for authenticated actions.
- State-changing requests are hard-coded or selected from predefined safe request data, not replayed from the URL or a message payload.
- `postMessage` handlers verify `origin`, validate message schema, and map message types to fixed safe actions.
- Findings are confirmed by real source-to-request flow and a reachable state-changing endpoint, not by the mere presence of `fetch`.
