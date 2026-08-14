---
id: WOF-PM-001
title: "postMessage Receiver Without Exact Origin Validation"
kind: vulnerability
severity: high
exploitability: medium
standards:
  cwe:
    - CWE-346
    - CWE-940
  owasp_top_10:
    - "A07:2025 Authentication Failures"
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
indicators:
  - window.addEventListener("message", ...) or window.onmessage = ...
  - handlers that process event.data without checking event.origin
  - origin checks using substring, prefix, suffix, regex, or wildcard matching instead of exact allowlisted origins
  - message-driven actions that complete payments, approve wallet flows, link accounts, navigate, or invoke backend mutations
tags:
  - postmessage
  - origin-validation
  - iframe
  - widget
  - payment
  - wallet
  - cross-origin
---

## Rule

Treat `message` events as untrusted cross-origin input.
Do not process `event.data` unless the receiver first verifies `event.origin` against an exact allowlist of expected origins and, when practical, confirms the expected sender window as well.

## Mental Model

`postMessage` is a deliberate hole through the same-origin policy.
The security boundary moves from the browser to your receiver code, so a vague origin check is effectively the same as letting an attacker talk directly to privileged widget logic.

## Why This Matters

This flaw is extremely common in iframe, popup, wallet, identity, and payment integrations.
If the receiver trusts any sender or uses fuzzy matching such as `includes`, `indexOf`, `endsWith`, or a broad regex, an attacker-controlled page can trigger privileged flows, spoof success states, or send crafted data into trusted application logic.

## Vulnerable Pattern

```html
<iframe id="payment-frame" src="https://pay.example.com/widget"></iframe>

<script>
  async function finalizeOrder(orderId, returnUrl) {
    await fetch("/api/orders/complete", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ orderId }),
    });

    window.location.assign(returnUrl);
  }

  window.addEventListener("message", async (event) => {
    // Problem: partial matching accepts attacker-controlled origins such as
    // https://pay.example.com.attacker.test
    if (!event.origin.includes("pay.example.com")) {
      return;
    }

    if (event.data?.type === "payment-success") {
      await finalizeOrder(event.data.orderId, event.data.returnUrl);
    }
  });
</script>
```

## Example Attack

```html
<!-- Origin: https://pay.example.com.attacker.test -->
<iframe id="victim" src="https://merchant.example.com/checkout"></iframe>

<script>
  const victim = document.getElementById("victim").contentWindow;

  victim.postMessage(
    {
      type: "payment-success",
      orderId: "ORDER-31337",
      returnUrl: "https://attacker.test/fake-receipt",
    },
    "https://merchant.example.com",
  );
</script>
```

## Why The Attack Works

1. Any page with a window reference can send a `message` event to the receiver.
2. The receiver performs a fuzzy string check instead of exact origin validation.
3. An attacker-controlled origin such as `https://pay.example.com.attacker.test` passes the flawed check.
4. The receiver trusts `event.data` and routes it into privileged order-completion logic.
5. The application marks the order as complete or navigates the victim based on an attacker-supplied message.

## Safer Pattern

Use an exact allowlist for origins, validate the sender window when possible, and treat `event.data` as untrusted until its schema is validated.

```html
<iframe id="payment-frame" src="https://pay.example.com/widget"></iframe>

<script>
  const paymentFrame = document.getElementById("payment-frame");
  const allowedOrigins = new Set(["https://pay.example.com"]);

  function isPaymentMessage(data) {
    return (
      typeof data === "object" &&
      data !== null &&
      data.type === "payment-success" &&
      typeof data.orderId === "string"
    );
  }

  async function finalizeOrder(orderId) {
    await fetch("/api/orders/complete", {
      method: "POST",
      credentials: "include",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ orderId }),
    });

    window.location.assign("/checkout/success");
  }

  window.addEventListener("message", async (event) => {
    if (!allowedOrigins.has(event.origin)) {
      return;
    }

    if (event.source !== paymentFrame.contentWindow) {
      return;
    }

    if (!isPaymentMessage(event.data)) {
      return;
    }

    await finalizeOrder(event.data.orderId);
  });
</script>
```

## Detection

Detection type: `semantic-pattern`.

- Candidate collection: search for `window.addEventListener("message", ...)`, `window.onmessage =`, and framework wrappers around `message` events.
- Confirmation: verify that the handler processes `event.data` or triggers privileged actions before enforcing an exact allowlist of full origin strings.
- Treat `includes`, `indexOf`, `startsWith`, `endsWith`, regex matching, hostname-only comparisons, or checks that ignore scheme or port as suspicious until proven safe.
- High-confidence findings often complete payments, advance checkout state, approve wallet or identity flows, write tokens to storage, navigate, or call privileged backend endpoints.
- A scanner should surface message handlers and validation patterns; the agent or reviewer should confirm whether an attacker-controlled origin can reach a sensitive branch with crafted message data.

## False Positives

- A receiver that checks `event.origin` against a fixed allowlist of exact origin strings and validates message schema is usually not this issue.
- Multi-environment integrations can still be safe if they allow only explicit production, staging, or local-development origins, each as a full origin string.
- Telemetry or debugging listeners may be lower priority if they do not expose data or trigger sensitive behavior, though they still deserve review if message contents flow elsewhere.

## Framework Notes

React, Vue, Angular, and SDK wrappers do not remove this risk.
Many widget integrations correctly use a strict sender `targetOrigin` but still fail on the receiving side because the application does not perform an exact `event.origin` check before mutating state or invoking backend actions.

## References

- [MITRE CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [MITRE CWE-940: Improper Verification of Source of a Communication Channel](https://cwe.mitre.org/data/definitions/940.html)
- [OWASP Top 10 2025 A07: Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [MDN: `Window.postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)

## Quick Checklist

- Every `message` receiver checks `event.origin` against an exact allowlist of expected origins.
- Origin validation uses full origin strings, not substring or suffix matching.
- The receiver validates message shape before using `event.data`.
- Sensitive flows also verify the expected sender window when a stable frame or popup reference exists.
