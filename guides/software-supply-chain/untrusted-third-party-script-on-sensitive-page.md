---
id: WOF-SUPPLY-005
title: "Untrusted Third-Party Script on Sensitive Page"
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-829
  owasp_top_10:
    - id: "A03:2025 Software Supply Chain Failures"
      relationship: related
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
    - "<script src="
    - next/script
    - googletagmanager.com
    - gtag(
    - eth_sendTransaction
    - signTypedData
indicators:
  - external or third-party script loads on pages that handle passwords, MFA, checkout, account recovery, admin actions, wallet connection, transaction review, or signing flows
  - analytics, chat, support, tag-manager, A/B testing, or session-recording SDKs that execute in the same page context as sensitive UI or secrets
  - framework code that injects remote scripts dynamically through helpers such as `next/script`, DOM script creation, or tag-manager bootstrap snippets
  - third-party scripts that can read DOM state, hook form submission, intercept fetch/XHR, or patch wallet and auth APIs before privileged actions execute
tags:
  - supply-chain
  - frontend
  - web3
  - third-party-script
  - analytics
  - tag-manager
---

## Rule

Treat third-party scripts on sensitive pages as untrusted same-page code execution.
Do not load analytics, chat, tag-manager, or similar third-party JavaScript on pages that handle credentials, payment details, administrative actions, API tokens, or wallet transaction and signing flows unless the script is eliminated, strongly isolated, or otherwise reduced to an explicitly accepted risk.

## Mental Model

```text
third-party script include
      ↓
script executes in page context
      ↓
same DOM and JavaScript privileges
      ↓
sensitive data or privileged action
      ↓
secret theft or transaction tampering
```

The vendor script is not "just a widget."
Once it executes in the page, it can generally read, modify, and invoke the same browser-side state and APIs as the application's own JavaScript.

## Why This Matters

If a third-party analytics, chat, or tag-manager dependency is compromised, every page that loads it becomes a potential execution path for attacker code.
On sensitive pages, that can mean credential theft, checkout tampering, token capture, or manipulation of security-critical actions before the user confirms them.
This is especially relevant to frontend and Web3 flows because a same-page script can alter displayed transaction data or the parameters sent to wallet APIs, even if it cannot directly extract private keys from the wallet itself.

## Vulnerable Pattern

```html
<!doctype html>
<html lang="en">
  <head>
    <script
      async
      src="https://third-party.example/sdk.js"
    ></script>
    <script type="module" src="/assets/send-transaction.js"></script>
  </head>
  <body>
    <main>
      <h1>Confirm treasury transfer</h1>
      <button id="send">Send 1.5 ETH</button>
    </main>
  </body>
</html>
```

```js
document.querySelector("#send").addEventListener("click", async () => {
  await window.ethereum.request({
    method: "eth_sendTransaction",
    params: [
      {
        from: window.currentAccount,
        to: "0x9fB1b7B5a2Eab2e3b3bB43B6D8C7401d57f01A11",
        value: "0x14d1120d7b160000",
      },
    ],
  });
});
```

## Example Attack

```text
1. A wallet confirmation page loads a third-party analytics SDK.
2. The vendor script is compromised or replaced upstream.
3. The malicious script patches window.ethereum.request before the app invokes it.
4. It swaps the destination address or modifies typed-data fields shown to the user.
5. The user signs a transaction or approval they did not intend.
```

The same pattern also applies to login, MFA, password reset, checkout, and admin pages where a compromised third-party script can read secrets or tamper with privileged requests before submission.

## Why The Attack Works

1. The sensitive page imports executable JavaScript from an origin the application does not fully control.
2. The browser executes that script in the page context, alongside the application's own code.
3. The third-party script can access the DOM, JavaScript objects, network APIs, event handlers, and other browser-visible state available to that page.
4. On a sensitive route, those capabilities reach credentials, tokens, payment details, transaction parameters, or privileged actions.
5. A compromise of the third-party provider or its delivery path becomes a direct compromise of the sensitive page.

## Safer Pattern

Eliminate third-party scripts from sensitive pages whenever possible.
If a business function must remain, prefer server-side integrations, narrow event forwarding, or a strongly sandboxed isolated frame instead of same-page script execution.
For less-sensitive pages where an external script is still justified, self-hosting a reviewed immutable copy, CSP, and SRI can reduce some classes of risk, but they do not make an untrusted third-party script equivalent to first-party code.
If the page also needs anti-framing protection, deliver that policy as an HTTP response header instead of trying to express it in a `<meta http-equiv="Content-Security-Policy">` element.

```html
<!doctype html>
<html lang="en">
  <head>
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'"
    >
    <script type="module" src="/assets/send-transaction.js"></script>
  </head>
  <body>
    <main>
      <h1>Confirm treasury transfer</h1>
      <button id="send">Send 1.5 ETH</button>
    </main>
  </body>
</html>
```

```http
Content-Security-Policy: frame-ancestors 'none'
X-Frame-Options: DENY
```

```html
<iframe
  src="https://support.example/widget.html"
  sandbox="allow-scripts allow-forms"
  referrerpolicy="no-referrer"
  title="Support"
></iframe>
```

If an external script really must run directly in the page, pin the exact asset when feasible, add SRI where supported, constrain script origins with CSP, and keep it off the routes that perform sensitive actions.

## Detection

Detection type: `semantic-pattern`.

- Candidate collection: inspect HTML, templates, framework components, and DOM script injection code for external `<script src>` loads, `next/script`, tag-manager bootstraps, and remote SDK initialization.
- Candidate collection: inspect route names, page components, and UI flows for sensitive contexts such as login, MFA, password reset, checkout, billing, admin, wallet connection, transaction review, token approvals, and signing prompts.
- Candidate collection: inspect for third-party analytics, chat, session-replay, support, experimentation, or tag-manager vendors on those routes.
- Confirmation: verify that a third-party or otherwise insufficiently trusted script executes in the same page context as a sensitive flow and can reach a privileged effect such as credential capture, token capture, request tampering, transaction parameter modification, or DOM manipulation of security-relevant UI.
- Confirmation requires both third-party same-page execution and a sensitive page or reachable privileged action. A vendor script on a low-risk marketing page is not enough for this rule.
- High-confidence signals include external scripts on login, recovery, checkout, admin, or Web3 transaction/signing pages, especially where the script can run before form submission or wallet API invocation.
- A scanner should surface third-party script loads plus route sensitivity signals; the agent or reviewer should confirm whether the script is truly third-party, whether the page is sensitive, and whether isolation removes same-page execution.

## False Positives

- A reviewed same-origin script that is built and deployed as part of the application is not automatically this rule, even if it originated from a vendor library during development.
- A third-party image, stylesheet, or server-side API call without same-page JavaScript execution is a different risk from an executable remote script.
- A sandboxed iframe with a narrow postMessage contract can still deserve review, but it is materially safer than giving the vendor direct same-page script execution.
- CSP and SRI are useful hardening controls, but their presence alone does not make a sensitive same-page third-party script safe; the core question is whether untrusted code still executes in the privileged page context.

## Framework Notes

Modern frameworks often hide remote script loading behind helpers such as `next/script`, consent-manager wrappers, or tag-manager configuration rather than raw HTML.
For Web3 applications, the most important question is not whether the third-party code can extract private keys directly, but whether it can change transaction details, approval targets, signing payloads, or user-visible security cues before the wallet request is made.

## References

- [MITRE CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)
- [OWASP Top 10 2025 A03: Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)
- [OWASP Cheat Sheet Series: Third Party JavaScript Management](https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html)
- [MDN Web Docs: `<script>` HTML element](https://developer.mozilla.org/en-US/docs/Web/HTML/Reference/Elements/script)
- [MDN Web Docs: HTMLScriptElement.src](https://developer.mozilla.org/en-US/docs/Web/API/HTMLScriptElement/src)
- [MDN Web Docs: Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)
- [MDN Web Docs: Content-Security-Policy `frame-ancestors`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors)
- [MDN Web Docs: Content-Security-Policy `script-src`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/script-src)

## Quick Checklist

- Sensitive routes do not load third-party analytics, chat, tag-manager, or similar remote scripts by default.
- Third-party UI or telemetry needs are moved off sensitive pages, pushed server-side, or isolated from same-page execution.
- External scripts that remain are explicitly reviewed, pinned where feasible, and constrained with CSP and SRI where applicable.
- Web3 transaction, approval, and signing flows assume any same-page third-party script can tamper with user-visible data and request parameters.
- Reviewers treat third-party same-page script execution on sensitive pages as a real supply-chain trust boundary, not as harmless frontend plumbing.
