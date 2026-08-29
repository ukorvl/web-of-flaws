---
id: WOF-CORS-001
title: "Untrusted Origin Reflected into Credentialed CORS Response"
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-942
  owasp_top_10:
    - "A02:2025 Security Misconfiguration"
platforms:
  - browser
  - server
languages:
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
    - Access-Control-Allow-Origin
    - Access-Control-Allow-Credentials
    - req.headers.origin
    - request.headers.get("origin")
    - ctx.get("Origin")
    - cors({
    - "origin: true"
    - "credentials: true"
sources:
  - Origin request header
  - req.headers.origin
  - request.headers.get("origin")
  - ctx.get("Origin")
sinks:
  - Access-Control-Allow-Origin response header
  - res.setHeader("Access-Control-Allow-Origin", origin)
  - response.headers.set("Access-Control-Allow-Origin", origin)
  - ctx.set("Access-Control-Allow-Origin", origin)
tags:
  - cors
  - origin-reflection
  - access-control-allow-origin
  - access-control-allow-credentials
  - same-origin-policy
  - authenticated-data
---

## Rule

Do not reflect untrusted request origins into credentialed CORS responses.
If a response can be read with credentials, set `Access-Control-Allow-Origin` only for exact allowlisted origins that are explicitly trusted for that resource.

## Mental Model

This is a cross-origin disclosure rule.
The dangerous flow is not the cross-site request by itself, but attacker-controlled origin data shaping the browser policy that decides whether JavaScript may read the authenticated response.

```text
attacker-controlled Origin
           ↓
Access-Control-Allow-Origin
           +
Access-Control-Allow-Credentials: true
           ↓
same-origin policy bypass
           ↓
authenticated response disclosure
```

## Why This Matters

Browsers already allow many cross-origin requests to be sent.
CORS decides whether the calling page's JavaScript can read the response.
If a server reflects any attacker origin into `Access-Control-Allow-Origin` and also enables `Access-Control-Allow-Credentials: true`, then attacker-controlled JavaScript can read authenticated API responses that were supposed to stay same-origin.

This is one of the canonical CORS failures because it turns the victim's browser into a cross-origin data exfiltration channel.
The impact is often private profile data, account state, tokens, billing information, or internal API output returned to an attacker-controlled page.

## Vulnerable Pattern

```js
const sessions = new Map([
  [
    "victim-session-id",
    {
      email: "victim@example.com",
      plan: "enterprise",
      mfaEnabled: true,
    },
  ],
]);

app.use((req, res, next) => {
  if (req.headers.origin) {
    // Problem: every supplied origin is reflected into ACAO.
    res.setHeader("Access-Control-Allow-Origin", req.headers.origin);

    // Problem: credentialed responses are now readable by that origin.
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }

  next();
});

app.get("/api/me", (req, res) => {
  const sessionId = req.cookies?.session;
  const account = sessionId ? sessions.get(sessionId) : null;

  if (!account) {
    return res.status(401).json({ error: "Authentication required" });
  }

  res.json(account);
});
```

## Example Attack

Attacker-controlled page:

```js
fetch("https://bank.example/api/me", {
  credentials: "include",
})
  .then((response) => response.json())
  .then((data) => steal(data));
```

Victim browser request and vulnerable response:

```http
GET /api/me HTTP/1.1
Host: bank.example
Origin: https://attacker.example
Cookie: session=...

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.example
Access-Control-Allow-Credentials: true
Content-Type: application/json

{"email":"victim@example.com","plan":"enterprise","mfaEnabled":true}
```

## Why The Attack Works

1. The attacker causes the victim's browser to send a cross-origin request from an attacker-controlled origin.
2. The browser includes credentials because the attacker code uses `credentials: "include"` and browser cookie policy allows them for that request.
3. The server copies the untrusted `Origin` header into `Access-Control-Allow-Origin`.
4. The server also returns `Access-Control-Allow-Credentials: true`, telling the browser the credentialed response may be exposed to that origin.
5. The browser makes the response body available to attacker-controlled JavaScript, bypassing the normal same-origin read restriction.

## Safer Pattern

Allow credentialed CORS only for exact trusted origins and only on routes that truly need cross-origin authenticated access.
If a resource is public, use `Access-Control-Allow-Origin: *` without credentials.
If a resource is not meant to be read cross-origin, omit CORS response headers entirely.

```js
const sessions = new Map([
  [
    "victim-session-id",
    {
      email: "victim@example.com",
      plan: "enterprise",
      mfaEnabled: true,
    },
  ],
]);

const allowedOrigins = new Set([
  "https://app.example.com",
  "https://admin.example.com",
]);

app.use("/api", (req, res, next) => {
  const origin = req.headers.origin;

  res.append("Vary", "Origin");

  if (origin && allowedOrigins.has(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }

  next();
});

app.get("/api/me", (req, res) => {
  const sessionId = req.cookies?.session;
  const account = sessionId ? sessions.get(sessionId) : null;

  if (!account) {
    return res.status(401).json({ error: "Authentication required" });
  }

  res.json(account);
});
```

The key control is the allowlist lookup.
The safer variant keeps the same session-backed authenticated endpoint behavior and changes only which origins may read the response.
Dynamic origin reflection is only safe when it is constrained to a fixed trusted set before the header is emitted.

## Detection

Detection type: `dataflow`.

- Candidate sources: `Origin` request header reads such as `req.headers.origin`, `request.headers.get("origin")`, `ctx.get("Origin")`, and framework abstractions around them.
- Candidate sinks: writes to `Access-Control-Allow-Origin`, CORS middleware configuration, and helper wrappers that decide which origin to echo back in the response.
- Confirmation: verify that attacker-controlled origin input can directly or effectively determine `Access-Control-Allow-Origin` for a response that also enables `Access-Control-Allow-Credentials: true`.
- Confirmation: verify that the affected endpoint can return authenticated or otherwise sensitive data, not just intentionally public assets.
- High-confidence signals include direct header reflection, origin callbacks that approve arbitrary origins, and middleware configs such as `cors({ origin: true, credentials: true })` on authenticated routes.
- A scanner should trace origin input into ACAO decisions and then confirm the credentialed-read condition, rather than reporting every use of CORS headers as a vulnerability.

## False Positives

- Reflecting an origin is usually not this rule when the value is first checked against a strict exact allowlist and only trusted origins pass.
- Public unauthenticated resources that intentionally use `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials` are not this issue.
- A route may still deserve review even if credentials are blocked in one browser configuration, but this rule should be confirmed based on real readable response exposure, not just the presence of CORS middleware.

## Framework Notes

Express `cors` middleware with `origin: true` reflects the request origin.
That can be acceptable for narrowly scoped public behavior, but it becomes dangerous when paired with `credentials: true` on routes that return authenticated data.
Similar pitfalls exist in Koa, Fastify, Hono, serverless edge handlers, and custom reverse-proxy logic that copies the request `Origin` into response headers.

## References

- [MITRE CWE-942: Permissive Cross-domain Security Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP Top 10 2025 A02: Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/)
- [MDN: Cross-Origin Resource Sharing (CORS)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS)
- [MDN: Cross-Origin Resource Sharing (CORS) configuration](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/CORS)
- [MDN: `Access-Control-Allow-Credentials` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Credentials)
- [MDN: `Access-Control-Allow-Origin` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin)

## Quick Checklist

- `Access-Control-Allow-Origin` is never set from an untrusted origin without an exact allowlist check.
- Credentialed CORS is enabled only for specific trusted origins and specific routes that truly need it.
- Public resources use `*` only when credentials are not allowed.
- Responses that vary by trusted origin include `Vary: Origin`.
- Findings are confirmed by attacker-controlled origin influence plus readable credentialed response exposure.
