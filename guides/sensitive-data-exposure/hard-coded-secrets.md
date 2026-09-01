---
id: WOF-SDE-001
title: Hard-coded Secrets
kind: vulnerability
default_severity: high
exploitability: medium
standards:
  cwe:
    - CWE-798
    - CWE-321
  owasp_top_10:
    - id: "A04:2025 Cryptographic Failures"
      relationship: direct
    - id: "A07:2025 Authentication Failures"
      relationship: direct
  mappings:
    - cwe: CWE-321
      owasp_top_10: "A04:2025 Cryptographic Failures"
      relationship: direct
    - cwe: CWE-798
      owasp_top_10: "A07:2025 Authentication Failures"
      relationship: direct
platforms:
  - server
  - browser
  - mobile
  - ci-cd
  - infrastructure
  - container
languages:
  - javascript
  - typescript
  - yaml
  - dotenv
  - json
  - shell
  - terraform
  - dockerfile
  - java
  - kotlin
  - swift
detection:
  type: semantic-pattern
  methods:
    - grep
    - entropy-analysis
    - ast
    - semantic-review
  candidate_tokens:
    - SECRET
    - TOKEN
    - PASSWORD
    - API_KEY
    - PRIVATE_KEY
    - BEGIN PRIVATE KEY
    - AKIA
    - sk_live_
    - JWT_SECRET
indicators:
  - variables or config keys named SECRET, TOKEN, PASSWORD, API_KEY, or PRIVATE_KEY
  - PEM blocks and private key material
  - cloud, SaaS, and database credential formats
tags:
  - sensitive-data-exposure
  - secrets-management
  - secrets
  - source-code
  - credentials
  - jwt
  - source-maps
---

## Rule

Do not hard-code passwords, API tokens, signing keys, database credentials, or other secrets in source code, templates, sample data files, or client-side bundles.
Load secrets from controlled runtime configuration or a dedicated secret manager instead.

## Mental Model

This is a secret-placement rule, not primarily a taint rule.
The problem starts when a real credential is embedded in an artifact that gets copied, reviewed, logged, bundled, cached, or shipped more widely than the credential itself was meant to travel.

## Why This Matters

Hard-coded secrets are easy to leak through repositories, pull requests, container images, CI logs, source archives, browser bundles, and source maps.
Once exposed, an attacker can often reuse the secret immediately to impersonate users, forge tokens, call privileged APIs, or access data stores.

## Vulnerable Pattern

```js
import express from "express";
import jwt from "jsonwebtoken";

const app = express();
// Problem: this production signing key is committed directly into the source.
const JWT_SECRET = "prod-2026-super-secret-signing-key";

app.get("/login-as-demo", (_req, res) => {
  // The application issues a normal user token with the hard-coded secret.
  const token = jwt.sign(
    { sub: "demo-user", role: "user" },
    JWT_SECRET,
    { expiresIn: "1h" },
  );

  res.json({ token });
});

app.get("/admin/report", (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "missing token" });
  }

  // The same secret is later trusted to verify privileged tokens.
  const payload = jwt.verify(token, JWT_SECRET);

  if (payload.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }

  return res.json({ revenue: "sensitive report contents" });
});
```

## Example Attack

If the repository, a server bundle, or a source archive becomes accessible, the attacker can recover the secret and mint an admin token offline.

```js
import jwt from "jsonwebtoken";

// The attacker copied the signing key from the repository or shipped server code.
const stolenSecret = "prod-2026-super-secret-signing-key";

// They can now mint a privileged token without touching the application.
const forgedAdminToken = jwt.sign(
  { sub: "attacker", role: "admin" },
  stolenSecret,
  { expiresIn: "1h" },
);

// Sending this token as `Authorization: Bearer <token>` to `/admin/report`
// will pass verification because the secret matches the server's secret.
console.log(forgedAdminToken);
```

## Why The Attack Works

1. The application stores a production signing secret directly in code.
2. Anyone who can read that code or a derived artifact can recover the secret verbatim.
3. JWT verification treats possession of that secret as proof that a token is legitimate.
4. The attacker signs their own `role=admin` token with the leaked key.
5. The application accepts the forged token and grants privileged access.

## Safer Pattern

Keep secrets out of source control and inject them at runtime.
Fail closed if a required secret is missing, and rotate the secret if you suspect it was exposed.

```js
import express from "express";
import jwt from "jsonwebtoken";

const app = express();
// The secret is injected at runtime instead of being stored in the repository.
const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
  throw new Error("JWT_SECRET must be provided at runtime");
}

app.get("/login-as-demo", (_req, res) => {
  // The application still signs tokens, but the key now comes from runtime config.
  const token = jwt.sign(
    { sub: "demo-user", role: "user" },
    jwtSecret,
    { expiresIn: "1h" },
  );

  res.json({ token });
});

app.get("/admin/report", (req, res) => {
  const token = req.headers.authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "missing token" });
  }

  // Verification still works the same way, but secret management moved out of code.
  const payload = jwt.verify(token, jwtSecret);

  if (payload.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }

  return res.json({ revenue: "sensitive report contents" });
});
```

Use environment variables only as a delivery mechanism, not as the long-term source of truth.
If a secret is loaded from a `.env` file, make sure that file is never reachable over HTTP and cannot be served by the web server as a static asset.
Treat `.env` files as sensitive deployment artifacts, not as public files that merely happen to live on the same host.

A stronger practice is to keep `.env` files or equivalent environment-variable bundles encrypted at rest. This reduces the chance that private keys and other credentials are exposed in plaintext on disk, pasted into shell commands, or left behind in terminal history. Encrypted env bundles can be stored in GitHub if the repository only contains ciphertext and the decryption password or key is strong, stored separately, and tightly access-controlled.

In production, prefer a managed secret store with access controls, rotation, audit logs, and short-lived credentials where possible.

## Detection

Detection type: `semantic-pattern`.

- Candidate collection: search for suspicious identifiers such as `secret`, `token`, `password`, `apiKey`, `privateKey`, `BEGIN PRIVATE KEY`, `AKIA`, `sk_live_`, and hard-coded connection strings.
- Candidate ranking: combine identifier heuristics, high-entropy string detection, AST assignment patterns, and known credential formats.
- Confirmation: determine whether the value is a real secret, whether it is committed or shipped in a distributable artifact, and whether it could reach unintended readers such as repository users, browser clients, build logs, or container consumers.
- Review surrounding artifacts as well as source files: frontend bundles, source maps, Dockerfiles, Helm charts, CI output, example configs, and seed data can all carry the same secret.
- A scanner should find likely secrets; the agent or reviewer should confirm that the value is sensitive, non-placeholder, and actually exposed beyond its intended trust boundary.

## False Positives

- Clearly fake placeholders such as `YOUR_API_KEY_HERE` or `example-not-a-real-secret` should not be reported as production secret leaks.
- Code that reads `process.env.JWT_SECRET` is not a hard-coded secret finding just because the variable name contains `SECRET`.
- Synthetic sample values can still be poor examples, but they are not the same severity as committed production credentials unless they are real or reused outside the test boundary.

## Scope Notes

This rule is not limited to Node.js or Express.
The same weakness appears when secrets are embedded in browser bundles, mobile apps, Terraform or Helm values, CI/CD definitions, source maps, Docker images, or example configuration files that accidentally carry live credentials.

## References

- [MITRE CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [MITRE CWE-321: Use of Hard-coded Cryptographic Key](https://cwe.mitre.org/data/definitions/321.html)
- [OWASP Top 10 2025 A04: Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/)
- [OWASP Top 10 2025 A07: Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [SOPS documentation](https://getsops.io/docs/)

## Quick Checklist

- Secrets are not stored directly in source files, client bundles, or committed config.
- Runtime configuration fails closed when a required secret is missing.
- Any `.env` file kept in the repository is encrypted at rest, and its decryption key is stored separately.
- Reviewers check for the same secret in bundles, source maps, container images, and CI artifacts.
- Exposed or previously committed secrets are rotated, not merely renamed or deleted from the current file.
