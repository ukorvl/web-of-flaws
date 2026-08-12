---
title: Hard-coded Secrets
impact: HIGH
tags: sensitive-data-exposure, secrets-management, secrets, source-code, jwt, credentials, source-maps
---

## Rule

Do not hard-code passwords, API tokens, signing keys, database credentials, or other secrets in source code, templates, test fixtures, or client-side bundles.
Load secrets from controlled runtime configuration or a dedicated secret manager instead.

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

  // Later, the server trusts any token that verifies with that same secret.
  const payload = jwt.verify(token, JWT_SECRET);

  if (payload.role !== "admin") {
    return res.status(403).json({ error: "forbidden" });
  }

  // If an attacker can sign role=admin with JWT_SECRET, they reach this code path.
  return res.json({ revenue: "sensitive report contents" });
});
```

## Example Attack

If the repository, a server bundle, or a source archive becomes accessible, the attacker can extract the signing key and mint an admin token.

```js
import jwt from "jsonwebtoken";

// The attacker copied the signing key from the repository or shipped server code.
const stolenSecret = "prod-2026-super-secret-signing-key";

// They can now mint a token offline without touching the server.
const forgedAdminToken = jwt.sign(
  { sub: "attacker", role: "admin" },
  stolenSecret,
  { expiresIn: "1h" },
);

// Sending this token as `Authorization: Bearer <token>` to `/admin/report`
// will pass `jwt.verify(...)` because the secret matches the server's secret.
console.log(forgedAdminToken);
```

## Why The Attack Works

1. The application stores a production signing secret directly in code.
2. Anyone who can read that code can recover the secret verbatim.
3. JWT verification trusts possession of the secret as proof that the token is legitimate.
4. The attacker signs their own token with the leaked key.
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

A stronger practice is to keep `.env` files or equivalent environment-variable bundles encrypted at rest. This reduces the chance that private keys and other credentials are exposed in plaintext on disk, pasted into shell commands, or left behind in terminal history, and it can make storing the encrypted file in GitHub acceptable if the decryption password or key is strong, kept separate, and access to it is tightly controlled.
In production, prefer a managed secret store with access controls, rotation, and audit logs.

## Client-side Code And Public Keys

Anything shipped to the browser should be treated as public. Even if you bundle and minify your code, an attacker can extract any embedded secrets from the client-side bundle or source maps.
Only embed values that are intentionally non-secret, such as publishable keys explicitly designed for client-side use.

## Review Hints

- Search for suspicious identifiers such as `secret`, `token`, `password`, `apiKey`, `privateKey`, `BEGIN PRIVATE KEY`, `AKIA`, `sk_live_`, and hard-coded connection strings.
- Check frontend bundles, source maps, Dockerfiles, seed data, example config files, CI output, and test fixtures for copied production credentials.
- Flag code that falls back to a default production secret when an environment variable is missing.
- If a secret may have been committed before, remember that deleting it from the latest revision is not enough; assume rotation is required.

## Quick Checklist

- Secrets are not stored directly in source files or client bundles.
- Runtime configuration fails closed when a required secret is missing.
- Production secrets come from a controlled secret-management path.
- Any `.env` file kept in the repository is encrypted at rest, and its decryption key is stored separately.
- Exposed or previously committed secrets are rotated, not merely renamed or deleted from the current file.
