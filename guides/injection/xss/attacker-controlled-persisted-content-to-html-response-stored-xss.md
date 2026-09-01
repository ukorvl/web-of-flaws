---
id: WOF-XSS-005
title: Attacker-controlled Persisted Content to HTML Response (Stored XSS)
kind: vulnerability
default_severity: high
exploitability: high
standards:
  cwe:
    - CWE-79
  owasp_top_10:
    - "A05:2025 Injection"
platforms:
  - server
  - browser
languages:
  - html
  - javascript
  - typescript
  - python
detection:
  type: dataflow
  methods:
    - grep
    - ast
    - taint-analysis
    - semantic-review
  candidate_tokens:
    - req.body
    - request.form
    - request.POST
    - .create(
    - .save(
    - .insert(
    - .update(
    - .upsert(
    - res.send(
    - res.write(
    - res.end(
    - res.render(
    - render_template(
    - "<%-"
    - "{{{"
    - "|safe"
sources:
  - "user-created comments, reviews, profile fields, posts, and messages"
  - "attacker-controlled request bodies and form fields"
  - "imported content from attacker-controlled files or integrations"
  - "application logs or audit records that contain attacker-controlled values"
sinks:
  - "HTML responses that render persisted attacker-controlled content"
  - "unescaped template output such as `{{{ ... }}}`, `<%- ... %>`, or `|safe`"
  - "raw HTML rendering helpers fed by stored values"
tags:
  - xss
  - stored-xss
  - persistent-xss
  - server-side
  - persisted-content
  - html-response
---

## Rule

Treat persisted content as untrusted when it can originate from users, imports, integrations, or logs.
Do not render stored values into HTML, inline JavaScript, attributes, or URL-valued response contexts without context-sensitive output encoding or safe auto-escaped templating.

If the product intentionally supports user-authored HTML, sanitize it with a maintained allowlist-based HTML sanitizer and render only the sanitizer's output.

## Mental Model

Stored XSS is a multi-request dataflow.
The attacker submits content, the application persists it, and a later page renders that same content for one or more users.

Unlike reflected XSS, the victim does not need to open the original attacker-controlled request.
The dangerous content is served from the application after it has been stored.

## Why This Matters

A single stored payload can execute whenever an affected page is viewed.
This makes stored XSS especially serious on shared content such as comments, support tickets, user profiles, and administrative audit views.

An attacker may target a page likely to be visited by a privileged user, then use the resulting same-origin script execution to access data or perform actions available to that user.

## Vulnerable Pattern

```js
app.post("/comments", async (req, res) => {
  const body = typeof req.body.body === "string" ? req.body.body : "";

  // Storage preserves the untrusted value; it does not establish trust.
  await db.comments.create({ body });
  res.redirect("/comments");
});

app.get("/comments", async (_req, res) => {
  const comments = await db.comments.findMany();

  // Problem: a stored value is interpreted as HTML for every visitor.
  res.send(comments.map((comment) => `<article>${comment.body}</article>`).join(""));
});
```

## Example Attack

An attacker posts the following as a comment:

```html
<script>alert(document.domain)</script>
```

When another user later visits the comments page, the server inserts the saved value into the response and the browser executes it as script from the application's origin.

## Why The Attack Works

1. The attacker controls a value accepted by the application.
2. The value crosses a persistence boundary, which does not make it trusted.
3. A later request retrieves the saved value.
4. The application places it into an executable browser parsing context.
5. Every viewer of the affected page can execute the attacker's code in their own session.

The storage boundary does not establish trust.
Values can also be dangerous when they reach a secondary view, such as an administrator-facing log or moderation page, even if the original user-facing page rendered them safely.

## Safer Pattern

For plain-text comments, let an auto-escaped template render the value as text.

```js
app.get("/comments", async (_req, res) => {
  const comments = await db.comments.findMany();

  res.render("comments", { comments });
});
```

```ejs
<% for (const comment of comments) { %>
  <article><%= comment.body %></article>
<% } %>
```

For a rich-text feature, define the allowed markup deliberately and sanitize with a maintained HTML sanitizer before storing or before every rendering boundary. Do not use raw template output for arbitrary user content merely because it was retrieved from the database.

Content Security Policy can reduce the impact of some XSS payloads, but it is a defense in depth measure. It does not replace correct output handling or trusted HTML sanitization.

## Detection

Detection type: `dataflow`.

- Candidate collection: find input paths that create or update persisted content, including comments, reviews, profiles, tickets, posts, imported records, and logs.
- Candidate collection: find reads of those values flowing into HTML response construction, raw HTML helpers, template raw-output markers, inline scripts, event-handler attributes, or URL-valued attributes.
- Confirmation: trace whether an attacker-controlled value can cross a persistence boundary and later reach an executable HTML context without context-sensitive encoding, safe auto-escaping, or a trusted sanitizer.
- Review every presentation path for a stored field, including internal and administrator-only views; safe handling in one view does not make a different view safe.
- Treat the database, cache, filesystem, and message queue as propagation boundaries, not as sanitization boundaries.

## False Positives

- Stored values rendered by an auto-escaped template in the correct output context are usually safe.
- Persisting user data is not itself a problem if every rendering path treats it as untrusted text.
- Sanitized rich text can be acceptable when the sanitizer is maintained, configured with a narrow allowlist, and its output is not moved into a different unsafe context.
- Returning stored data as `application/json` is not this issue unless browser code later places it into an HTML or execution sink.

## Framework Notes

Most server-side template engines escape normal text interpolation by default. Avoid their raw HTML escape hatches for stored untrusted values, including EJS `<%- ... %>`, Handlebars `{{{ ... }}}`, and Jinja `|safe`.

Server-rendered React also escapes normal text output. Risk returns when a stored value is passed to raw HTML mechanisms such as `dangerouslySetInnerHTML` or is interpolated into inline scripts.

## References

- [MITRE CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2025 A05: Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP: Testing for Stored Cross Site Scripting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/02-Testing_for_Stored_Cross_Site_Scripting)

## Quick Checklist

- Stored content is treated as untrusted at every read and rendering boundary.
- Plain text uses auto-escaped templates or context-appropriate output encoding.
- Rich-text features use a maintained sanitizer with a narrow allowlist.
- Internal and administrator-facing views receive the same XSS review as public pages.
- CSP is used as defense in depth, not as the primary XSS control.
