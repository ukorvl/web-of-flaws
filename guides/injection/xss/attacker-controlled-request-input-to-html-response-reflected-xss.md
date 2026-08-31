---
id: WOF-XSS-004
title: Attacker-controlled Request Input to HTML Response (Reflected XSS)
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
    - req.query
    - req.params
    - req.body
    - req.headers
    - req.cookies
    - request.args
    - request.form
    - request.GET
    - request.POST
    - request.headers
    - res.send(
    - res.write(
    - res.end(
    - res.render(
    - render_template(
    - "<%-"
    - "{{{"
    - "|safe"
sources:
  - "Express `req.query`"
  - "Express `req.params`"
  - "Express `req.body`"
  - "Express `req.headers`"
  - "Express `req.cookies`"
  - "Flask `request.args`"
  - "Flask `request.form`"
  - "Django `request.GET`"
  - "Django `request.POST`"
  - "request headers and cookies reflected into HTML responses"
sinks:
  - "`res.send()` with attacker-controlled HTML content"
  - "`res.write()` with attacker-controlled HTML content"
  - "`res.end()` with attacker-controlled HTML content"
  - "server-side template output in an HTML response"
  - "unescaped template output such as `{{{ ... }}}`, `<%- ... %>`, or `|safe`"
tags:
  - xss
  - reflected-xss
  - server-side
  - request-input
  - html-response
---

## Rule

Treat request-derived data as untrusted when building HTML responses.
Do not reflect query parameters, path parameters, form fields, headers, cookies, or other attacker-controlled request input into HTML, inline JavaScript, attributes, or URL-valued response contexts without context-sensitive output encoding or safe auto-escaped templating.

## Mental Model

This is a server-to-browser dataflow rule.
The attacker controls part of the HTTP request, the server copies that data into an HTML response, and the browser then parses the response as trusted content from the vulnerable origin.

Unlike DOM XSS, the unsafe transformation happens on the server or template path before the page reaches the browser.

## Why This Matters

Reflected XSS often needs only a crafted URL or form submission.
If the victim loads the attacker-controlled request, the browser can execute injected code with the privileges of the vulnerable origin.

That can lead to session abuse, sensitive data access, phishing inside a trusted page, unauthorized actions, or chaining into other browser-side attack paths.

## Vulnerable Pattern

```js
app.get("/search", (req, res) => {
  const query = typeof req.query.q === "string" ? req.query.q : "";

  // Problem: request input is copied directly into an HTML response.
  res.send(`
    <h1>Results for ${query}</h1>
    <p>No matches found.</p>
  `);
});
```

## Example Attack

```text
https://example.com/search?q=%3Cscript%3Ealert(document.domain)%3C/script%3E
```

## Why The Attack Works

1. The attacker controls the `q` parameter in the HTTP request.
2. The server reads that parameter and inserts it into an HTML response.
3. The response is served from the trusted application origin.
4. The browser parses the injected string as active markup instead of as inert text.
5. The attacker's script executes in the victim's session.

The same underlying flaw can also appear in attribute, URL, CSS, or inline JavaScript contexts, often with different payload shapes.

## Safer Pattern

Prefer templates and rendering paths that escape untrusted values by default for the current output context.
If you are placing untrusted data into normal HTML text, encode it before building the response.

```js
function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

app.get("/search", (req, res) => {
  const query = typeof req.query.q === "string" ? req.query.q : "";

  res.send(`
    <h1>Results for ${escapeHtml(query)}</h1>
    <p>No matches found.</p>
  `);
});
```

This example is safe for HTML text context only.
Do not reuse HTML entity encoding blindly inside attributes, URLs, CSS, or inline JavaScript.
Those contexts need their own safe construction patterns or context-specific encoding rules.

Avoid raw template escape hatches such as `{{{ ... }}}`, `<%- ... %>`, or `|safe` for attacker-controlled values.

## Detection

Detection type: `dataflow`.

- Candidate collection: find request-derived sources such as `req.query`, `req.params`, `req.body`, `req.headers`, `req.cookies`, `request.args`, `request.form`, `request.GET`, and `request.POST`.
- Candidate collection: find HTML response sinks such as `res.send(...)`, `res.write(...)`, `res.end(...)`, template render paths, and template raw-output markers such as `{{{ ... }}}`, `<%- ... %>`, or `|safe`.
- Confirmation: trace whether attacker-controlled request data can reach an HTML response context without context-sensitive encoding, safe auto-escaping, or a trusted sanitizer.
- Give extra attention to reflected data inserted into inline scripts, event handlers, URL-valued attributes, or raw HTML blocks, because generic HTML escaping is not sufficient for every context.
- Distinguish this from DOM XSS: if the dangerous transformation happens later in browser JavaScript rather than during server response generation, use the DOM XSS rule instead.

## False Positives

- Returning attacker-controlled data in `application/json` or `text/plain` is not this issue unless that data is later embedded into a browser execution sink elsewhere.
- Auto-escaped server templates in the correct output context are usually acceptable, provided developers are not bypassing escaping with raw output helpers.
- Mapping a user-controlled ID through a fixed allowlist of display strings is different from reflecting raw request data into the response.
- HTML text encoding alone does not prove safety if the data is actually rendered inside an attribute, URL, CSS block, or inline JavaScript.

## Framework Notes

Many server-side template engines escape normal text interpolation by default, but unsafe escape hatches reintroduce risk.
Examples include EJS `<%- ... %>`, Handlebars `{{{ ... }}}`, and Jinja `|safe`.

Server-rendered React and similar frameworks also escape normal text output by default.
The risk returns when applications inject raw HTML, build inline scripts from request data, or bypass framework defaults in template helpers.

## References

- [MITRE CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP Top 10 2025 A05: Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)
- [OWASP Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN: Cross-site scripting (XSS)](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS)

## Quick Checklist

- Request-derived data does not flow into HTML responses as raw executable content.
- Output encoding matches the exact browser parsing context, not just "escaped somewhere."
- Auto-escaped templates are preferred over manual string concatenation.
- Raw output helpers and template escape hatches are not used with attacker-controlled values.
