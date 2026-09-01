# Cross-site scripting (XSS)

XSS guides focus on cases where attacker-controlled input reaches browser execution or HTML parsing sinks.

## Rules

- [Attacker-controlled Request Input to HTML Response (Reflected XSS)](attacker-controlled-request-input-to-html-response-reflected-xss.md)
- [Attacker-controlled Persisted Content to HTML Response (Stored XSS)](attacker-controlled-persisted-content-to-html-response-stored-xss.md)
- [Attacker-controlled HTML to `window`/`document` property lookup (DOM clobbering)](attacker-controlled-html-to-window-document-property-lookup-dom-clobbering.md)
- [URL-derived input to HTML sink (`innerHTML`)](url-derived-input-to-html-sink-innerhtml.md)
- [URL-derived input to navigation sink (`javascript:` URL)](url-derived-input-to-navigation-sink-javascript-url.md)

## Notes

- [Self-XSS](notes/self-xss.md)
