# Cross-site scripting (XSS)

XSS guides focus on cases where attacker-controlled input reaches browser execution or HTML parsing sinks.

## Rules

- [Attacker-controlled Request Input to HTML Response (Reflected XSS)](attacker-controlled-request-input-to-html-response-reflected-xss.md)
- [Attacker-controlled Persisted Content to HTML Response (Stored XSS)](attacker-controlled-persisted-content-to-html-response-stored-xss.md)
- [Attacker-controlled HTML to `window`/`document` property lookup (DOM clobbering)](attacker-controlled-html-to-window-document-property-lookup-dom-clobbering.md)
- [Attacker-controlled Browser Input to HTML Parsing Sink (DOM XSS)](attacker-controlled-browser-input-to-html-parsing-sink-dom-xss.md)
- [Attacker-controlled URL to Executable Navigation Sink (`javascript:` URL)](attacker-controlled-url-to-executable-navigation-sink-javascript-url.md)

## Notes

- [Self-XSS](notes/self-xss.md)
