# Web of Flaws

Web of Flaws is a markdown-first catalog of vulnerable web patterns and safer replacements.
The repository is designed for both humans and coding agents: each guide shows the risky pattern,
why it is exploitable, and how to fix it with concrete code.

## For Agents

The repository is designed to be agent-friendly. Each guide is structured in a consistent way, with clear sections for the risky pattern, safer replacement, and detection metadata.

- Machine-readable rule catalog: [catalog/rules.json](catalog/rules.json)
- Rule guides carry stable IDs, standards mappings, detection metadata, kind, tags and severity. This data is stored in YAML frontmatter at the top of each guide to help agents work with the rules programmatically.

## Repository Shape

- Categories are grouped by security topic and vulnerability family.
- [Cross-origin Communication](guides/cross-origin-communication/README.md)
- [Injection](guides/injection/README.md)
- [Request Authenticity](guides/request-authenticity/README.md)
- [Sensitive Data Exposure](guides/sensitive-data-exposure/README.md)

## License

This repository is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
