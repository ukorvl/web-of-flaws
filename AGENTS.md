# Agents guide for Web of Flaws

## Overview

This project is a catalog of vulnerable web patterns and safer replacements, designed for both humans and coding agents. Each guide shows the risky pattern, why it is exploitable, and how to fix it with concrete code. The core idea is to provide a structured and machine-readable format that allows agents to parse the guides and extract relevant information.

The repository is organized into categories based on security topics and vulnerability families. Each category contains guides that follow a consistent structure. Each category has a `README.md` file that provides an overview of the category and links to the individual guides.

A purpose of this repository is to enable coding agents to learn from the guides and apply the knowledge to identify and fix vulnerabilities in web applications. Humans also are supposed to benefit from it by learning about common web vulnerabilities and how to mitigate them. Consider this repository as a knowledge base for both humans and agents to improve web security.

A guide can be either a single markdown file or a directory containing multiple files. Guide markdown files should start with YAML frontmatter that includes standard properties of each guide, followed by the standard heading structure. Dataflow rules should declare explicit `sources` and `sinks`; pattern rules should declare `indicators`. Look at `.markdownlint-cli2.jsonc`, `CONTRIBUTING.md`, `catalog/rules.json`, and `catalog/allowed-reference-domains.json` for the expected guide structure.

## Environment

This is a docs-first repository with no app runtime or build step. The main local tool is `markdownlint-cli2`; run `npx markdownlint-cli2 "**/*.md"` and use `--fix` when appropriate. Follow `.editorconfig` for whitespace and indentation, and keep in mind that CI checks Markdown style, links, and GitHub Actions security.

## Workspace structure

All guides are located in the `guides` directory. Each category has its own subdirectory, and each guide is either a markdown file or a directory containing multiple files.

## Before marking things as done

### General rules

- Run `npx markdownlint-cli2 "**/*.md"` and fix any issues, or explicitly note anything left unresolved.
- If you changed Markdown heavily, prefer `npx markdownlint-cli2 --fix "**/*.md"` before final review.
- Verify any new or changed links in guides are valid and relevant; avoid placeholders unless they are clearly marked.
- Before adding any external link in `guides/`, confirm that its domain is listed in `catalog/allowed-reference-domains.json`. If it is not listed, add it there with a clear scope and rationale before using it in a guide.
- Every new or changed external URL in `guides/` must be checked by opening it and confirming that it resolves to the intended document. Prefer canonical final URLs over links that only work through redirects.
- Keep filenames and titles parallel with related guides so similar cases are easy to compare.
- Make sure each guide still contains a concrete vulnerable pattern, an attack example, a safer pattern, explicit detection guidance, false-positive guidance, and references.
- If you touch GitHub Actions, keep actions pinned, make sure workflow lint/security checks still make sense and follow the exisitng code style and structure.
- Keep existing structure, style and formatting in the repository overall. Avoid introducing new styles or conventions unless they are clearly documented and reported.

### Writing guides

- For new guide pages under `guides/` (excluding `README.md` index files), keep the required heading structure from `.markdownlint-cli2.jsonc`.
- For new guide pages under `guides/` (excluding `README.md` index files), start with YAML frontmatter containing a stable `id`, `kind`, `severity`, `exploitability`, standards mappings, detection metadata, and `tags`. Keep the frontmatter consistent with existing guides. Look at `catalog/rules.json` for the expected structure.
- For links in guides, use only domains that are allowlisted for `guide-references` or `example-urls` in `catalog/allowed-reference-domains.json`.
- When you add a new guide or move an exisitng one, update the nearest category `README.md` to include a link to the new guide.
- When you add a new category, update the main `README.md` to include a link to the new category.
- When you add or materially change a guide, update `catalog/rules.json`.
- When you add a new external reference domain for guides, update `catalog/allowed-reference-domains.json` and verify the exact URLs you introduced.
- When adding code examples ensure they are complete, self-contained, and clearly demonstrate the vulnerability or safer pattern. Use comments to explain key points in the code. Make code self-explanatory and avoid unnecessary complexity. Keep in mind that humans should be able to understand the code without needing to run it, and agents should be able to parse it easily.
- When writing attack examples, ensure they are realistic and demonstrate how an attacker could exploit the vulnerability. Avoid using overly complex or contrived examples that may confuse readers. Use comments to explain the attack steps and the impact of the vulnerability.
- Never invent vulnerabilities or safer patterns. Only document real-world examples that have been observed in practice. If you are unsure about the validity of a vulnerability or safer pattern, consult with other security experts or refer to reputable sources, and include those sources in the guide's `References` section.
- In general , keep the guides concise and focused on the specific vulnerability or safer pattern being discussed. Avoid including unrelated information or tangential topics. Don't be too wordy.
- Ensure you use modern language features and specifications when writing code examples. For example, use ES6+ features in JavaScript, and avoid deprecated or outdated syntax.
- Try to keep guide in one markdown file if possible. If the guide is too long or complex, consider splitting it into multiple files within a directory, but ensure that the structure is clear and consistent with the rest of the repository.
- Remember the repo's review philosophy: scanners should find candidates, while agents confirm whether the candidate is a real vulnerability, weakness, or hardening gap. Use `False Positives` sections to keep the KB from turning into security noise.
- When working with YAML frontmatter ensure that the syntax is correct and all required fields are present. Don't invent new fields or change the expected structure without a clear reason. Use existing guides and `catalog/rules.json` as a reference for the correct format.
- Quote YAML frontmatter string values whenever they contain `:`, `#`, leading special characters, or other parser-sensitive content. In particular, quote values like `javascript:` so they remain valid for strict YAML parsers.
