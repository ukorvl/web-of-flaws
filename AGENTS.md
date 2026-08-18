# Agents guide for Web of Flaws

## Overview

This project is a catalog of vulnerable web patterns and safer replacements, designed for both humans and coding agents. Each guide shows the risky pattern, why it is exploitable, and how to fix it with concrete code. The core idea is to provide a structured and machine-readable format that allows agents to parse the guides and extract relevant information.

The repository is organized into categories based on security topics and vulnerability families. Each category contains guides that follow a consistent structure. Each category has a `README.md` file that provides an overview of the category and links to the individual guides.

A purpose of this repository is to enable coding agents to learn from the guides and apply the knowledge to identify and fix vulnerabilities in web applications. Humans also are supposed to benefit from it by learning about common web vulnerabilities and how to mitigate them. Consider this repository as a knowledge base for both humans and agents to improve web security.

A guide can be either a single markdown file or a directory containing multiple files. Guide markdown files should start with YAML frontmatter that includes standard properties of each guide, followed by the standard heading structure. Dataflow rules should declare explicit `sources` and `sinks`; pattern rules should declare `indicators`. Look at `.markdownlint-cli2.jsonc`, `CONTRIBUTING.md`, `catalog/rules.json`, and `catalog/allowed-reference-domains.json` for the expected guide structure.

## Environment

This is a docs-first repository with no app runtime or build step. `python3` and `markdownlint-cli2` should be present in the environment. If either command is missing, report that directly instead of silently falling back to another toolchain. The main local Markdown tool is `markdownlint-cli2`; run `markdownlint-cli2 "**/*.md"` and use `--fix` when appropriate. Follow `.editorconfig` for whitespace and indentation, and keep in mind that CI checks Markdown style, links, and GitHub Actions security.

## Workspace structure

All guides are located in the `guides` directory. Each category has its own subdirectory, and each guide is either a markdown file or a directory containing multiple files.

## Before marking things as done

- Follow [CONTRIBUTING.md](CONTRIBUTING.md) for the canonical repository rules on guide structure, validation commands, generated files, labels, and contributor workflow.
- If you change guides, generated files, or link allowlists, run the checks required by `CONTRIBUTING.md` before marking the task done and report anything you could not verify.

### Other resources

- [Contributing guide](CONTRIBUTING.md)
- [.markdownlint-cli2.jsonc](.markdownlint-cli2.jsonc)
- [catalog/rules.json](catalog/rules.json)
- [catalog/allowed-reference-domains.json](catalog/allowed-reference-domains.json)
