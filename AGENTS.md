# Agent Instructions for Web of Flaws

## Purpose

Web of Flaws is a machine-readable catalog of vulnerable web patterns and safer replacements.
Every rule must help a developer or coding agent understand the security boundary, exploitation
conditions, and appropriate remediation.

## Instruction Hierarchy

Read this file first, then read the closest nested `AGENTS.md` for every directory you modify.
The closest instruction file takes precedence for its subtree.

- [`guides/AGENTS.md`](guides/AGENTS.md) defines the guide contract.
- [`catalog/AGENTS.md`](catalog/AGENTS.md) defines catalog data and generated-file rules.
- [`scripts/AGENTS.md`](scripts/AGENTS.md) defines repository tooling and its tests.
- [`.github/AGENTS.md`](.github/AGENTS.md) defines CI, Actions, and workflow-script rules.

`CONTRIBUTING.md` is a concise guide for human contributors, not the source of truth for agent
instructions. Keep durable, machine-actionable rules in the relevant `AGENTS.md`.

## Repository-wide Rules

- This is a documentation-first repository; do not introduce an application runtime or build step
  without an explicit architectural decision.
- Follow `.editorconfig` and preserve existing formatting and naming conventions.
- Do not edit generated files by hand. The closest `AGENTS.md` identifies their generators.
- Run the validations required by every applicable nested instruction file. If a required tool is
  unavailable, report the missing check rather than substituting another tool.
- Keep validation errors actionable: write them to stderr and return a nonzero exit status.
- The primary branch is `main`; target pull requests there.

## Completion

Before finishing, run the relevant focused checks and report the commands that could not run.
For changes spanning repository data or guides, `python3 scripts/check.py` is the central integrity
entry point.
