# Agent Instructions for Web of Flaws

## Purpose

Web of Flaws is a machine-readable catalog of vulnerable web patterns and safer replacements.
Every rule must help a developer or coding agent understand the security boundary, exploitation
conditions, and appropriate remediation.

The goal of the project is to serve both humans and machines. It means, all guides should be written in a way that is understandable by humans, but also structured and formatted in a way that can be parsed and processed by machines.

Technical correctness, clear security reasoning, and machine-readable consistency take priority over brevity or stylistic preference.

## Instruction Hierarchy

Read this file first, then read the closest nested `AGENTS.md` for every directory you modify before you start.
The closest instruction file takes precedence for its subtree and may override or extend the rules in this file.

- Do not duplicate parent rules in nested AGENTS.md files.
- Keep root instructions limited to rules that apply repo-wide.
- If you add a new module consider to add a new AGENTS.md file in that module to define its own rules if it has any specific requirements valuable for code generation.
- If you change repository structure, update the instruction hierarchy accordingly.

## Stack and Environment

- This is a documentation-first repository with Python tooling for validation, generation, and repository maintenance.
- Python code targets the version declared in pyproject.toml.
- Repository dependency and tool versions are defined by their existing configuration and lockfiles; do not introduce alternative package-management or build systems without an explicit architectural reason.
- Use repository-provided scripts and configuration as the source of truth for validation behavior.
- Do not assume tools are installed globally when the repository defines a reproducible way to invoke them.
- Use paths relative to the repository root unless a local instruction explicitly defines another convention.

## Repository-wide Rules

- This is a documentation-first repository; do not introduce an application runtime or build step
  without an explicit architectural decision.
- Follow `.editorconfig` and preserve existing formatting and naming conventions.
- Do not edit generated files by hand.
- Run the validations required by every applicable nested instruction file. If a required tool is
  unavailable, report the missing check rather than substituting another tool.
- Keep validation errors actionable: write them to stderr and return a nonzero exit status.
- The primary branch is `main`; use this name when you need to reference the default repository branch in your code or documentation.
- Prefer existing repository conventions over introducing new abstractions, dependencies, or tooling.
- Make the smallest change that fully solves the requested problem.
- Do not perform unrelated cleanup or refactoring.
- Preserve backward compatibility unless the task explicitly requires a breaking change.

## Security and Correctness

- Treat security content as technical documentation, not opinionated advice.
- Do not overstate vulnerability impact, exploitability, detection confidence, or mitigation guarantees.
- Distinguish candidate detection from confirmed exploitability.
- Prefer primary or authoritative technical sources over secondary summaries when verifying security behavior.
- Do not introduce intentionally insecure behavior outside examples whose purpose is to demonstrate a vulnerability.
- Never add real secrets, credentials, private keys, access tokens, or sensitive production data.
- Treat external inputs and repository-controlled data as untrusted when they cross an execution or trust boundary.

## Completion

Before finishing, run the relevant focused checks and report the commands that could not run.
For changes spanning repository data or guides, `python3 scripts/check.py` is the central integrity
entry point.
Any nested `AGENTS.md` may define additional required checks.

Do not claim that a change is complete, fixed, valid, or passing without fresh verification from the checks relevant to that change.
