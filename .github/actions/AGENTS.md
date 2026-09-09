# Composite Actions Guidelines

## Scope

This directory contains reusable composite actions that encapsulate common workflow patterns. Composite actions are intended to simplify workflows, reduce duplication, and promote consistency across the repository.

## Composite Action Coding Rules

- When you encounter a repeated workflow pattern, consider creating a composite action in `.github/actions/` to encapsulate it and keep the code DRY.
- Extract an action when logic is reused or conceptually independent, not merely because YAML is long.
- Composite actions must document any required caller-provided tools, files, environment variables, or repository state.
- Do not rely on undocumented caller state.
- Use `$GITHUB_ACTION_PATH` when referencing files owned by the composite action. Do not assume the caller's working directory.
- Follow the principle: one composite action = one clear responsibility.
- Prefer names like `.github/actions/python-scripts-check/action.yml`.
- Always provide name and concise description.
- Keep inputs minimal and don't add inputs that are not vitally necessary.
- Use kebab-case input/output names.
- Treat all action inputs as untrusted strings.
- Avoid hidden behavior controlled by undocumented environment variables.
- Define outputs only when callers actually need them.
- Give steps meaningful names.
- Always specify shell: bash for run: steps.
- Never eval input.
- Never execute input as a command.
- Permissions belong in the workflow, not the composite action.
- Never make a validation action mutate the repository.
- Produce concise diagnostic output which is readable for humans and parsable by machines.

## Required Checks

```bash
yamllint .github
zizmor .github
actionlint
shellcheck .github/scripts/*.sh
```
