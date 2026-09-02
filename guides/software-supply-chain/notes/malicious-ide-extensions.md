# Malicious IDE Extensions

## Summary

Malicious IDE extension attacks abuse the trust developers place in editor plugins.
An extension can run code in the development environment when the editor starts, a workspace opens, a command runs, or a relevant file type is detected.

This is a software supply chain concern rather than a catalog rule because the initial foothold is usually an extension marketplace, a publisher compromise, or developer social engineering, not a reusable application-side pattern that a scanner can confirm.

## Mental Model

```text
third-party extension
        +
developer source, tools, and credentials
        ↓
extension host or language-server process
        ↓
local code execution as the developer
        ↓
source-code theft, credential theft, or downstream compromise
```

Treat an IDE extension as third-party local software, not as a harmless editor preference.
An extension or its language server may read workspace files, access environment variables, start child processes, make network requests, and interact with Git or build tools.

## Why This Matters

The IDE sits near several high-value trust boundaries: source code, package managers, cloud tooling, Git credentials, SSH material, local development servers, and deployment workflows.
An extension compromise can therefore move from one developer workstation to a repository, CI/CD system, production environment, and ultimately customers.

Extension updates make this risk especially sharp.
A trusted publisher or dependency can be compromised after the extension is installed, and automatic updates can distribute the malicious release before developers have a chance to review it.

## Vulnerable Pattern

Risky practices include:

- installing extensions based on a recommendation, name similarity, or copied branding without verifying the publisher;
- allowing any extension update to reach every developer immediately;
- trusting an extension solely because it has many installs or a familiar name;
- exposing broad cloud, package-registry, or source-control credentials to the IDE environment;
- opening untrusted repositories on a host that contains sensitive credentials.

Repository recommendations create a social-engineering path even though they do not normally install an extension silently:

```json
{
  "recommendations": ["attacker.fake-extension"]
}
```

## Example Attack

An attacker compromises a popular extension publisher and releases a new version.
The extension activates when a developer opens a TypeScript file, collects repository and environment details, then uploads selected files and tokens to an attacker-controlled service.

```text
trusted extension v1.4.1
        ↓
publisher or build pipeline compromised
        ↓
malicious v1.4.2 published
        ↓
automatic extension update
        ↓
workspace opens and extension activates
```

The attacker may instead publish a typosquatted extension, take over an abandoned extension, or compromise an npm dependency used by a legitimate extension.

## Why The Attack Works

1. Extensions are installed code, often with access to the workspace and local development tools.
2. Activation can happen during normal editor use, which makes malicious activity blend into routine development.
3. Language servers and bundled helper binaries introduce additional executable components beyond the visible extension UI.
4. Developers tend to trust marketplace reputation and repository recommendations, even though publishers, build systems, and updates can be compromised.
5. A developer environment often has credentials and write access that can turn a workstation compromise into a broader supply chain compromise.

## Safer Pattern

Keep the extension set small and explicitly approved.
Prefer verified or official publishers, but still review high-risk extensions and their release process because publisher reputation alone is not a security boundary.

Use isolated development environments for unfamiliar repositories and keep secrets out of the general IDE process whenever possible.
Use short-lived, scoped credentials and require branch protection, review, and controlled release processes so that one compromised workstation cannot directly ship a production backdoor.

For sensitive projects, pin approved remote-container extensions to an exact VSIX artifact and verify its checksum before installing it.

## Detection

Review installed extensions, extension recommendations, and publisher ownership regularly.
Prioritize unknown publishers, sudden ownership changes, unrelated functionality, typosquatted names, and extensions that access secrets, Git, cloud tools, containers, wallets, or source-code indexing.

During incident response, inspect the extension host and language-server processes for unexpected child processes, network connections, command execution, or large outbound uploads.
High-signal APIs and behaviors include `child_process`, `exec`, `spawn`, `process.env`, filesystem access, unexpected HTTP requests, and runtime-downloaded binaries.

Review the lockfile and checksum whenever a pinned extension is updated.
An unexpected extension in a development container should be treated as a configuration drift signal rather than automatically trusted.

## False Positives

- Many legitimate extensions read workspace files, start language servers, or make network requests as part of their documented functionality.
- A recommendation in `.vscode/extensions.json` is not itself code execution and normally requires developer approval before installation.
- Automatic updates are valuable for receiving security fixes quickly; disabling them shifts responsibility to a deliberate update and rollout process.

## References

- [VS Code: Development Containers](https://code.visualstudio.com/docs/devcontainers/containers)
- [OWASP Top 10 2025 A03: Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)

## Quick Checklist

- Treat IDE extensions and language servers as executable third-party software.
- Install only extensions that are necessary and approved for the repository's risk level.
- Verify publishers and review updates to high-risk extensions before broad rollout.
- Pin and checksum-verify container extension artifacts when reproducibility matters.
- Disable automatic updates only with an intentional process to review and ship security updates.
- Keep broad or long-lived credentials out of the IDE environment and isolate unfamiliar repositories.
