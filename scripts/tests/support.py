from __future__ import annotations

import sys
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from importlib import import_module
from io import StringIO
from pathlib import Path
from textwrap import dedent
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parents[1]
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))


def load_module(name: str):
    return import_module(name)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(dedent(content).lstrip(), encoding="utf-8")


def build_valid_repo(root: Path) -> None:
    write(
        root / "catalog/allowed-reference-domains.json",
        """
        {
          "schema_version": 1,
          "domains": [
            {
              "domain": "cwe.mitre.org",
              "scopes": ["guide-references"],
              "purpose": "CWE references"
            },
            {
              "domain": "owasp.org",
              "scopes": ["guide-references"],
              "purpose": "OWASP references"
            },
            {
              "domain": "example.com",
              "scopes": ["example-urls"],
              "purpose": "Example URLs"
            }
          ]
        }
        """,
    )
    write(
        root / "guides/injection/README.md",
        """
        # Injection

        ## Categories

        - [Cross-site scripting (XSS)](xss/README.md)
        """,
    )
    write(
        root / "guides/injection/xss/README.md",
        """
        # Cross-site scripting (XSS)

        ## Rules

        - [URL-derived input to HTML sink (`innerHTML`)](url-derived-input-to-html-sink-innerhtml.md)
        """,
    )
    write(
        root / "guides/injection/xss/url-derived-input-to-html-sink-innerhtml.md",
        """
        ---
        id: WOF-XSS-001
        title: URL-derived Input to HTML Sink (innerHTML)
        kind: vulnerability
        default_severity: high
        exploitability: high
        standards:
          cwe:
            - CWE-79
          owasp_top_10:
            - "A05:2025 Injection"
        platforms:
          - browser
        languages:
          - html
          - javascript
        detection:
          type: dataflow
          methods:
            - grep
            - ast
          candidate_tokens:
            - innerHTML
            - URLSearchParams
        sources:
          - window.location.search
        sinks:
          - Element.innerHTML
        tags:
          - xss
          - dom-xss
        ---

        ## Rule

        Example body.

        ## Example Attack

        ```text
        https://attacker.test/payload
        ```

        ## References

        - [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
        - [OWASP Top 10 2025 A05: Injection](https://owasp.org/Top10/2025/A05_2025-Injection/)

        ## Quick Checklist
        """,
    )
    write(
        root / "guides/sensitive-data-exposure/README.md",
        """
        # Sensitive Data Exposure

        ## Rules

        - [Hard-coded secrets](hard-coded-secrets.md)
        """,
    )
    write(
        root / "guides/sensitive-data-exposure/hard-coded-secrets.md",
        """
        ---
        id: WOF-SDE-001
        title: Hard-coded Secrets
        kind: vulnerability
        default_severity: high
        exploitability: medium
        standards:
          cwe:
            - CWE-798
          owasp_top_10:
            - "A07:2025 Authentication Failures"
        platforms:
          - server
        languages:
          - javascript
        detection:
          type: semantic-pattern
          methods:
            - grep
            - semantic-review
          candidate_tokens:
            - SECRET
            - BEGIN PRIVATE KEY
        indicators:
          - variables or config keys named SECRET
        tags:
          - secrets
          - source-code
        ---

        ## Rule

        Example body.

        ## References

        - [CWE-798](https://cwe.mitre.org/data/definitions/798.html)
        - [OWASP Top 10 2025 A07: Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/)

        ## Quick Checklist
        """,
    )


@contextmanager
def patched_root(root: Path, *modules):
    patches = [mock.patch.object(module, "ROOT", root) for module in modules]
    with TemporaryStack(patches):
        yield


class TemporaryStack:
    def __init__(self, patches):
        self._patches = patches
        self._started = []

    def __enter__(self):
        for patcher in self._patches:
            self._started.append(patcher.start())
        return self

    def __exit__(self, exc_type, exc, tb):
        while self._patches:
            self._patches.pop().stop()


def run_main(module, root: Path, *args: str) -> tuple[int, str, str]:
    stdout = StringIO()
    stderr = StringIO()
    argv = [f"{module.__name__}.py", *args]
    with (
        patched_root(root, module),
        mock.patch.object(module.sys, "argv", argv),
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        code = module.main()
    return code, stdout.getvalue(), stderr.getvalue()
