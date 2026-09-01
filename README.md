# Web of Flaws

- [Web of Flaws](#web-of-flaws)
  - [Overview](#overview)
  - [Repository Shape](#repository-shape)
  - [Contributing](#contributing)
  - [License](#license)

[![Lint](https://github.com/ukorvl/web-of-flaws/actions/workflows/lint.yml/badge.svg)](https://github.com/ukorvl/web-of-flaws/actions/workflows/lint.yml?query=branch%3Amain) [![Coverage Status](https://coveralls.io/repos/github/ukorvl/web-of-flaws/badge.svg?branch=main)](https://coveralls.io/github/ukorvl/web-of-flaws?branch=main) [![Markdown style: markdownlint-cli2](https://img.shields.io/badge/Markdown%20style-markdownlint--cli2-000000)](https://github.com/DavidAnson/markdownlint-cli2) [![Python style: Ruff](https://img.shields.io/badge/Python%20style-Ruff-D7FF64)](https://github.com/astral-sh/ruff) [![prek](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/j178/prek/v0.4.13/docs/assets/badge-v0.json)](https://github.com/j178/prek) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

Web of Flaws is a markdown-first catalog of vulnerable web patterns and safer replacements.
The repository is designed for both humans and coding agents: each guide shows the risky pattern,
why it is exploitable, and how to fix it with concrete code.

It can be used as a knowledge base for SAST, model training, and agent-assisted security review. At the same time the library could be useful for developers and security engineers to learn about common web vulnerabilities and how to mitigate them.

## Repository Shape

Categories are grouped by security topic and vulnerability family.

- [Cross-origin Communication](guides/cross-origin-communication/README.md)
- [Injection](guides/injection/README.md)
- [Object Integrity](guides/object-integrity/README.md)
- [Request Authenticity](guides/request-authenticity/README.md)
- [Software Supply Chain](guides/software-supply-chain/README.md)
- [Sensitive Data Exposure](guides/sensitive-data-exposure/README.md)

The repository is designed to be agent-friendly. Each guide is structured in a consistent way, with clear sections for the risky pattern, safer replacement, and detection metadata.

- Machine-readable rule catalog: [catalog/rules.json](catalog/rules.json)
- Rule guides carry stable IDs, standards mappings, detection metadata, kind, tags, severity and other metadata. This data is stored in YAML frontmatter at the top of each guide to help agents work with the rules programmatically.

## Contributing

We appreciate contributions from the community! If you have a new guide to add, or an improvement to an existing one, please follow the [contribution guidelines](CONTRIBUTING.md) to submit your changes.

## License

This repository is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
