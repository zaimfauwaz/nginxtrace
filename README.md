# nginxtrace

Note: Project is still in active development.

nginxtrace is a CLI-only, offline tool for inspecting NGINX configuration files. It validates supported static configuration syntax and reports common security and reliability risks through explainable, source-located findings.

The tool is intended for DevOps engineers and developers who want a fast local review step before deployment, during CI, or when inspecting the effective configuration produced by `nginx -T`.

## Features

- Parse supported NGINX directives and nested blocks.
- Validate static configuration structure.
- Follow static `include` directives and filename globs.
- Detect include cycles, unsafe include paths, and malformed included files.
- Parse captured `nginx -T` output without reading the server filesystem.
- Report findings with rule IDs, severity, confidence, file, line, evidence, and remediation.
- Output findings as readable text or JSON.
- Filter findings by severity.
- Configure rule severity, disable rules, and suppress reviewed findings with TOML policy files.
- List built-in rules and inspect rule metadata from the CLI.

## Requirements

- Python 3.12 or later.
- [uv](https://docs.astral.sh/uv/) for the recommended development workflow.

## Installation

Clone the repository and create the project environment:

```bash
git clone [https://github.com/zaimfauwaz/nginxtrace.git](https://github.com/zaimfauwaz/nginxtrace.git)
cd nginxtrace
uv sync
```

Run the CLI through uv:

```bash
uv run nginxtrace --help
```

For an editable installation without uv:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --editable .
nginxtrace --help
```

## Usage

### Check configuration syntax

Check a configuration file and follow its static includes:

```bash
uv run nginxtrace check --config nginx.conf
```

Check a captured effective configuration dump:

```bash
uv run nginxtrace check --dump nginx-T.txt
```

Do not resolve include directives:

```bash
uv run nginxtrace check --config nginx.conf --no-includes
```

### Scan for configuration issues

Scan a configuration file:

```bash
uv run nginxtrace scan --config nginx.conf
```

Scan with JSON output:

```bash
uv run nginxtrace scan --config nginx.conf --format json
```

Report only findings at or above a severity:

```bash
uv run nginxtrace scan --config nginx.conf --min-severity high
```

Scan a captured `nginx -T` dump:

```bash
uv run nginxtrace scan --dump nginx-T.txt
```

### Inspect rules

List all built-in rules:

```bash
uv run nginxtrace rules list
```

Show a specific rule:

```bash
uv run nginxtrace rules show NGX-SECRET-001
```

## Configuration input

nginxtrace accepts one input source per command:

```text
--config PATH    Read an NGINX configuration file from disk.
--dump PATH      Read a file containing captured nginx -T output.
```

For `--config`, nginxtrace follows static `include` directives by default. Use `--no-includes` to inspect only the supplied file.

For `--dump`, nginxtrace reads included files only from the dump content. It does not read the original server paths from the local filesystem.

Create a dump from the NGINX server:

```bash
nginx -T > nginx-T.txt 2>&1
```

Then inspect it locally or in CI:

```bash
uv run nginxtrace check --dump nginx-T.txt
uv run nginxtrace scan --dump nginx-T.txt
```

## Exit codes

| Exit code | Meaning |
|---:|---|
| `0` | The command completed successfully and produced no scan findings. |
| `1` | A scan completed and reported one or more findings. |
| `2` | Invalid command arguments, unreadable input, invalid policy, or configuration parsing/loading error. |

For `check`, exit code `0` means nginxtrace successfully parsed the supplied configuration under its supported static syntax model.

## Policy files

Use a TOML policy file to set a default severity threshold, disable rules, override severities, or suppress reviewed findings.

```toml
min_severity = "medium"

disable = [
  "NGX-REFERER-001",
]

[severity]
NGX-HOST-001 = "high"

[[suppress]]
rule = "NGX-ALIAS-001"
file = "conf.d/legacy.conf"
line = 12
reason = "Reviewed legacy routing behavior."
```

Run a scan with the policy:

```bash
uv run nginxtrace scan --config nginx.conf --policy nginxtrace-policy.toml
```

The command-line `--min-severity` option overrides the policy file’s `min_severity` value.

## Syntax checking

`nginxtrace check` validates the static NGINX configuration syntax that nginxtrace supports:

- Tokenization, comments, quoted values, and supported escapes.
- Directive separators and nested block structure.
- Static `include` directives and supported filename globs.
- Include cycles, include depth, and included-file count limits.
- Captured `nginx -T` configuration sections.

When an included file is malformed, nginxtrace reports the original included file path and the relevant parser error.

nginxtrace is not a replacement for NGINX itself. It does not validate:

- NGINX version-specific directives or installed modules.
- Directive context requirements enforced by NGINX.
- Runtime variable values or dynamic include paths.
- Filesystem permissions, upstream reachability, or DNS.
- TLS certificates, key material, or third-party module syntax.
- Whether a reported static pattern is exploitable in a deployed environment.

Validate configuration with the target NGINX installation before deployment:

```bash
nginx -t
nginx -T
```

## Safety model

nginxtrace is designed for offline inspection:

- It does not start NGINX.
- It does not make network requests.
- It does not modify configuration files.
- It does not execute configuration directives.
- It restricts file-based input and static includes to the allowed base directory.

By default, the allowed base directory is the current working directory. Set `NGINXTRACE_BASE_DIR` when a controlled input root is needed:

```bash
export NGINXTRACE_BASE_DIR=/path/to/configuration-root
uv run nginxtrace scan --config nginx.conf
```

Do not commit production secrets, TLS private keys, customer data, or unsanitized live configuration files as project fixtures.

## Development

Run the full test suite:

```bash
uv run pytest -q
```

Run the configured linter:

```bash
uv run ruff check .
```

Run the CLI during development:

```bash
uv run nginxtrace --help
```
