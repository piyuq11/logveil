# Changelog

All notable changes are documented here.

## 0.1.1 - 2026-07-16

- Use the available PyPI distribution name `logveil-cli` while keeping the
  `logveil` command and Python package name unchanged.

## 0.1.0 - 2026-07-16

- Redact common credentials, private-key headers, and email addresses from text.
- Preserve nested JSON and JSONL structures while redacting sensitive fields.
- Support custom sensitive keys, strict JSONL validation, and replacement reports.
- Process stdin and files as streams without runtime dependencies.
