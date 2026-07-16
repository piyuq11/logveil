# logveil

`logveil` removes common credentials and personal data from logs before they are pasted into issues, chats, or support tickets. It runs locally, reads streams line by line, and has no runtime dependencies.

It is designed for developers, support teams, maintainers, and anyone who needs to share diagnostic output without exposing credentials or personal information.

## What it redacts

- Bearer tokens, GitHub tokens, OpenAI-style keys, and AWS access key IDs
- Private-key headers
- Password, token, API-key, and secret assignments
- Email addresses (optional)
- Sensitive values in nested JSON and JSONL objects
- Additional JSON keys supplied by the user

## Install

```bash
python -m pip install logveil
```

For local development:

```bash
python -m pip install -e .
```

## Usage

Pipe a command through `logveil`:

```bash
my-command 2>&1 | logveil --report > safe.log
```

Sanitize a file:

```bash
logveil server.log -o server.safe.log
```

Preserve JSONL structure and redact a project-specific field:

```bash
logveil events.jsonl --jsonl --key session_id -o events.safe.jsonl
```

By default, malformed lines in JSONL input are treated as plain text so mixed log streams remain usable. Add `--strict-jsonl` to stop at the first malformed line.

Show a replacement count without mixing it into the sanitized output:

```bash
logveil server.log --report > server.safe.log
```

Keep email addresses when they are required for diagnosis:

```bash
logveil server.log --keep-emails
```

## Design principles

- Local only: no network requests and no telemetry
- Stream friendly: memory use does not grow with the input file
- Conservative: targeted rules avoid rewriting ordinary identifiers
- Composable: works with pipes, redirected output, and JSONL tooling

## Limits

Automated redaction reduces accidental disclosure but cannot recognize every secret format. Review sanitized output before publishing it. `logveil` deliberately avoids attempting to decode, validate, or transmit detected values. It is not a replacement for secret rotation after an exposure.

## Contributing

Bug reports and small, focused pull requests are welcome. New detection rules should include tests with synthetic values and avoid matching ordinary identifiers.

Run the test suite with:

```bash
python -m unittest discover -s tests
```

## License

MIT
