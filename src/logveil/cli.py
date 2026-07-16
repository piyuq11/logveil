from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import TextIO

from .redactor import Redactor
from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logveil",
        description="Redact secrets and personal data from logs locally.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("path", nargs="?", type=Path, help="input file; stdin by default")
    parser.add_argument("-o", "--output", type=Path, help="write output to a file")
    parser.add_argument("--jsonl", action="store_true", help="preserve JSONL structure")
    parser.add_argument("--strict-jsonl", action="store_true", help="fail on invalid JSONL")
    parser.add_argument("--keep-emails", action="store_true", help="do not redact emails")
    parser.add_argument("--redact-ipv4", action="store_true", help="redact IPv4 addresses")
    parser.add_argument(
        "--key",
        action="append",
        default=[],
        metavar="NAME",
        help="additional sensitive JSON key; may be repeated",
    )
    parser.add_argument("--replacement", default="[REDACTED]")
    parser.add_argument("--report", action="store_true", help="print counts to stderr")
    return parser


def process(source: TextIO, destination: TextIO, args: argparse.Namespace) -> int:
    redactor = Redactor(
        replacement=args.replacement,
        sensitive_keys=args.key,
        redact_emails=not args.keep_emails,
        redact_ipv4=args.redact_ipv4,
    )
    total = 0
    invalid = 0
    for number, line in enumerate(source, start=1):
        ending = "\n" if line.endswith("\n") else ""
        content = line[:-1] if ending else line
        if args.jsonl:
            try:
                result = redactor.redact_json_line(content)
            except json.JSONDecodeError as error:
                invalid += 1
                if args.strict_jsonl:
                    print(f"logveil: invalid JSON on line {number}: {error.msg}", file=sys.stderr)
                    return 2
                result = redactor.redact_text(content)
        else:
            result = redactor.redact_text(content)
        destination.write(result.value + ending)
        total += result.replacements
    if args.report:
        noun = "replacement" if total == 1 else "replacements"
        print(f"logveil: {total} {noun}, {invalid} invalid JSON line(s)", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    source: TextIO = sys.stdin
    destination: TextIO = sys.stdout
    try:
        if args.path:
            source = args.path.open(encoding="utf-8")
        if args.output:
            destination = args.output.open("w", encoding="utf-8", newline="")
        return process(source, destination, args)
    except OSError as error:
        print(f"logveil: {error}", file=sys.stderr)
        return 1
    finally:
        if source is not sys.stdin:
            source.close()
        if destination is not sys.stdout:
            destination.close()


if __name__ == "__main__":
    raise SystemExit(main())
