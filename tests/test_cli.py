import argparse
import io
import unittest
from contextlib import redirect_stderr

from logveil.cli import process


def args(**overrides):
    values = {
        "replacement": "[REDACTED]",
        "key": [],
        "keep_emails": False,
        "jsonl": False,
        "strict_jsonl": False,
        "report": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class CliTests(unittest.TestCase):
    def test_processes_stream_without_loading_it_all(self):
        output = io.StringIO()
        status = process(io.StringIO("a@example.com\nplain\n"), output, args())
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), "[REDACTED]\nplain\n")

    def test_jsonl_falls_back_to_text_by_default(self):
        output = io.StringIO()
        status = process(io.StringIO('{"token":"x"}\nemail=a@example.com\n'), output, args(jsonl=True))
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), '{"token":"[REDACTED]"}\nemail=[REDACTED]\n')

    def test_strict_jsonl_returns_error(self):
        output = io.StringIO()
        with redirect_stderr(io.StringIO()):
            status = process(io.StringIO("not json\n"), output, args(jsonl=True, strict_jsonl=True))
        self.assertEqual(status, 2)

    def test_report_does_not_pollute_output(self):
        output = io.StringIO()
        report = io.StringIO()
        with redirect_stderr(report):
            status = process(io.StringIO("a@example.com\n"), output, args(report=True))
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), "[REDACTED]\n")
        self.assertIn("1 replacement", report.getvalue())
