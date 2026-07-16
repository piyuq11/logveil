import io
import unittest

from logveil.redactor import Redactor
from logveil.cli import process


def args(**overrides):
    # Mirror CLI defaults used by process()
    values = {
        "path": None,
        "output": None,
        "jsonl": False,
        "strict_jsonl": False,
        "keep_emails": False,
        "key": [],
        "replacement": "[REDACTED]",
        "report": False,
        "redact_ipv4": False,
    }
    values.update(overrides)
    # Simple namespace for process()
    class NS:
        pass
    ns = NS()
    for k, v in values.items():
        setattr(ns, k, v)
    return ns


class IPv4RedactionTests(unittest.TestCase):
    def test_redacts_valid_ipv4(self):
        source = "client 192.168.0.1 connected"
        result = Redactor(redact_ipv4=True).redact_text(source)
        self.assertEqual(result.value, "client [REDACTED] connected")
        self.assertEqual(result.replacements, 1)

    def test_does_not_redact_by_default(self):
        result = Redactor().redact_text("192.168.0.1")
        self.assertEqual(result.value, "192.168.0.1")
        self.assertEqual(result.replacements, 0)

    def test_does_not_redact_invalid_octet(self):
        source = "client 256.0.0.1 connected"
        result = Redactor(redact_ipv4=True).redact_text(source)
        self.assertEqual(result.value, source)
        self.assertEqual(result.replacements, 0)

    def test_redacts_ipv4_with_port(self):
        source = "127.0.0.1:8080"
        result = Redactor(redact_ipv4=True).redact_text(source)
        self.assertEqual(result.value, "[REDACTED]:8080")
        self.assertEqual(result.replacements, 1)

    def test_jsonl_redacts_ipv4_string(self):
        line = '{"ip":"10.0.0.1","port":80}'
        result = Redactor(redact_ipv4=True).redact_json_line(line)
        self.assertEqual(result.value, '{"ip":"[REDACTED]","port":80}')
        self.assertEqual(result.replacements, 1)

    def test_cli_flag_enables_ipv4(self):
        output = io.StringIO()
        status = process(io.StringIO("192.168.1.5\n"), output, args(redact_ipv4=True))
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), "[REDACTED]\n")
