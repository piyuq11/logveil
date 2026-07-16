import json
import unittest

from logveil import Redactor


class RedactorTests(unittest.TestCase):
    def test_redacts_common_secrets_and_email(self):
        source = "user=a@example.com Authorization: Bearer abcdefghijklmnop sk-abcdefghijklmnop"
        result = Redactor().redact_text(source)
        self.assertEqual(result.value, "user=[REDACTED] Authorization: [REDACTED] [REDACTED]")
        self.assertEqual(result.replacements, 3)

    def test_keeps_assignment_name(self):
        result = Redactor().redact_text("password=hunter2 token: abcdefghijkl")
        self.assertEqual(result.value, "password=[REDACTED] token: [REDACTED]")

    def test_redacts_nested_json_without_changing_types(self):
        source = {"token": "abc", "event": {"email": "a@example.com", "ok": True}}
        result, count = Redactor().redact_json(source)
        self.assertEqual(result, {"token": "[REDACTED]", "event": {"email": "[REDACTED]", "ok": True}})
        self.assertEqual(count, 2)

    def test_json_line_is_compact_and_valid(self):
        result = Redactor().redact_json_line('{"password":"x","items":[1,"a@example.com"]}')
        self.assertEqual(json.loads(result.value), {"password": "[REDACTED]", "items": [1, "[REDACTED]"]})
        self.assertEqual(result.replacements, 2)

    def test_custom_key_and_email_opt_out(self):
        redactor = Redactor(sensitive_keys=["session_id"], redact_emails=False)
        result, count = redactor.redact_json({"session_id": "123", "email": "a@example.com"})
        self.assertEqual(result, {"session_id": "[REDACTED]", "email": "a@example.com"})
        self.assertEqual(count, 1)

    def test_sensitive_json_keys_are_case_insensitive(self):
        result, count = Redactor().redact_json({"Authorization": "value", "CLIENT_SECRET": "value"})
        self.assertEqual(result, {"Authorization": "[REDACTED]", "CLIENT_SECRET": "[REDACTED]"})
        self.assertEqual(count, 2)

    def test_redacts_private_key_header(self):
        result = Redactor().redact_text("-----BEGIN PRIVATE KEY-----")
        self.assertEqual(result.value, "[REDACTED]")

    def test_does_not_redact_ordinary_identifiers(self):
        source = "request_id=abc123 status=ok user=alice"
        result = Redactor().redact_text(source)
        self.assertEqual(result.value, source)
        self.assertEqual(result.replacements, 0)

    def test_redacts_ipv4_addresses_only_when_enabled(self):
        source = "client=192.168.1.10 upstream=255.255.255.255:443"
        unchanged = Redactor().redact_text(source)
        self.assertEqual(unchanged.value, source)
        self.assertEqual(unchanged.replacements, 0)

        result = Redactor(redact_ipv4=True).redact_text(source)
        self.assertEqual(
            result.value,
            "client=[REDACTED] upstream=[REDACTED]:443",
        )
        self.assertEqual(result.replacements, 2)

    def test_uses_custom_replacement_for_ipv4(self):
        result = Redactor(replacement="<IP>", redact_ipv4=True).redact_text(
            "client=10.0.0.1"
        )
        self.assertEqual(result.value, "client=<IP>")
        self.assertEqual(result.replacements, 1)

    def test_rejects_invalid_or_partial_ipv4_candidates(self):
        source = (
            "valid=0.0.0.0 invalid_octet=256.1.2.3 "
            "missing_octet=1.2.3 leading_zero=01.2.3.4 "
            "long_form=1.2.3.4.5 embedded=v1.2.3.4 sentence=10.0.0.2."
        )
        result = Redactor(redact_ipv4=True).redact_text(source)
        self.assertEqual(
            result.value,
            "valid=[REDACTED] invalid_octet=256.1.2.3 "
            "missing_octet=1.2.3 leading_zero=01.2.3.4 "
            "long_form=1.2.3.4.5 embedded=v1.2.3.4 sentence=[REDACTED].",
        )
        self.assertEqual(result.replacements, 2)

    def test_redacts_ipv4_inside_json_strings(self):
        source = '{"client_ip":"10.0.0.1","message":"connected to 192.0.2.5:8443"}'
        result = Redactor(redact_ipv4=True).redact_json_line(source)
        self.assertEqual(
            json.loads(result.value),
            {
                "client_ip": "[REDACTED]",
                "message": "connected to [REDACTED]:8443",
            },
        )
        self.assertEqual(result.replacements, 2)
