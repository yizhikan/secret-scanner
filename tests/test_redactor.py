# tests/test_redactor.py
import pytest
from secret_scanner.redactor import Redactor


class TestRedactor:
    def test_redact_content(self):
        content = "API_KEY = 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"
        redactor = Redactor()
        result, secrets = redactor.redact_content(content, "test.py")

        # The generic_api_key rule matches the whole assignment
        assert "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in result
        assert "<REDACTED:" in result
        assert len(secrets) == 1
        assert secrets[0]["original"] == "API_KEY = 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"

    def test_redact_multiple_secrets(self):
        content = """
        AWS_KEY = AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        """
        redactor = Redactor()
        result, secrets = redactor.redact_content(content, "test.py")

        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in result
        assert len(secrets) == 2
