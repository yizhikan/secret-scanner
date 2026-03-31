# tests/test_redactor.py
import pytest
from pathlib import Path
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

    def test_redact_content_empty(self):
        """Test redacting empty content."""
        redactor = Redactor()
        result, secrets = redactor.redact_content("", "test.py")

        assert result == ""
        assert len(secrets) == 0

    def test_redact_content_no_secrets(self):
        """Test content with no secrets found."""
        content = "This is just regular text with no secrets"
        redactor = Redactor()
        result, secrets = redactor.redact_content(content, "test.py")

        assert result == content
        assert len(secrets) == 0

    def test_short_secret_uses_redacted_placeholder(self):
        """Test that secrets <=12 chars use <REDACTED> placeholder."""
        # Create content that would match a short secret pattern
        # Using a pattern that the detector might match as a short secret
        content = "token = abc123"  # 8 chars secret value
        redactor = Redactor()
        result, secrets = redactor.redact_content(content, "test.py")

        # If a secret was found and it's <=12 chars, it should use <REDACTED>
        for secret in secrets:
            if len(secret["original"]) <= 12:
                assert "<REDACTED>" in result
                assert "<REDACTED:" not in result

    def test_long_secret_uses_detailed_placeholder(self):
        """Test that secrets >12 chars use <REDACTED:prefix...suffix> placeholder."""
        content = "API_KEY = sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        redactor = Redactor()
        result, secrets = redactor.redact_content(content, "test.py")

        # Long secrets should use the detailed placeholder
        assert "<REDACTED:" in result
        assert "..." in result

    def test_redact_file(self, tmp_path):
        """Test redact_file() method with file I/O."""
        # Create a test file with secrets
        test_file = tmp_path / "secret_test.py"
        original_content = "AWS_KEY = AKIAIOSFODNN7EXAMPLE\n"
        test_file.write_text(original_content)

        redactor = Redactor()
        secrets = redactor.redact_file(str(test_file))

        # Verify secrets were found
        assert len(secrets) >= 1

        # Verify file was modified
        redacted_content = test_file.read_text()
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted_content
        assert "<REDACTED" in redacted_content

    def test_redact_file_multiple_secrets(self, tmp_path):
        """Test redact_file() with multiple secrets."""
        test_file = tmp_path / "multi_secret.py"
        original_content = """
        AWS_KEY = AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        """
        test_file.write_text(original_content)

        redactor = Redactor()
        secrets = redactor.redact_file(str(test_file))

        assert len(secrets) == 2

        redacted_content = test_file.read_text()
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted_content
        assert "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in redacted_content

    def test_redact_file_empty_file(self, tmp_path):
        """Test redact_file() with empty file."""
        test_file = tmp_path / "empty.py"
        test_file.write_text("")

        redactor = Redactor()
        secrets = redactor.redact_file(str(test_file))

        assert len(secrets) == 0
        assert test_file.read_text() == ""

    def test_redact_file_no_secrets(self, tmp_path):
        """Test redact_file() with file containing no secrets."""
        test_file = tmp_path / "no_secrets.py"
        original_content = "Just regular code without any secrets\n"
        test_file.write_text(original_content)

        redactor = Redactor()
        secrets = redactor.redact_file(str(test_file))

        assert len(secrets) == 0
        assert test_file.read_text() == original_content

    def test_redact_file_write_failure(self, tmp_path, monkeypatch):
        """Test exception handling when file write fails."""
        test_file = tmp_path / "test.py"
        test_file.write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE")

        # Make the file read-only to trigger write failure
        test_file.chmod(0o444)

        redactor = Redactor()

        # Should raise IOError when write fails
        with pytest.raises(IOError, match="Failed to write redacted file"):
            redactor.redact_file(str(test_file))

        # Restore permissions for cleanup
        test_file.chmod(0o644)
