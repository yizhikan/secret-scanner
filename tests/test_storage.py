# tests/test_storage.py
import pytest
from secret_scanner.storage import SecretStorage


class TestSecretStorage:
    def test_save_secrets(self, tmp_path):
        secrets = [
            {"file": "config.py", "line": 15, "rule_id": "aws_key", "original": "AKIAIOSFODNN7EXAMPLE"},
            {"file": ".env", "line": 3, "rule_id": "github_token", "original": "ghp_xxxx"}
        ]
        storage = SecretStorage()
        output_path = tmp_path / ".env.secret"

        storage.save_secrets(secrets, str(output_path))

        content = output_path.read_text()
        assert "AKIAIOSFODNN7EXAMPLE" in content
        assert "config.py:15" in content

    def test_create_gitignore_entry(self, tmp_path):
        storage = SecretStorage()
        gitignore_path = tmp_path / ".gitignore"

        storage.ensure_gitignore_entry(str(gitignore_path))

        content = gitignore_path.read_text()
        assert ".env.secret" in content
