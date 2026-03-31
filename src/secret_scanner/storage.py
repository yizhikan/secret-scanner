# src/secret_scanner/storage.py
from datetime import datetime
from typing import List, Dict
from pathlib import Path


class SecretStorage:
    def __init__(self):
        self.generated_at = datetime.now().isoformat()

    def save_secrets(
        self,
        secrets: List[Dict],
        output_path: str
    ) -> str:
        """Save extracted secrets to file.

        Args:
            secrets: List of secret dictionaries with keys: file, line, rule_id, original
            output_path: Path to write the secrets file

        Returns:
            The output path where secrets were written

        Raises:
            ValueError: If secrets list is empty or contains invalid entries
        """
        if not secrets:
            raise ValueError("Secrets list cannot be empty")

        required_keys = {"file", "line", "rule_id", "original"}
        for i, secret in enumerate(secrets):
            missing_keys = required_keys - set(secret.keys())
            if missing_keys:
                raise ValueError(
                    f"Secret at index {i} is missing required keys: {missing_keys}"
                )

        lines = [
            "# Secret Scanner - Extracted Secrets",
            f"# Generated: {self.generated_at}",
            "# WARNING: Keep this file secure and never commit to version control!",
            "",
        ]

        for i, secret in enumerate(secrets, 1):
            lines.extend([
                f"# Secret {i}",
                f"# Location: {secret['file']}:{secret['line']}",
                f"# Rule: {secret['rule_id']}",
                f"{secret['rule_id']}={secret['original']}",
                "",
            ])

        content = "\n".join(lines)
        with open(output_path, "w") as f:
            f.write(content)

        return output_path

    def ensure_gitignore_entry(self, gitignore_path: str) -> None:
        """Ensure .env.secret is in .gitignore."""
        entry = ".env.secret"

        if Path(gitignore_path).exists():
            with open(gitignore_path, "r") as f:
                content = f.read()
            if entry not in content:
                with open(gitignore_path, "a") as f:
                    f.write(f"\n# Secret Scanner\n{entry}\n")
        else:
            with open(gitignore_path, "w") as f:
                f.write(f"# Secret Scanner\n{entry}\n")
