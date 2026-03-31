# src/secret_scanner/redactor.py
from typing import List, Dict, Tuple
from pathlib import Path
from .detector import Detector, Finding


class Redactor:
    def __init__(self):
        self.detector = Detector()

    def redact_content(
        self,
        content: str,
        file_path: str
    ) -> Tuple[str, List[Dict]]:
        """Replace secrets in content with placeholders."""
        findings = self.detector.scan_content(content, file_path)
        secrets = []

        # Sort by position (reverse order to maintain positions)
        findings.sort(key=lambda f: f.line_number * 1000 + f.column, reverse=True)

        lines = content.split("\n")

        for finding in findings:
            line_idx = finding.line_number - 1
            if line_idx >= len(lines):
                continue

            line = lines[line_idx]
            col_start = finding.column - 1
            col_end = col_start + len(finding.value)

            if col_start < 0 or col_end > len(line):
                continue

            # Create placeholder
            value = finding.value
            if len(value) > 12:
                placeholder = f"<REDACTED:{value[:4]}...{value[-4:]}>"
            else:
                placeholder = "<REDACTED>"

            # Store secret
            secrets.append({
                "file": file_path,
                "line": finding.line_number,
                "rule_id": finding.rule_id,
                "original": value
            })

            # Replace in line
            lines[line_idx] = line[:col_start] + placeholder + line[col_end:]

        return "\n".join(lines), secrets

    def redact_file(self, file_path: str) -> List[Dict]:
        """Redact secrets in file and save."""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        redacted, secrets = self.redact_content(content, file_path)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(redacted)

        return secrets
