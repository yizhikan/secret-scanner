# src/secret_scanner/scanner.py
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
from .detector import Detector, Finding
from .redactor import Redactor
from .reporter import Reporter
from .storage import SecretStorage


@dataclass
class ScanResult:
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    secrets_extracted: int = 0
    redacted_files: int = 0


class Scanner:
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        # Pass config to Detector for custom rules if provided
        self.detector = Detector(rules=self.config.get("rules"))
        self.redactor = Redactor()
        self.reporter = Reporter()
        self.storage = SecretStorage()

    def scan_local(
        self,
        dir_path: str,
        redact: bool = False,
        output_dir: Optional[str] = None
    ) -> ScanResult:
        """Scan local directory for secrets."""
        result = ScanResult()

        # Scan for findings
        result.findings = self.detector.scan_directory(dir_path)
        result.files_scanned = sum(1 for p in Path(dir_path).rglob("*") if p.is_file())
        result.secrets_extracted = len(result.findings)

        if redact and output_dir:
            # Redact files and collect secrets
            files_redacted = set()
            all_secrets = []
            for finding in result.findings:
                if finding.file_path not in files_redacted:
                    secrets = self.redactor.redact_file(finding.file_path)
                    files_redacted.add(finding.file_path)
                    all_secrets.extend(secrets)

            # Save secrets if any were found
            if all_secrets:
                secret_path = Path(output_dir) / ".env.secret"
                self.storage.save_secrets(all_secrets, str(secret_path))
                self.storage.ensure_gitignore_entry(
                    str(Path(output_dir) / ".gitignore")
                )

        # Generate report
        if output_dir:
            report_path = Path(output_dir) / "secret_report.md"
            self.reporter.generate_report(result.findings, str(report_path))

        return result
