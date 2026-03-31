# tests/test_reporter.py
import pytest
from secret_scanner.reporter import Reporter
from secret_scanner.detector import Finding


class TestReporter:
    def test_generate_report(self, tmp_path):
        findings = [
            Finding(
                rule_id="aws_access_key",
                value="AKIAIOSFODNN7EXAMPLE",
                description="AWS Access Key ID",
                severity="high",
                file_path="/repo/config.py",
                line_number=15,
                column=10
            ),
            Finding(
                rule_id="github_token",
                value="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                description="GitHub Token",
                severity="high",
                file_path="/repo/.env",
                line_number=3,
                column=1
            )
        ]
        reporter = Reporter()
        report_path = tmp_path / "report.md"
        reporter.generate_report(findings, str(report_path))

        content = report_path.read_text()
        assert "# Secret Scan Report" in content
        assert "AWS Access Key ID" in content
        assert "config.py:15" in content
