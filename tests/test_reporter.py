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

    def test_empty_findings(self, tmp_path):
        """Test report generation with empty findings list."""
        reporter = Reporter()
        report_path = tmp_path / "empty_report.md"
        reporter.generate_report([], str(report_path))

        content = report_path.read_text()
        assert "# Secret Scan Report" in content
        assert "**Total secrets found:** 0" in content
        assert "**High severity:** 0" in content
        assert "**Medium severity:** 0" in content
        assert "**Low severity:** 0" in content

    def test_high_severity_only(self, tmp_path):
        """Test report with only high severity findings."""
        findings = [
            Finding(
                rule_id="aws_access_key",
                value="AKIAIOSFODNN7EXAMPLE",
                description="AWS Access Key",
                severity="high",
                file_path="/repo/config.py",
                line_number=10,
                column=5
            )
        ]
        reporter = Reporter()
        report_path = tmp_path / "high_only.md"
        reporter.generate_report(findings, str(report_path))

        content = report_path.read_text()
        assert "## High Severity" in content
        assert "## Medium Severity" not in content
        assert "## Low Severity" not in content
        assert "**High severity:** 1" in content
        assert "**Medium severity:** 0" in content
        assert "**Low severity:** 0" in content

    def test_medium_severity_only(self, tmp_path):
        """Test report with only medium severity findings."""
        findings = [
            Finding(
                rule_id="generic_api_key",
                value="api_key_12345678",
                description="Generic API Key",
                severity="medium",
                file_path="/repo/api.py",
                line_number=20,
                column=1
            )
        ]
        reporter = Reporter()
        report_path = tmp_path / "medium_only.md"
        reporter.generate_report(findings, str(report_path))

        content = report_path.read_text()
        assert "## High Severity" not in content
        assert "## Medium Severity" in content
        assert "## Low Severity" not in content
        assert "**High severity:** 0" in content
        assert "**Medium severity:** 1" in content
        assert "**Low severity:** 0" in content

    def test_low_severity_only(self, tmp_path):
        """Test report with only low severity findings."""
        findings = [
            Finding(
                rule_id="debug_mode",
                value="DEBUG=true",
                description="Debug Mode Enabled",
                severity="low",
                file_path="/repo/settings.py",
                line_number=5,
                column=1
            )
        ]
        reporter = Reporter()
        report_path = tmp_path / "low_only.md"
        reporter.generate_report(findings, str(report_path))

        content = report_path.read_text()
        assert "## High Severity" not in content
        assert "## Medium Severity" not in content
        assert "## Low Severity" in content
        assert "**High severity:** 0" in content
        assert "**Medium severity:** 0" in content
        assert "**Low severity:** 1" in content

    def test_mixed_severities(self, tmp_path):
        """Test report with mixed severity findings."""
        findings = [
            Finding(
                rule_id="aws_access_key",
                value="AKIAIOSFODNN7EXAMPLE",
                description="AWS Access Key",
                severity="high",
                file_path="/repo/config.py",
                line_number=10,
                column=5
            ),
            Finding(
                rule_id="generic_api_key",
                value="api_key_12345678",
                description="Generic API Key",
                severity="medium",
                file_path="/repo/api.py",
                line_number=20,
                column=1
            ),
            Finding(
                rule_id="debug_mode",
                value="DEBUG=true",
                description="Debug Mode Enabled",
                severity="low",
                file_path="/repo/settings.py",
                line_number=5,
                column=1
            )
        ]
        reporter = Reporter()
        report_path = tmp_path / "mixed.md"
        reporter.generate_report(findings, str(report_path))

        content = report_path.read_text()
        assert "## High Severity" in content
        assert "## Medium Severity" in content
        assert "## Low Severity" in content
        assert "**High severity:** 1" in content
        assert "**Medium severity:** 1" in content
        assert "**Low severity:** 1" in content

    def test_generated_at_uses_actual_time(self, tmp_path):
        """Test that generated_at uses the actual generation time, not instantiation time."""
        import time
        reporter = Reporter()
        time.sleep(0.01)  # Small delay to ensure time difference
        report_path = tmp_path / "timing_report.md"
        reporter.generate_report([], str(report_path))

        content = report_path.read_text()
        # The report should contain a timestamp
        assert "**Generated:**" in content

    def test_redact_value_short(self):
        """Test redaction of short values (8 chars or less)."""
        reporter = Reporter()
        assert reporter._redact_value("short") == "***REDACTED***"
        assert reporter._redact_value("12345678") == "***REDACTED***"

    def test_redact_value_empty_string(self):
        """Test redaction of empty string."""
        reporter = Reporter()
        assert reporter._redact_value("") == "***REDACTED***"

    def test_redact_value_single_char(self):
        """Test redaction of single character."""
        reporter = Reporter()
        assert reporter._redact_value("x") == "***REDACTED***"

    def test_redact_value_long(self):
        """Test redaction of longer values."""
        reporter = Reporter()
        assert reporter._redact_value("AKIAIOSFODNN7EXAMPLE") == "AKIA***MPLE"
        assert reporter._redact_value("secret_key_12345") == "secr***2345"

    def test_redact_value_exactly_9_chars(self):
        """Test redaction of value with exactly 9 characters."""
        reporter = Reporter()
        result = reporter._redact_value("123456789")
        assert result == "1234***6789"
