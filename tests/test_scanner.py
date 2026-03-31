# tests/test_scanner.py
import pytest
from pathlib import Path
from secret_scanner.scanner import Scanner, ScanResult


class TestScanner:
    def test_scan_local_directory(self, tmp_path):
        # Create test repo structure
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        (repo_dir / "config.py").write_text("API_KEY = 'sk-xxxxxxxxxxxxxxxxxxxxxxxx'")

        scanner = Scanner()
        results = scanner.scan_local(str(repo_dir))

        assert len(results.findings) >= 1
        assert results.secrets_extracted > 0

    def test_scanner_result(self):
        result = ScanResult(
            files_scanned=10,
            findings=[],
            secrets_extracted=0,
            redacted_files=0
        )
        assert result.files_scanned == 10

    def test_scan_empty_directory(self, tmp_path):
        """Test scanning an empty directory returns empty results."""
        empty_dir = tmp_path / "empty-repo"
        empty_dir.mkdir()

        scanner = Scanner()
        results = scanner.scan_local(str(empty_dir))

        assert results.files_scanned == 0
        assert len(results.findings) == 0
        assert results.secrets_extracted == 0

    def test_scan_with_custom_config(self):
        """Test scanner initialization with custom config."""
        custom_config = {"max_file_size": 1024 * 1024, "exclude_patterns": ["*.test"]}
        scanner = Scanner(config=custom_config)

        # Config should be stored
        assert scanner.config == custom_config

    def test_scan_with_no_config(self):
        """Test scanner initialization without config defaults to empty dict."""
        scanner = Scanner()
        assert scanner.config == {}

    def test_redact_workflow(self, tmp_path):
        """Test the redact=True workflow with output directory."""
        # Create test repo with secrets
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        secret_file = repo_dir / "secrets.py"
        secret_file.write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE\n")

        scanner = Scanner()
        results = scanner.scan_local(
            str(repo_dir),
            redact=True,
            output_dir=str(output_dir)
        )

        # Verify findings were detected
        assert len(results.findings) >= 1

        # Verify report was generated
        report_path = output_dir / "secret_report.md"
        assert report_path.exists()
        assert "# Secret Scan Report" in report_path.read_text()

    def test_redact_workflow_saves_secrets(self, tmp_path):
        """Test that redact workflow saves secrets to .env.secret file."""
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        secret_file = repo_dir / "config.py"
        secret_file.write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE\n")

        scanner = Scanner()
        scanner.scan_local(
            str(repo_dir),
            redact=True,
            output_dir=str(output_dir)
        )

        # Verify .env.secret was created
        secret_path = output_dir / ".env.secret"
        assert secret_path.exists()

        # Verify .gitignore was created/updated
        gitignore_path = output_dir / ".gitignore"
        assert gitignore_path.exists()

    def test_report_generation(self, tmp_path):
        """Test report generation in output directory."""
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        # Create file with high severity secret
        secret_file = repo_dir / "aws.py"
        secret_file.write_text("AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE\n")

        scanner = Scanner()
        results = scanner.scan_local(
            str(repo_dir),
            output_dir=str(output_dir)
        )

        # Verify report exists
        report_path = output_dir / "secret_report.md"
        assert report_path.exists()

        content = report_path.read_text()
        assert "# Secret Scan Report" in content
        assert "AKIA***MPLE" in content or "***REDACTED***" in content
        assert "aws.py" in content

    def test_scan_without_output_dir(self, tmp_path):
        """Test scanning without output_dir doesn't create files."""
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        (repo_dir / "config.py").write_text("API_KEY = 'sk-xxxxxxxxxxxxxxxx'")

        scanner = Scanner()
        results = scanner.scan_local(str(repo_dir))

        # Should not create any report files
        assert not (repo_dir / "secret_report.md").exists()
        assert not (repo_dir / ".env.secret").exists()

    def test_redact_false_no_output(self, tmp_path):
        """Test that redact=False doesn't create redaction files."""
        repo_dir = tmp_path / "test-repo"
        repo_dir.mkdir()
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        secret_file = repo_dir / "secrets.py"
        secret_file.write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE\n")
        original_content = secret_file.read_text()

        scanner = Scanner()
        scanner.scan_local(
            str(repo_dir),
            redact=False,
            output_dir=str(output_dir)
        )

        # Original file should be unchanged
        assert secret_file.read_text() == original_content

        # No .env.secret should be created
        assert not (output_dir / ".env.secret").exists()
