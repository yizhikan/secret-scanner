# tests/test_scanner.py
import pytest
from secret_scanner.scanner import Scanner


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
        from secret_scanner.scanner import ScanResult
        result = ScanResult(
            files_scanned=10,
            findings=[],
            secrets_extracted=0,
            redacted_files=0
        )
        assert result.files_scanned == 10
