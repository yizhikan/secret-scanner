# tests/test_detector.py
import pytest
from secret_scanner.detector import Detector, Finding
from pathlib import Path
import os


class TestDetector:
    def test_find_aws_key(self):
        content = "AWS_KEY = AKIAIOSFODNN7EXAMPLE"
        detector = Detector()
        findings = detector.scan_content(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "aws_access_key"
        assert "AKIAIOSFODNN7EXAMPLE" in findings[0].value

    def test_find_github_token(self):
        content = "token = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        detector = Detector()
        findings = detector.scan_content(content)
        assert len(findings) == 1
        assert findings[0].rule_id == "github_token"

    def test_find_multiple_secrets(self):
        content = """
        AWS_KEY = AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        """
        detector = Detector()
        findings = detector.scan_content(content)
        assert len(findings) == 2

    def test_scan_file(self, tmp_path):
        test_file = tmp_path / "config.py"
        test_file.write_text("API_KEY = 'generic_api_key_value_12345678'")
        detector = Detector()
        findings = detector.scan_file(str(test_file))
        assert len(findings) == 1
        assert findings[0].file_path == str(test_file)

    def test_scan_file_nonexistent(self):
        """Test that scan_file returns empty list for non-existent file."""
        detector = Detector()
        findings = detector.scan_file("/nonexistent/path/file.txt")
        assert findings == []

    def test_scan_file_exception_handling(self, tmp_path):
        """Test that scan_file handles exceptions gracefully."""
        detector = Detector()
        # Test with a path that will raise an exception
        findings = detector.scan_file(str(tmp_path / "nonexistent"))
        assert findings == []

    def test_scan_directory(self, tmp_path):
        """Test scanning a directory recursively for secrets."""
        # Create test files
        file1 = tmp_path / "secret1.py"
        file1.write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE")

        file2 = tmp_path / "secret2.py"
        file2.write_text("GITHUB_TOKEN = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

        # Create subdirectory with file
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        file3 = subdir / "secret3.py"
        file3.write_text("API_KEY = 'generic_api_key_value_12345678'")

        detector = Detector()
        findings = detector.scan_directory(str(tmp_path))

        assert len(findings) == 3
        file_paths = [f.file_path for f in findings]
        assert str(file1) in file_paths
        assert str(file2) in file_paths
        assert str(file3) in file_paths

    def test_scan_directory_excludes(self, tmp_path):
        """Test that scan_directory respects exclude patterns."""
        # Create test files
        file1 = tmp_path / "secret1.py"
        file1.write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE")

        # Create __pycache__ directory (should be excluded by default)
        pycache = tmp_path / "__pycache__"
        pycache.mkdir()
        file2 = pycache / "cached.pyc"
        file2.write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE")

        detector = Detector()
        findings = detector.scan_directory(str(tmp_path))

        assert len(findings) == 1
        assert findings[0].file_path == str(file1)

    def test_scan_directory_custom_excludes(self, tmp_path):
        """Test scan_directory with custom exclude patterns."""
        # Create test files
        file1 = tmp_path / "secret1.py"
        file1.write_text("AWS_KEY = AKIAIOSFODNN7EXAMPLE")

        file2 = tmp_path / "secret2.py"
        file2.write_text("GITHUB_TOKEN = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

        detector = Detector()
        findings = detector.scan_directory(str(tmp_path), exclude_patterns=["*.py"])

        assert len(findings) == 0

    def test_matches_pattern(self):
        """Test the _matches_pattern helper method."""
        detector = Detector()

        # Test exact match
        assert detector._matches_pattern("file.py", "file.py") is True

        # Test wildcard pattern
        assert detector._matches_pattern("file.py", "*.py") is True
        assert detector._matches_pattern("test.py", "*.py") is True
        assert detector._matches_pattern("file.txt", "*.py") is False

        # Test directory pattern
        assert detector._matches_pattern("__pycache__", "__pycache__") is True
        assert detector._matches_pattern(".git", ".git") is True

        # Test complex patterns
        assert detector._matches_pattern("file.pyc", "*.pyc") is True
        assert detector._matches_pattern("venv", "venv") is True
