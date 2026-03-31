# tests/test_detector.py
import pytest
from secret_scanner.detector import Detector, Finding


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
