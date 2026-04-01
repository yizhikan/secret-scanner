# tests/test_cli.py
import pytest
from click.testing import CliRunner
from secret_scanner.cli import main


class TestCLI:
    def test_main_help(self):
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output

    def test_scan_local(self, tmp_path):
        runner = CliRunner()
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text("# no secrets here")

        result = runner.invoke(main, [
            "scan",
            "--local",
            str(tmp_path),
            "--output",
            str(tmp_path)
        ])
        assert result.exit_code == 0
