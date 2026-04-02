# src/secret_scanner/reporter.py
from datetime import datetime
from pathlib import Path
from typing import List
from .detector import Finding


class Reporter:
    def generate_report(self, findings: List[Finding], output_path: str) -> str:
        """Generate Markdown report."""
        generated_at = datetime.now().isoformat()

        # Group by severity
        by_severity = {"high": [], "medium": [], "low": []}
        for finding in findings:
            severity = finding.severity.lower()
            if severity in by_severity:
                by_severity[severity].append(finding)
            else:
                by_severity["medium"].append(finding)

        lines = [
            "# Secret Scan Report",
            "",
            f"**Generated:** {generated_at}",
            "",
            "## Summary",
            "",
            f"- **Total secrets found:** {len(findings)}",
            f"- **High severity:** {len(by_severity['high'])}",
            f"- **Medium severity:** {len(by_severity['medium'])}",
            f"- **Low severity:** {len(by_severity['low'])}",
            "",
        ]

        # High severity
        if by_severity["high"]:
            lines.extend([
                "## High Severity",
                "",
            ])
            for finding in by_severity["high"]:
                lines.extend(self._format_finding(finding))

        # Medium severity
        if by_severity["medium"]:
            lines.extend([
                "## Medium Severity",
                "",
            ])
            for finding in by_severity["medium"]:
                lines.extend(self._format_finding(finding))

        # Low severity
        if by_severity["low"]:
            lines.extend([
                "## Low Severity",
                "",
            ])
            for finding in by_severity["low"]:
                lines.extend(self._format_finding(finding))

        content = "\n".join(lines)

        # Ensure output directory exists
        output_dir = Path(output_path).parent
        if output_dir and not output_dir.exists():
            output_dir.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w") as f:
            f.write(content)

        return output_path

    def _format_finding(self, finding: Finding) -> List[str]:
        """Format a single finding."""
        return [
            f"### {finding.description}",
            f"- **Rule:** `{finding.rule_id}`",
            f"- **Location:** `{finding.file_path}:{finding.line_number}`",
            f"- **Value:** `{self._redact_value(finding.value)}`",
            "",
        ]

    def _redact_value(self, value: str) -> str:
        """Partially redact value for report."""
        if len(value) <= 8:
            return "***REDACTED***"
        return value[:4] + "***" + value[-4:]
