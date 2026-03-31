# src/secret_scanner/detector.py
from dataclasses import dataclass
from typing import List, Optional
from pathlib import Path
from .rules.engine import RulesEngine


@dataclass
class Finding:
    rule_id: str
    value: str
    description: str
    severity: str
    file_path: str
    line_number: int
    column: int


class Detector:
    def __init__(self, rules: Optional[List] = None):
        self.engine = RulesEngine()
        if rules:
            self.rules = self.engine.merge_rules(
                self.engine.load_default_rules(),
                rules
            )
        else:
            self.rules = self.engine.load_default_rules()
        self.engine.compile_rules(self.rules)

    def scan_content(self, content: str, file_path: str = "") -> List[Finding]:
        """Scan content string for secrets."""
        findings = []
        matches = self.engine.match(content)

        # Build line number index
        lines = content.split("\n")
        char_to_line = {}
        char_to_col = {}
        char_pos = 0
        for line_num, line in enumerate(lines, 1):
            for col in range(len(line) + 1):
                char_to_line[char_pos] = line_num
                char_to_col[char_pos] = col + 1
                char_pos += 1

        # Create rule lookup
        rule_lookup = {r["id"]: r for r in self.rules}

        for match in matches:
            rule = rule_lookup.get(match["rule_id"], {})
            start_pos = match["start"]
            line_num = char_to_line.get(start_pos, 1)
            col = char_to_col.get(start_pos, 1)

            findings.append(Finding(
                rule_id=match["rule_id"],
                value=match["value"],
                description=rule.get("description", ""),
                severity=rule.get("severity", "medium"),
                file_path=file_path,
                line_number=line_num,
                column=col
            ))

        return findings

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a file for secrets."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return self.scan_content(content, file_path)
        except (IOError, OSError):
            return []

    def scan_directory(
        self,
        dir_path: str,
        exclude_patterns: Optional[List[str]] = None
    ) -> List[Finding]:
        """Scan all files in directory recursively."""
        findings = []
        exclude = exclude_patterns or []

        # Common exclusions
        default_excludes = [
            "__pycache__", ".git", "node_modules", "*.pyc",
            "*.pyo", ".venv", "venv", "dist", "build"
        ]
        exclude.extend(default_excludes)

        for root, dirs, files in Path(dir_path).walk():
            # Filter directories
            dirs[:] = [
                d for d in dirs
                if not any(self._matches_pattern(d, p) for p in exclude)
            ]

            for file in files:
                if any(self._matches_pattern(file, p) for p in exclude):
                    continue
                file_path = str(root / file)
                findings.extend(self.scan_file(file_path))

        return findings

    def _matches_pattern(self, name: str, pattern: str) -> bool:
        """Check if name matches glob pattern."""
        import fnmatch
        return fnmatch.fnmatch(name, pattern)
