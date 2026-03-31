# src/secret_scanner/rules/engine.py
import re
from typing import List, Dict, Any
from pathlib import Path
import yaml


class RulesEngine:
    def __init__(self):
        self._compiled_patterns: Dict[str, re.Pattern] = {}

    def load_default_rules(self) -> List[Dict[str, Any]]:
        """Load built-in detection rules."""
        rules_path = Path(__file__).parent / "default_rules.yaml"
        with open(rules_path, "r") as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])

    def load_custom_rules(self, path: str) -> List[Dict[str, Any]]:
        """Load user-defined rules from YAML file."""
        if not Path(path).exists():
            raise FileNotFoundError(f"Rules file not found: {path}")
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        return data.get("rules", [])

    def merge_rules(
        self,
        base_rules: List[Dict[str, Any]],
        custom_rules: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Merge base and custom rules, custom rules override by id."""
        merged = {r["id"]: r for r in base_rules}
        merged.update({r["id"]: r for r in custom_rules})
        return list(merged.values())

    def compile_rules(self, rules: List[Dict[str, Any]]) -> None:
        """Compile regex patterns for efficient matching."""
        for rule in rules:
            if "id" not in rule:
                raise ValueError("Rule dict must contain 'id' key")
            if "pattern" not in rule:
                raise ValueError(f"Rule dict must contain 'pattern' key (rule id: {rule['id']})")
            try:
                self._compiled_patterns[rule["id"]] = re.compile(rule["pattern"])
            except re.error as e:
                raise ValueError(f"Invalid regex pattern for rule {rule['id']}: {e}")

    def match(self, content: str) -> List[Dict[str, Any]]:
        """Find all matches in content."""
        matches = []
        for rule_id, pattern in self._compiled_patterns.items():
            for match in pattern.finditer(content):
                matches.append({
                    "rule_id": rule_id,
                    "value": match.group(),
                    "start": match.start(),
                    "end": match.end()
                })
        return matches
