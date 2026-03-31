# tests/test_rules.py
import pytest
from secret_scanner.rules.engine import RulesEngine


class TestRulesEngine:
    def test_load_default_rules(self):
        engine = RulesEngine()
        rules = engine.load_default_rules()
        assert len(rules) > 0
        assert any(r["id"] == "aws_access_key" for r in rules)

    def test_load_custom_rules(self, tmp_path):
        custom_rules_file = tmp_path / "custom.yaml"
        custom_rules_file.write_text("""
rules:
  - id: custom_test
    pattern: "CUSTOM_[A-Z]+"
    description: "Custom Test Rule"
    severity: low
""")
        engine = RulesEngine()
        rules = engine.load_custom_rules(str(custom_rules_file))
        assert len(rules) == 1
        assert rules[0]["id"] == "custom_test"

    def test_merge_rules(self):
        engine = RulesEngine()
        base_rules = [{"id": "base", "pattern": "BASE"}]
        custom_rules = [{"id": "custom", "pattern": "CUSTOM"}]
        merged = engine.merge_rules(base_rules, custom_rules)
        assert len(merged) == 2
