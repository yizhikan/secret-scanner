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

    def test_compile_rules(self):
        engine = RulesEngine()
        rules = [{"id": "test_rule", "pattern": "TEST_[A-Z]+"}]
        engine.compile_rules(rules)
        assert "test_rule" in engine._compiled_patterns

    def test_compile_rules_invalid_regex(self):
        engine = RulesEngine()
        rules = [{"id": "bad_rule", "pattern": "[invalid"}]
        with pytest.raises(ValueError, match="Invalid regex pattern"):
            engine.compile_rules(rules)

    def test_compile_rules_missing_id(self):
        engine = RulesEngine()
        rules = [{"pattern": "TEST"}]
        with pytest.raises(ValueError, match="must contain 'id' key"):
            engine.compile_rules(rules)

    def test_compile_rules_missing_pattern(self):
        engine = RulesEngine()
        rules = [{"id": "test_rule"}]
        with pytest.raises(ValueError, match="must contain 'pattern' key"):
            engine.compile_rules(rules)

    def test_match(self):
        engine = RulesEngine()
        rules = [{"id": "aws_key", "pattern": "AKIA[0-9A-Z]{16}"}]
        engine.compile_rules(rules)
        content = "My key is AKIAIOSFODNN7EXAMPLE here"
        matches = engine.match(content)
        assert len(matches) == 1
        assert matches[0]["rule_id"] == "aws_key"
        assert matches[0]["value"] == "AKIAIOSFODNN7EXAMPLE"

    def test_match_multiple(self):
        engine = RulesEngine()
        rules = [
            {"id": "pattern_a", "pattern": "AAA"},
            {"id": "pattern_b", "pattern": "BBB"}
        ]
        engine.compile_rules(rules)
        content = "AAA BBB AAA"
        matches = engine.match(content)
        assert len(matches) == 3

    def test_match_no_results(self):
        engine = RulesEngine()
        rules = [{"id": "test", "pattern": "NOTFOUND"}]
        engine.compile_rules(rules)
        matches = engine.match("some content")
        assert len(matches) == 0

    def test_load_custom_rules_file_not_found(self):
        engine = RulesEngine()
        with pytest.raises(FileNotFoundError, match="Rules file not found"):
            engine.load_custom_rules("/nonexistent/path/rules.yaml")

    def test_load_custom_rules_malformed_yaml(self, tmp_path):
        custom_rules_file = tmp_path / "malformed.yaml"
        custom_rules_file.write_text("rules:\n  - id: test\n    pattern: [invalid")
        engine = RulesEngine()
        with pytest.raises(Exception):
            engine.load_custom_rules(str(custom_rules_file))
