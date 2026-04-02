# Secret Scanner Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 构建一个 Python 项目，扫描用户所有代码仓库中的敏感信息（API Key、密码、Token 等），生成报告并自动脱敏修复。

**Architecture:** 模块化设计，包含扫描器、规则引擎、检测器、脱敏器、报告器和安全存储六个核心模块，支持本地和远程（GitHub API）两种扫描模式。

**Tech Stack:** Python 3.8+, PyYAML, requests, GitHub API v3, pytest

---

## Task 1: 项目骨架和基础配置

**Files:**
- Create: `secret-scanner/pyproject.toml`
- Create: `secret-scanner/src/secret_scanner/__init__.py`
- Create: `secret-scanner/README.md`
- Create: `secret-scanner/.gitignore`

### Step 1.1: 创建 pyproject.toml

```toml
[build-system]
requires = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "secret-scanner"
version = "0.1.0"
description = "Scan code repositories for sensitive information like API keys, passwords, and tokens"
requires-python = ">=3.8"
dependencies = [
    "pyyaml>=6.0",
    "requests>=2.28.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0",
    "pytest-cov>=4.0",
]

[project.scripts]
secret-scanner = "secret_scanner.cli:main"
```

### Step 1.2: 创建 __init__.py

```python
"""Secret Scanner - Detect and redact sensitive information in code repositories."""

__version__ = "0.1.0"
```

### Step 1.3: 创建 .gitignore

```
__pycache__/
*.pyc
*.pyo
.env.secret
secret_report.md
.pytest_cache/
.coverage
dist/
build/
*.egg-info
```

### Step 1.4: 创建 README.md

```markdown
# Secret Scanner

扫描代码仓库中的敏感信息（API Key、密码、Token 等），生成报告并自动脱敏修复。

## 功能

- 本地目录扫描
- GitHub 远程仓库扫描
- 内置规则 + 自定义规则
- Markdown 报告生成
- 自动脱敏和安全存储

## 安装

```bash
pip install -e .
```

## 使用

```bash
secret-scanner --config .secret-scanner.yaml
```
```

### Step 1.5: 提交

```bash
cd secret-scanner
git init
git add .
git commit -m "feat: initialize project structure"
```

---

## Task 2: 默认规则集

**Files:**
- Create: `secret-scanner/src/secret_scanner/rules/default_rules.yaml`
- Create: `secret-scanner/src/secret_scanner/rules/__init__.py`

### Step 2.1: 创建默认规则文件

```yaml
# default_rules.yaml
rules:
  - id: aws_access_key
    pattern: "AKIA[0-9A-Z]{16}"
    description: "AWS Access Key ID"
    severity: high

  - id: aws_secret_key
    pattern: "(?i)aws[_-]?secret[_-]?access[_-]?key\\s*[=:]\\s*[\"']?[A-Za-z0-9/+=]{40}"
    description: "AWS Secret Access Key"
    severity: high

  - id: github_token
    pattern: "gh[pousr]_[A-Za-z0-9_]{36,}"
    description: "GitHub Token"
    severity: high

  - id: gitlab_token
    pattern: "glpat-[A-Za-z0-9_-]{20,}"
    description: "GitLab Token"
    severity: high

  - id: openai_api_key
    pattern: "sk-[A-Za-z0-9]{48}"
    description: "OpenAI API Key"
    severity: high

  - id: anthropic_api_key
    pattern: "sk-ant-[A-Za-z0-9_-]{90,}"
    description: "Anthropic API Key"
    severity: high

  - id: google_api_key
    pattern: "AIza[0-9A-Za-z_-]{35}"
    description: "Google API Key"
    severity: high

  - id: private_key
    pattern: "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"
    description: "Private Key"
    severity: high

  - id: database_url
    pattern: "(?i)(mysql|postgres|postgresql|mongodb|redis)://[^\\s:]+:[^\\s@]+@"
    description: "Database Connection String"
    severity: high

  - id: generic_password
    pattern: "(?i)(password|passwd|pwd|secret)\\s*[=:]\\s*[\"'][^\"']{8,}[\"']"
    description: "Generic Password"
    severity: medium

  - id: generic_api_key
    pattern: "(?i)api[_-]?key\\s*[=:]\\s*[\"']?[A-Za-z0-9_-]{16,}[\"']?"
    description: "Generic API Key"
    severity: medium

  - id: jwt_secret
    pattern: "(?i)jwt[_-]?(secret|key)\\s*[=:]\\s*[\"'][^\"']{16,}[\"']"
    description: "JWT Secret"
    severity: medium
```

### Step 2.2: 创建 rules/__init__.py

```python
"""Rules module for secret detection patterns."""

from pathlib import Path

DEFAULT_RULES_PATH = Path(__file__).parent / "default_rules.yaml"
```

### Step 2.3: 提交

```bash
git add .
git commit -m "feat: add default detection rules"
```

---

## Task 3: 规则引擎 (rules.py)

**Files:**
- Create: `secret-scanner/src/secret_scanner/rules/engine.py`
- Test: `secret-scanner/tests/test_rules.py`

### Step 3.1: 编写测试

```python
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
```

### Step 3.2: 运行测试验证失败

```bash
pytest tests/test_rules.py -v
# Expected: FAIL - ModuleNotFoundError: No module named 'secret_scanner.rules.engine'
```

### Step 3.3: 实现规则引擎

```python
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
```

### Step 3.4: 运行测试验证通过

```bash
pytest tests/test_rules.py -v
# Expected: PASS
```

### Step 3.5: 提交

```bash
git add .
git commit -m "feat: implement rules engine with TDD"
```

---

## Task 4: 检测器 (detector.py)

**Files:**
- Create: `secret-scanner/src/secret_scanner/detector.py`
- Test: `secret-scanner/tests/test_detector.py`

### Step 4.1: 编写测试

```python
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
        test_file.write_text("API_KEY = 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'")
        detector = Detector()
        findings = detector.scan_file(str(test_file))
        assert len(findings) == 1
        assert findings[0].file_path == str(test_file)
```

### Step 4.2: 运行测试验证失败

```bash
pytest tests/test_detector.py -v
# Expected: FAIL
```

### Step 4.3: 实现检测器

```python
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
```

### Step 4.4: 运行测试验证通过

```bash
pytest tests/test_detector.py -v
# Expected: PASS
```

### Step 4.5: 提交

```bash
git add .
git commit -m "feat: implement secret detector with TDD"
```

---

## Task 5: 报告生成器 (reporter.py)

**Files:**
- Create: `secret-scanner/src/secret_scanner/reporter.py`
- Test: `secret-scanner/tests/test_reporter.py`

### Step 5.1: 编写测试

```python
# tests/test_reporter.py
import pytest
from secret_scanner.reporter import Reporter
from secret_scanner.detector import Finding


class TestReporter:
    def test_generate_report(self, tmp_path):
        findings = [
            Finding(
                rule_id="aws_access_key",
                value="AKIAIOSFODNN7EXAMPLE",
                description="AWS Access Key ID",
                severity="high",
                file_path="/repo/config.py",
                line_number=15,
                column=10
            ),
            Finding(
                rule_id="github_token",
                value="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                description="GitHub Token",
                severity="high",
                file_path="/repo/.env",
                line_number=3,
                column=1
            )
        ]
        reporter = Reporter()
        report_path = tmp_path / "report.md"
        reporter.generate_report(findings, str(report_path))

        content = report_path.read_text()
        assert "# Secret Scan Report" in content
        assert "AWS Access Key ID" in content
        assert "config.py:15" in content
```

### Step 5.2: 运行测试验证失败

```bash
pytest tests/test_reporter.py -v
# Expected: FAIL
```

### Step 5.3: 实现报告生成器

```python
# src/secret_scanner/reporter.py
from datetime import datetime
from typing import List
from .detector import Finding


class Reporter:
    def __init__(self):
        self.generated_at = datetime.now().isoformat()

    def generate_report(self, findings: List[Finding], output_path: str) -> str:
        """Generate Markdown report."""
        # Group by severity
        by_severity = {"high": [], "medium": [], "low": []}
        for finding in findings:
            severity = finding.severity.lower()
            if severity in by_severity:
                by_severity[severity].append(finding)
            else:
                by_severity["medium"].append(finding)

        # Count by repo
        repos = set()
        for f in findings:
            parts = f.file_path.split("/")
            for i, p in enumerate(parts):
                if i < len(parts) - 1:
                    repos.add("/".join(parts[:i+1]))
                    break

        lines = [
            "# Secret Scan Report",
            "",
            f"**Generated:** {self.generated_at}",
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
                "## 🔴 High Severity",
                "",
            ])
            for finding in by_severity["high"]:
                lines.extend(self._format_finding(finding))

        # Medium severity
        if by_severity["medium"]:
            lines.extend([
                "## 🟡 Medium Severity",
                "",
            ])
            for finding in by_severity["medium"]:
                lines.extend(self._format_finding(finding))

        # Low severity
        if by_severity["low"]:
            lines.extend([
                "## 🟢 Low Severity",
                "",
            ])
            for finding in by_severity["low"]:
                lines.extend(self._format_finding(finding))

        content = "\n".join(lines)
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
```

### Step 5.4: 运行测试验证通过

```bash
pytest tests/test_reporter.py -v
# Expected: PASS
```

### Step 5.5: 提交

```bash
git add .
git commit -m "feat: implement report generator with TDD"
```

---

## Task 6: 脱敏器 (redactor.py)

**Files:**
- Create: `secret-scanner/src/secret_scanner/redactor.py`
- Test: `secret-scanner/tests/test_redactor.py`

### Step 6.1: 编写测试

```python
# tests/test_redactor.py
import pytest
from secret_scanner.redactor import Redactor


class TestRedactor:
    def test_redact_content(self):
        content = "API_KEY = 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"
        redactor = Redactor()
        result, secrets = redactor.redact_content(content, "test.py")

        assert "sk-xxx" not in result
        assert "<REDACTED:sk-xxxx...xxxxxxx>" in result
        assert len(secrets) == 1
        assert secrets[0]["original"] == "sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

    def test_redact_multiple_secrets(self):
        content = """
        AWS_KEY = AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
        """
        redactor = Redactor()
        result, secrets = redactor.redact_content(content, "test.py")

        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" not in result
        assert len(secrets) == 2
```

### Step 6.2: 运行测试验证失败

```bash
pytest tests/test_redactor.py -v
# Expected: FAIL
```

### Step 6.3: 实现脱敏器

```python
# src/secret_scanner/redactor.py
from typing import List, Dict, Tuple
from pathlib import Path
from .detector import Detector, Finding


class Redactor:
    def __init__(self):
        self.detector = Detector()

    def redact_content(
        self,
        content: str,
        file_path: str
    ) -> Tuple[str, List[Dict]]:
        """Replace secrets in content with placeholders."""
        findings = self.detector.scan_content(content, file_path)
        secrets = []

        # Sort by position (reverse order to maintain positions)
        findings.sort(key=lambda f: f.line_number * 1000 + f.column, reverse=True)

        lines = content.split("\n")

        for finding in findings:
            line_idx = finding.line_number - 1
            if line_idx >= len(lines):
                continue

            line = lines[line_idx]
            col_start = finding.column - 1
            col_end = col_start + len(finding.value)

            if col_start < 0 or col_end > len(line):
                continue

            # Create placeholder
            value = finding.value
            if len(value) > 12:
                placeholder = f"<REDACTED:{value[:4]}...{value[-4:]}>"
            else:
                placeholder = "<REDACTED>"

            # Store secret
            secrets.append({
                "file": file_path,
                "line": finding.line_number,
                "rule_id": finding.rule_id,
                "original": value
            })

            # Replace in line
            lines[line_idx] = line[:col_start] + placeholder + line[col_end:]

        return "\n".join(lines), secrets

    def redact_file(self, file_path: str) -> List[Dict]:
        """Redact secrets in file and save."""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        redacted, secrets = self.redact_content(content, file_path)

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(redacted)

        return secrets
```

### Step 6.4: 运行测试验证通过

```bash
pytest tests/test_redactor.py -v
# Expected: PASS
```

### Step 6.5: 提交

```bash
git add .
git commit -m "feat: implement redactor with TDD"
```

---

## Task 7: 安全存储 (storage.py)

**Files:**
- Create: `secret-scanner/src/secret_scanner/storage.py`
- Test: `secret-scanner/tests/test_storage.py`

### Step 7.1: 编写测试

```python
# tests/test_storage.py
import pytest
from secret_scanner.storage import SecretStorage


class TestSecretStorage:
    def test_save_secrets(self, tmp_path):
        secrets = [
            {"file": "config.py", "line": 15, "rule_id": "aws_key", "original": "AKIAIOSFODNN7EXAMPLE"},
            {"file": ".env", "line": 3, "rule_id": "github_token", "original": "ghp_xxxx"}
        ]
        storage = SecretStorage()
        output_path = tmp_path / ".env.secret"

        storage.save_secrets(secrets, str(output_path))

        content = output_path.read_text()
        assert "AKIAIOSFODNN7EXAMPLE" in content
        assert "config.py:15" in content

    def test_create_gitignore_entry(self, tmp_path):
        storage = SecretStorage()
        gitignore_path = tmp_path / ".gitignore"

        storage.ensure_gitignore_entry(str(gitignore_path))

        content = gitignore_path.read_text()
        assert ".env.secret" in content
```

### Step 7.2: 运行测试验证失败

```bash
pytest tests/test_storage.py -v
# Expected: FAIL
```

### Step 7.3: 实现安全存储

```python
# src/secret_scanner/storage.py
from datetime import datetime
from typing import List, Dict
from pathlib import Path


class SecretStorage:
    def __init__(self):
        self.generated_at = datetime.now().isoformat()

    def save_secrets(
        self,
        secrets: List[Dict],
        output_path: str
    ) -> str:
        """Save extracted secrets to file."""
        lines = [
            "# Secret Scanner - Extracted Secrets",
            f"# Generated: {self.generated_at}",
            "# WARNING: Keep this file secure and never commit to version control!",
            "",
        ]

        for i, secret in enumerate(secrets, 1):
            lines.extend([
                f"# Secret {i}",
                f"# Location: {secret['file']}:{secret['line']}",
                f"# Rule: {secret['rule_id']}",
                f"{secret['rule_id']}={secret['original']}",
                "",
            ])

        content = "\n".join(lines)
        with open(output_path, "w") as f:
            f.write(content)

        return output_path

    def ensure_gitignore_entry(self, gitignore_path: str) -> None:
        """Ensure .env.secret is in .gitignore."""
        entry = ".env.secret"

        if Path(gitignore_path).exists():
            with open(gitignore_path, "r") as f:
                content = f.read()
            if entry not in content:
                with open(gitignore_path, "a") as f:
                    f.write(f"\n# Secret Scanner\n{entry}\n")
        else:
            with open(gitignore_path, "w") as f:
                f.write(f"# Secret Scanner\n{entry}\n")
```

### Step 7.4: 运行测试验证通过

```bash
pytest tests/test_storage.py -v
# Expected: PASS
```

### Step 7.5: 提交

```bash
git add .
git commit -m "feat: implement secure secret storage with TDD"
```

---

## Task 8: 扫描器核心 (scanner.py)

**Files:**
- Create: `secret-scanner/src/secret_scanner/scanner.py`
- Test: `secret-scanner/tests/test_scanner.py`

### Step 8.1: 编写测试

```python
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
```

### Step 8.2: 运行测试验证失败

```bash
pytest tests/test_scanner.py -v
# Expected: FAIL
```

### Step 8.3: 实现扫描器

```python
# src/secret_scanner/scanner.py
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path
from .detector import Detector, Finding
from .redactor import Redactor
from .reporter import Reporter
from .storage import SecretStorage


@dataclass
class ScanResult:
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    secrets_extracted: int = 0
    redacted_files: int = 0


class Scanner:
    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.detector = Detector()
        self.redactor = Redactor()
        self.reporter = Reporter()
        self.storage = SecretStorage()

    def scan_local(
        self,
        dir_path: str,
        redact: bool = False,
        output_dir: Optional[str] = None
    ) -> ScanResult:
        """Scan local directory for secrets."""
        result = ScanResult()

        # Scan for findings
        result.findings = self.detector.scan_directory(dir_path)
        result.files_scanned = sum(1 for _ in Path(dir_path).rglob("*") if _.is_file())

        if redact and output_dir:
            # Redact files
            files_redacted = set()
            for finding in result.findings:
                if finding.file_path not in files_redacted:
                    secrets = self.redactor.redact_file(finding.file_path)
                    result.secrets_extracted += len(secrets)
                    files_redacted.add(finding.file_path)

            # Save secrets
            secret_path = Path(output_dir) / ".env.secret"
            all_secrets = []
            for f in files_redacted:
                all_secrets.extend(self.redactor.redact_content(
                    Path(f).read_text(), f
                )[1])
            self.storage.save_secrets(all_secrets, str(secret_path))
            self.storage.ensure_gitignore_entry(
                str(Path(output_dir) / ".gitignore")
            )

        # Generate report
        if output_dir:
            report_path = Path(output_dir) / "secret_report.md"
            self.reporter.generate_report(result.findings, str(report_path))

        return result
```

### Step 8.4: 运行测试验证通过

```bash
pytest tests/test_scanner.py -v
# Expected: PASS
```

### Step 8.5: 提交

```bash
git add .
git commit -m "feat: implement core scanner with TDD"
```

---

## Task 9: GitHub 客户端 (github_client.py)

**Files:**
- Create: `secret-scanner/src/secret_scanner/github_client.py`
- Test: `secret-scanner/tests/test_github_client.py`

### Step 9.1: 编写测试

```python
# tests/test_github_client.py
import pytest
from unittest.mock import Mock, patch
from secret_scanner.github_client import GitHubClient


class TestGitHubClient:
    def test_list_user_repos(self):
        client = GitHubClient(token="fake_token")
        # Mock the API call
        with patch.object(client, "_fetch_repos") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "repo1", "full_name": "user/repo1", "clone_url": "https://github.com/user/repo1.git"},
                {"name": "repo2", "full_name": "user/repo2", "clone_url": "https://github.com/user/repo2.git"}
            ]
            repos = client.list_user_repos("testuser")
            assert len(repos) == 2
            assert repos[0]["name"] == "repo1"

    def test_clone_repo(self, tmp_path):
        client = GitHubClient(token="fake_token")
        # This would need actual git mocking for full test
        assert client is not None
```

### Step 9.2: 运行测试验证失败

```bash
pytest tests/test_github_client.py -v
# Expected: FAIL
```

### Step 9.3: 实现 GitHub 客户端

```python
# src/secret_scanner/github_client.py
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict, Optional
import requests


class GitHubClient:
    def __init__(self, token: str):
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        })

    def list_user_repos(self, username: str) -> List[Dict]:
        """List all repositories for a user."""
        repos = []
        page = 1

        while True:
            url = f"https://api.github.com/users/{username}/repos"
            params = {"page": page, "per_page": 100}
            response = self.session.get(url, params=params)
            response.raise_for_status()

            page_repos = response.json()
            if not page_repos:
                break

            repos.extend([
                {
                    "name": r["name"],
                    "full_name": r["full_name"],
                    "clone_url": r["clone_url"]
                }
                for r in page_repos
            ])
            page += 1

        return repos

    def clone_repo(
        self,
        clone_url: str,
        dest_dir: Optional[str] = None
    ) -> str:
        """Clone repository to local directory."""
        if dest_dir is None:
            dest_dir = tempfile.mkdtemp()

        # Extract repo name from URL
        repo_name = clone_url.split("/")[-1].replace(".git", "")
        dest_path = Path(dest_dir) / repo_name

        # Clone with token
        auth_url = clone_url.replace(
            "https://",
            f"https://{self.token}@"
        )

        subprocess.run(
            ["git", "clone", "--depth", "1", auth_url, str(dest_path)],
            check=True,
            capture_output=True
        )

        return str(dest_path)

    def scan_remote(
        self,
        username: str,
        redact: bool = False,
        output_dir: Optional[str] = None
    ):
        """Scan all user repositories."""
        from .scanner import Scanner

        scanner = Scanner()
        repos = self.list_user_repos(username)
        all_findings = []

        for repo in repos:
            try:
                # Clone repo
                repo_path = self.clone_repo(repo["clone_url"])

                # Scan it
                result = scanner.scan_local(repo_path, redact=False)
                all_findings.extend(result.findings)

            except Exception as e:
                print(f"Error scanning {repo['full_name']}: {e}")

        # Generate combined report
        if output_dir:
            self.reporter.generate_report(all_findings, str(Path(output_dir) / "remote_report.md"))

        return all_findings
```

### Step 9.4: 运行测试验证通过

```bash
pytest tests/test_github_client.py -v
# Expected: PASS
```

### Step 9.5: 提交

```bash
git add .
git commit -m "feat: implement GitHub client for remote scanning"
```

---

## Task 10: CLI 入口 (cli.py)

**Files:**
- Create: `secret-scanner/src/secret_scanner/cli.py`
- Test: `secret-scanner/tests/test_cli.py`

### Step 10.1: 编写测试

```python
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
```

### Step 10.2: 添加 click 依赖

编辑 `pyproject.toml`:
```toml
dependencies = [
    "pyyaml>=6.0",
    "requests>=2.28.0",
    "click>=8.0",
]
```

### Step 10.3: 运行测试验证失败

```bash
pip install -e ".[dev]"
pytest tests/test_cli.py -v
# Expected: FAIL
```

### Step 10.4: 实现 CLI

```python
# src/secret_scanner/cli.py
import click
import yaml
from pathlib import Path
from .scanner import Scanner
from .github_client import GitHubClient


@click.group()
@click.version_option(version="0.1.0")
def main():
    """Secret Scanner - Detect and redact sensitive information."""
    pass


@main.command()
@click.option(
    "--local", "-l",
    "local_path",
    help="Local directory to scan"
)
@click.option(
    "--remote", "-r",
    "username",
    help="GitHub username to scan"
)
@click.option(
    "--config", "-c",
    "config_file",
    help="Configuration file path"
)
@click.option(
    "--output", "-o",
    "output_dir",
    help="Output directory for reports"
)
@click.option(
    "--redact/--no-redact",
    default=False,
    help="Redact secrets from source files"
)
@click.option(
    "--github-token",
    envvar="GITHUB_TOKEN",
    help="GitHub API token"
)
def scan(local_path, username, config_file, output_dir, redact, github_token):
    """Scan repositories for secrets."""
    config = {}

    if config_file:
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)

    output_dir = output_dir or "."

    if local_path:
        click.echo(f"Scanning local directory: {local_path}")
        scanner = Scanner(config)
        result = scanner.scan_local(local_path, redact=redact, output_dir=output_dir)
        click.echo(f"Scanned {result.files_scanned} files")
        click.echo(f"Found {len(result.findings)} secrets")

    if username:
        if not github_token:
            click.echo("Error: --github-token required for remote scan", err=True)
            return
        click.echo(f"Scanning GitHub user: {username}")
        client = GitHubClient(github_token)
        findings = client.scan_remote(username, redact=redact, output_dir=output_dir)
        click.echo(f"Found {len(findings)} secrets")

    if output_dir:
        click.echo(f"Report saved to: {Path(output_dir) / 'secret_report.md'}")


if __name__ == "__main__":
    main()
```

### Step 10.5: 运行测试验证通过

```bash
pytest tests/test_cli.py -v
# Expected: PASS
```

### Step 10.6: 提交

```bash
git add .
git commit -m "feat: implement CLI interface"
```

---

## Task 11: GitHub Actions Workflow

**Files:**
- Create: `secret-scanner/.github/workflows/scan.yml`
- Create: `secret-scanner/.secret-scanner.yaml`

### Step 11.1: 创建示例配置文件

```yaml
# .secret-scanner.yaml
scan:
  mode: local  # local, remote, or both
  github_token: ${GITHUB_TOKEN}

output:
  report_file: secret_report.md
  secret_storage: .env.secret

rules:
  include_default: true
  custom_rules: null

redact: false
```

### Step 11.2: 创建 GitHub Actions Workflow

```yaml
# .github/workflows/scan.yml
name: Secret Scan

on:
  push:
    branches: [main, master]
  pull_request:
    branches: [main, master]

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'

      - name: Install secret-scanner
        run: |
          pip install -e .

      - name: Run secret scan
        run: |
          python -m secret_scanner scan \
            --local . \
            --output . \
            --config .secret-scanner.yaml || true

      - name: Upload report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: secret-scan-report
          path: |
            secret_report.md
            .env.secret
```

### Step 11.3: 提交

```bash
git add .
git commit -m "feat: add GitHub Actions workflow"
```

---

## Task 12: 完善文档和最终测试

**Files:**
- Modify: `secret-scanner/README.md`

### Step 12.1: 更新 README

```markdown
# Secret Scanner

扫描代码仓库中的敏感信息（API Key、密码、Token 等），生成报告并自动脱敏修复。

## 功能

- ✅ 本地目录扫描
- ✅ GitHub 远程仓库扫描
- ✅ 内置规则 + 自定义规则
- ✅ Markdown 报告生成
- ✅ 自动脱敏和安全存储
- ✅ GitHub Actions CI/CD 集成

## 安装

```bash
pip install -e .
```

## 使用

### 本地扫描

```bash
python -m secret_scanner scan --local /path/to/repos --output ./report
```

### 远程扫描

```bash
export GITHUB_TOKEN=your_token
python -m secret_scanner scan --remote username --output ./report
```

### 带脱敏

```bash
python -m secret_scanner scan \
  --local /path/to/repos \
  --output ./report \
  --redact
```

## 配置

创建 `.secret-scanner.yaml`:

```yaml
scan:
  mode: local
  github_token: ${GITHUB_TOKEN}

output:
  report_file: secret_report.md
  secret_storage: .env.secret

rules:
  include_default: true
```

## CI/CD 集成

将 `.github/workflows/scan.yml` 添加到你的仓库，每次 push 时自动扫描。

## License

MIT
```

### Step 12.2: 运行完整测试套件

```bash
pytest tests/ -v --cov=secret_scanner
# Expected: All tests pass with >80% coverage
```

### Step 12.3: 最终提交

```bash
git add .
git commit -m "docs: complete README and final polish"
```

---

## Summary

This plan creates a complete secret scanning tool with:
- 12 tasks with TDD approach
- 50+ test-driven steps
- Frequent commits (one per feature)
- Full CI/CD integration
- Comprehensive documentation

**Next:** Use `superpowers:executing-plans` to implement this plan task-by-task.