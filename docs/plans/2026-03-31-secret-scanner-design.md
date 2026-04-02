# Secret Scanner - Design Document

**Date:** 2026-03-31
**Author:** Claude Code
**Status:** Approved

---

## Overview

构建一个 Python 项目，用于扫描用户所有代码仓库中的敏感信息（API Key、密码、Token 等），生成报告并自动脱敏修复。

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SecretScanner                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Local Scanner │  │  Remote Scanner │  │   Reporter  │ │
│  │   (本地扫描)    │  │  (GitHub API)   │  │   (报告器)  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │  Rule Engine    │  │   Redactor      │  │   Storage   │ │
│  │  (规则引擎)     │  │   (脱敏器)      │  │   (存储)    │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## Core Modules

| Module | File | Responsibility |
|--------|------|----------------|
| Scanner | `src/scanner.py` | 核心扫描逻辑，遍历文件和仓库 |
| Rules Engine | `src/rules.py` | 加载和管理检测规则 |
| Detector | `src/detector.py` | 敏感信息检测和匹配 |
| Redactor | `src/redactor.py` | 替换源文件中的敏感信息 |
| Reporter | `src/reporter.py` | 生成 Markdown 报告 |
| Storage | `src/storage.py` | 安全存储敏感信息到 .env.secret |
| GitHub Client | `src/github_client.py` | 调用 GitHub API 获取仓库列表 |

---

## Detection Rules

### Built-in Rules

- AWS Access Key ID (`AKIA[0-9A-Z]{16}`)
- GitHub Token (`gh[pousr]_[A-Za-z0-9_]{36,}`)
- Google API Key
- OpenAI/Anthropic API Key
- Database Connection Strings
- Private Keys (.pem, .key)
- JWT Secrets

### Custom Rules

用户可通过 YAML 配置文件自定义规则：

```yaml
rules:
  - id: custom_api_key
    pattern: "api[_-]?key\\s*[=:]\\s*[\"']?[A-Za-z0-9]{16,}"
    description: "自定义 API Key"
    severity: medium
```

---

## Data Flow

```
1. Input → 2. Discover Repos → 3. Traverse Files → 4. Rule Match → 5. Output
                                                        ↓
                                      ┌─────────────────┴─────────────────┐
                                      ↓                                   ↓
                                Generate Report                    Redact + Store
                            (secret_report.md)                  (.env.secret + modify)
```

---

## Output Report Format

```markdown
# Secret Scan Report - 2026-03-31

## 🔴 High Severity

### AWS Access Key
- **Location**: `user/repo-alpha/src/config.py:15`
- **Found**: `AKIA1234567890ABCDEF`
- **Rule**: aws_access_key

## Summary
- Total repos scanned: 12
- Files with secrets: 3
- Secrets found: 5 (High: 2, Medium: 3)
```

---

## Project Structure

```
secret-scanner/
├── src/
│   ├── __init__.py
│   ├── scanner.py
│   ├── rules.py
│   ├── detector.py
│   ├── redactor.py
│   ├── reporter.py
│   ├── storage.py
│   └── github_client.py
├── rules/
│   └── default_rules.yaml
├── tests/
│   ├── test_scanner.py
│   ├── test_detector.py
│   └── fixtures/
├── .github/
│   └── workflows/
│       └── scan.yml
├── requirements.txt
├── setup.py
└── README.md
```

---

## CI/CD Integration

### GitHub Actions Workflow

```yaml
name: Secret Scan

on:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Python
        uses: actions/setup-python@v5
      - name: Install scanner
        run: pip install secret-scanner
      - name: Run scan
        run: python -m secret_scanner --config .secret-scanner.yaml
```

### Configuration File

```yaml
# .secret-scanner.yaml
scan:
  mode: both  # local, remote, both
  local_path: /path/to/repos
  github_token: ${{ secrets.GITHUB_TOKEN }}

output:
  report_file: secret_report.md
  secret_storage: .env.secret

rules:
  include_default: true
  custom_rules: ./custom_rules.yaml
```

---

## Security Considerations

- 敏感信息存储到 `.env.secret` 文件
- 自动配置 `.gitignore` 防止提交
- 严格模式：宁可误报也不要漏报
- 用户手动确认可疑项

---

## Requirements

1. **扫描模式**: 支持本地目录扫描和 GitHub 远程仓库扫描
2. **规则引擎**: 内置规则 + 用户自定义规则
3. **报告输出**: Markdown 格式，包含文件路径和行号
4. **自动脱敏**: 替换源文件中的敏感信息为占位符
5. **安全存储**: 敏感信息保存到 `.env.secret`
6. **CI/CD 集成**: GitHub Actions，push 到主分支时触发

---

## Next Steps

1. Invoke `writing-plans` skill to create implementation plan
2. Create task breakdown for implementation
3. Implement with TDD approach
