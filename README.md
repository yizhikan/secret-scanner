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

### 使用配置文件

```bash
python -m secret_scanner scan --config .secret-scanner.yaml
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

## 内置检测规则

| 规则 ID | 描述 | 严重程度 |
|--------|------|---------|
| `aws_access_key` | AWS Access Key ID | High |
| `aws_secret_key` | AWS Secret Access Key | High |
| `github_token` | GitHub Token | High |
| `gitlab_token` | GitLab Token | High |
| `openai_api_key` | OpenAI API Key | High |
| `anthropic_api_key` | Anthropic API Key | High |
| `google_api_key` | Google API Key | High |
| `private_key` | Private Key (.pem, .key) | High |
| `database_url` | Database Connection String | High |
| `generic_password` | Generic Password | Medium |
| `generic_api_key` | Generic API Key | Medium |
| `jwt_secret` | JWT Secret | Medium |

## 报告输出示例

```markdown
# Secret Scan Report

**Generated:** 2026-03-31T12:00:00

## Summary

- **Total secrets found:** 5
- **High severity:** 2
- **Medium severity:** 3

## 🔴 High Severity

### AWS Access Key ID
- **Rule:** `aws_access_key`
- **Location:** `config.py:15`
- **Value:** `AKIA***EF`
```

## CI/CD 集成

将 `.github/workflows/scan.yml` 添加到你的仓库，每次 push 时自动扫描。

## 项目结构

```
secret-scanner/
├── src/secret_scanner/
│   ├── __init__.py
│   ├── cli.py          # CLI 入口
│   ├── scanner.py      # 核心扫描器
│   ├── detector.py     # 检测器
│   ├── rules/
│   │   ├── __init__.py
│   │   ├── engine.py   # 规则引擎
│   │   └── default_rules.yaml
│   ├── redactor.py     # 脱敏器
│   ├── reporter.py     # 报告生成器
│   ├── storage.py      # 安全存储
│   └── github_client.py # GitHub 客户端
├── tests/
├── .github/workflows/
├── pyproject.toml
├── .secret-scanner.yaml
└── README.md
```

## License

MIT
