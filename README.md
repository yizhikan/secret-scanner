# Secret Scanner

扫描代码仓库中的敏感信息 (API Key、密码、Token 等),生成报告并自动脱敏修复。

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
