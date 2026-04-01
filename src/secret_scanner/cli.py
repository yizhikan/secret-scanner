"""Command-line interface for Secret Scanner."""
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
