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

    def _fetch_repos(self, username: str, page: int) -> List[Dict]:
        """Fetch a single page of repos for a user."""
        url = f"https://api.github.com/users/{username}/repos"
        params = {"page": page, "per_page": 100}
        response = self.session.get(url, params=params)
        response.raise_for_status()
        return response.json()

    def list_user_repos(self, username: str) -> List[Dict]:
        """List all repositories for a user."""
        repos = []
        page = 1

        while True:
            page_repos = self._fetch_repos(username, page)
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
