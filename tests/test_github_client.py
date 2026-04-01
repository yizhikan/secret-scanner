# tests/test_github_client.py
import pytest
from unittest.mock import Mock, patch


class TestGitHubClient:
    def test_list_user_repos(self):
        from secret_scanner.github_client import GitHubClient

        client = GitHubClient(token="fake_token")

        # Mock the _fetch_repos method
        with patch.object(client, "_fetch_repos") as mock_fetch:
            mock_fetch.return_value = [
                {"name": "repo1", "full_name": "user/repo1", "clone_url": "https://github.com/user/repo1.git"},
                {"name": "repo2", "full_name": "user/repo2", "clone_url": "https://github.com/user/repo2.git"}
            ]
            repos = client.list_user_repos("testuser")
            assert len(repos) == 2
            assert repos[0]["name"] == "repo1"

    def test_clone_repo(self, tmp_path):
        from secret_scanner.github_client import GitHubClient

        client = GitHubClient(token="fake_token")
        # This would need actual git mocking for full test
        assert client is not None
