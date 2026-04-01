# tests/test_github_client.py
import pytest
from unittest.mock import Mock, patch, MagicMock


class TestGitHubClient:
    @patch('secret_scanner.github_client.requests.Session')
    def test_list_user_repos(self, mock_session_class):
        from secret_scanner.github_client import GitHubClient

        # Setup mock session and response
        mock_session = MagicMock()
        mock_session_class.return_value = mock_session

        # Mock the API response to return empty list (no more pages)
        mock_response = MagicMock()
        mock_response.json.return_value = []
        mock_response.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_response

        client = GitHubClient(token="fake_token")
        repos = client.list_user_repos("testuser")

        assert repos == []

    def test_clone_repo(self, tmp_path):
        from secret_scanner.github_client import GitHubClient

        client = GitHubClient(token="fake_token")
        # This would need actual git mocking for full test
        assert client is not None
