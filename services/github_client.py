import httpx
from typing import List, Dict, Any, Optional

GITHUB_API = "https://api.github.com"


class GitHubClient:
    """Lightweight GitHub REST client for PR files."""

    def __init__(self, token: Optional[str] = None):
        self.token = token

    async def fetch_pr_files(self, owner: str, repo: str, pr_number: int) -> List[Dict[str, Any]]:
        url = f"{GITHUB_API}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
            headers["X-GitHub-Api-Version"] = "2022-11-28"

        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(url, headers=headers)
            r.raise_for_status()
            data = r.json()
            # data is a list of files with keys like filename, status, additions, deletions, patch, etc.
            return data
