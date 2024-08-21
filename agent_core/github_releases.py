import requests
import logging

logger = logging.getLogger('InstallationLogger')

class GitHubReleases:
    def __init__(self, repo):
        self.repo = repo

    def get_latest_release_url(self):
        url = f"https://api.github.com/repos/{self.repo}/releases"
        logger.debug(f"Fetching latest release from {url}")
        response = requests.get(url)
        response.raise_for_status()
        releases = response.json()
        latest_release = releases[0]  # Assuming the first one is the latest. Adjust if necessary.
        assets = latest_release["assets"]
        logger.debug(f"Latest release assets: {assets}")
        return {asset["name"]: asset["browser_download_url"] for asset in assets}
