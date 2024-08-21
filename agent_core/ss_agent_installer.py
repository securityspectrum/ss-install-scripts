import requests
from agent_core.constants import (SS_AGENT_REPO, DOWNLOAD_DIR_LINUX, DOWNLOAD_DIR_WINDOWS, DOWNLOAD_DIR_MACOS, )
import shutil
import platform
import subprocess
from pathlib import Path
import logging
from agent_core.constants import (SS_AGENT_EXECUTABLE_PATH_LINUX, SS_AGENT_EXECUTABLE_PATH_MACOS,
                                  SS_AGENT_EXECUTABLE_PATH_WINDOWS, )

# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

SS_AGENT_ASSET_PATTERNS = {"linux": "ss-agent-linux", "darwin": "ss-agent-darwin", "windows": "ss-agent-win.exe", }


class SSAgentInstaller:

    def __init__(self):
        self.repo = SS_AGENT_REPO

    def get_latest_release_url(self):
        url = f"https://api.github.com/repos/{self.repo}/releases"
        response = requests.get(url)
        response.raise_for_status()
        releases = response.json()
        latest_release = releases[0]  # Assuming the first one is the latest.
        assets = latest_release["assets"]
        return {asset["name"]: asset["browser_download_url"] for asset in assets}

    def categorize_assets(self, assets):
        categorized = {key: [] for key in SS_AGENT_ASSET_PATTERNS}

        for asset_name, url in assets.items():
            for key, pattern in SS_AGENT_ASSET_PATTERNS.items():
                if pattern in asset_name:
                    categorized[key].append((asset_name, url))

        return categorized

    def select_asset(self, categorized_assets):
        system = platform.system().lower()
        logger.info(f"Detected system: {system}")
        if system == "linux":
            return categorized_assets.get("linux")
        elif system == "darwin":
            return categorized_assets.get("darwin")
        elif system == "windows":
            return categorized_assets.get("windows")
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def install(self):
        release_urls = self.get_latest_release_url()
        categorized_assets = self.categorize_assets(release_urls)
        selected_asset = self.select_asset(categorized_assets)

        if not selected_asset:
            raise ValueError("No suitable asset found for your OS/distribution.")

        asset_name, download_url = selected_asset[0]  # Get the first matching asset

        # Determine the appropriate download directory based on the OS
        if platform.system() == "Linux":
            dest_path = DOWNLOAD_DIR_LINUX / asset_name
        elif platform.system() == "Darwin":
            dest_path = DOWNLOAD_DIR_MACOS / asset_name
        elif platform.system() == "Windows":
            dest_path = DOWNLOAD_DIR_WINDOWS / asset_name
        else:
            raise NotImplementedError(f"Unsupported OS: {platform.system()}")

        logger.info(f"Downloading {asset_name} from {download_url}...")
        self.download_binary(download_url, dest_path)

        logger.info(f"Installing {asset_name}...")
        self.run_installation_command(dest_path)

        logger.info("Installation complete.")

    def download_binary(self, download_url, dest_path):
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        with open(dest_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

    def run_installation_command(self, dest_path):
        system = platform.system()

        if system == "Linux":
            final_path = Path(SS_AGENT_EXECUTABLE_PATH_LINUX)
        elif system == "Darwin":
            final_path = Path(SS_AGENT_EXECUTABLE_PATH_MACOS)
        elif system == "Windows":
            final_path = Path(SS_AGENT_EXECUTABLE_PATH_WINDOWS)
            final_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

        # Move the binary to the final location
        try:
            logger.info(f"Moving {dest_path} to {final_path}...")
            shutil.move(str(dest_path), str(final_path))
            logger.info(f"{final_path} has been installed successfully.")
        except Exception as e:
            logger.error(f"Failed to move the file to {final_path}: {e}")
            raise

        # Make the binary executable on Linux and macOS
        if system in ["Linux", "Darwin"]:
            try:
                final_path.chmod(0o755)
                logger.info(f"{final_path} is now executable.")
            except Exception as e:
                logger.error(f"Failed to make the file executable: {e}")
                raise

        # Run the binary with a specific command to verify installation
        try:
            logger.info(f"Running {final_path} to verify installation...")
            result = subprocess.run([str(final_path), "version"], check=True, capture_output=True, text=True)
            logger.info(f"Installed binary version: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Running {final_path} failed: {e}")
            raise
