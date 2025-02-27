import platform
import requests
import logging
import subprocess
import shutil
from pathlib import Path
import os
from agent_core.constants import (
    SS_NETWORK_ANALYZER_REPO,
    SS_NETWORK_ANALYZER_EXECUTABLE_PATH_MACOS,
    SS_NETWORK_ANALYZER_EXECUTABLE_PATH_LINUX,
    SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS,
)

logger = logging.getLogger(__name__)

# Asset patterns
SS_NETWORK_ANALYZER_ASSET_PATTERNS = {
    "linux": "network-analyzer-linux",
    "darwin": "network-analyzer-darwin",
    "windows": "network-analyzer-win.exe",
}


class SSNetworkAnalyzerInstaller:

    def __init__(self):
        self.repo = SS_NETWORK_ANALYZER_REPO

    def get_latest_release_url(self):
        url = f"https://api.github.com/repos/{self.repo}/releases"
        response = requests.get(url)
        response.raise_for_status()
        releases = response.json()
        latest_release = releases[0]  # Assuming the first one is the latest.
        assets = latest_release["assets"]
        return {asset["name"]: asset["browser_download_url"] for asset in assets}

    def categorize_assets(self, assets):
        categorized = {key: [] for key in SS_NETWORK_ANALYZER_ASSET_PATTERNS}

        for asset_name, url in assets.items():
            for key, pattern in SS_NETWORK_ANALYZER_ASSET_PATTERNS.items():
                if pattern in asset_name:
                    categorized[key].append((asset_name, url))

        return categorized

    def select_asset(self, categorized_assets):
        system = platform.system().lower()
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
            dest_path = Path("/tmp") / asset_name
            final_path = Path(SS_NETWORK_ANALYZER_EXECUTABLE_PATH_LINUX)
        elif platform.system() == "Darwin":
            dest_path = Path("/tmp") / asset_name
            final_path = Path(SS_NETWORK_ANALYZER_EXECUTABLE_PATH_MACOS)
        elif platform.system() == "Windows":
            dest_path = Path(r"C:\Temp") / asset_name
            final_path = Path(SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS)
            final_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
        else:
            raise NotImplementedError(f"Unsupported OS: {platform.system()}")

        logger.info(f"Downloading {asset_name} from {download_url}...")
        self.download_binary(download_url, dest_path)

        logger.info(f"Installing {asset_name}...")
        self.run_installation_command(dest_path, final_path)

        logger.info("Installation complete.")

    def download_binary(self, download_url, dest_path):
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        with open(dest_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

    def run_installation_command(self, dest_path, final_path):
        # Move the binary to the final location with elevated privileges
        try:
            logger.info(f"Moving {dest_path} to {final_path}...")

            if platform.system() in ["Linux", "Darwin"]:
                # Use sudo to move the file to a protected directory
                subprocess.run(["sudo", "cp", str(dest_path), str(final_path)], check=True)
                os.remove(str(dest_path))  # Remove the original file if the copy was successful

                # Set the necessary permissions and capabilities
                subprocess.run(["sudo", "chmod", "755", str(final_path)], check=True)

                if platform.system() == "Linux":
                    subprocess.run(["sudo", "setcap", "cap_net_raw,cap_net_admin=eip", str(final_path)], check=True)
                    logger.info(f"Set network capture capabilities on {final_path}.")

            elif platform.system() == "Windows":
                shutil.move(str(dest_path), str(final_path))

            logger.info(f"{final_path} has been installed successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to move the file to {final_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to move the file to {final_path}: {e}")
            raise

        # Verify installation by running the version command of the installed binary
        try:
            logger.info(f"Running '{final_path} version' to verify installation...")
            result = subprocess.run([str(final_path), "-version"], check=True, capture_output=True, text=True)
            logger.info(f"Installed binary version: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Running {final_path} failed: {e}")
            raise
