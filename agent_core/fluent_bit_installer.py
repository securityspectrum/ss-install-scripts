import os
import platform
import requests
import logging
import tempfile
import subprocess
from pathlib import Path
from agent_core.constants import (
    FLUENT_BIT_REPO,
    FLUENT_BIT_ASSET_PATTERNS,
    DOWNLOAD_DIR_LINUX,
    DOWNLOAD_DIR_WINDOWS,
    DOWNLOAD_DIR_MACOS,
)
import distro

# Setup logger
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class FluentBitInstaller:

    def __init__(self):
        self.repo = FLUENT_BIT_REPO

    def get_latest_release_url(self):
        url = f"https://api.github.com/repos/{self.repo}/releases"
        response = requests.get(url)
        response.raise_for_status()
        releases = response.json()
        latest_release = releases[0]  # Assuming the first one is the latest.
        assets = latest_release["assets"]
        return {asset["name"]: asset["browser_download_url"] for asset in assets}

    def categorize_assets(self, assets):
        categorized = {key: [] for key in FLUENT_BIT_ASSET_PATTERNS}

        for asset_name, url in assets.items():
            for key, pattern in FLUENT_BIT_ASSET_PATTERNS.items():
                if pattern in asset_name:
                    categorized[key].append((asset_name, url))

        return categorized

    def select_asset(self, categorized_assets):
        system = platform.system().lower()
        logger.info(f"Detected system: {system}")
        if system == "linux":
            distro_name = distro.id().lower()
            version = distro.major_version()
            logger.info(f"Detected distro: {distro_name} {version}")
            if "centos" in distro_name:
                if version == "8":
                    return categorized_assets.get("centos8")
                elif version == "9":
                    return categorized_assets.get("centos9")
            elif "fedora" in distro_name:
                version = int(version)
                if 28 <= version <= 33:
                    return categorized_assets.get("centos8")
                elif version >= 34:
                    return categorized_assets.get("centos9")
            elif "debian" in distro_name:
                return categorized_assets.get("debian")
            elif "ubuntu" in distro_name:
                if version == "18":
                    return categorized_assets.get("ubuntu_18.04")
                elif version == "22":
                    return categorized_assets.get("ubuntu_22.04")
        elif system == "darwin":
            return categorized_assets.get("macos")
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

    def download_binary(self, download_url, dest_path=None):
        # Use /var/tmp/ if no dest_path is provided
        if dest_path is None:
            temp_dir = tempfile.gettempdir()
            dest_path = os.path.join(temp_dir, os.path.basename(download_url))
        else:
            # Expand the ~ to the user's home directory
            dest_path = os.path.expanduser(dest_path)

        # Download the file
        response = requests.get(download_url, stream=True)
        response.raise_for_status()

        # Write the file in chunks
        with open(dest_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        logger.info(f"Downloaded file saved to: {dest_path}")
        return dest_path

    def run_installation_command(self, dest_path):
        system = platform.system()
        dest_path = Path(os.path.expanduser(dest_path))
        if system == "Linux":
            if dest_path.suffix == ".rpm":
                package_name = "fluent-bit"
                rpm_version = self.extract_rpm_version(dest_path)

                if self.is_package_installed(package_name, rpm_version):
                    logger.info(f"{package_name} version {rpm_version} is already installed. Skipping installation.")
                    return
                elif self.is_newer_version_installed(package_name, rpm_version):
                    logger.info(f"A newer version of {package_name} is installed. Skipping downgrade to version {rpm_version}.")
                    return
                else:
                    logger.info(f"A different version of {package_name} is installed. Updating to version {rpm_version}.")
                    try:
                        subprocess.run(["sudo", "rpm", "-Uvh", str(dest_path)], check=True)
                    except subprocess.CalledProcessError as e:
                        logger.error(f"RPM installation failed: {e}")
                        raise
            elif dest_path.suffix == ".deb":
                package_name = "fluent-bit"
                deb_version = self.extract_deb_version(dest_path)

                if self.is_package_installed(package_name, deb_version):
                    logger.info(f"{package_name} version {deb_version} is already installed. Skipping installation.")
                    return
                elif self.is_newer_version_installed(package_name, deb_version):
                    logger.info(f"A newer version of {package_name} is installed. Skipping downgrade to version {deb_version}.")
                    return
                else:
                    logger.info(f"A different version of {package_name} is installed. Updating to version {deb_version}.")
                    try:
                        subprocess.run(["sudo", "dpkg", "-i", str(dest_path)], check=True)
                    except subprocess.CalledProcessError as e:
                        logger.error(f"DEB installation failed: {e}")
                        raise
        elif system == "Darwin":
            try:
                logger.info(f"Installing {dest_path}...")
                subprocess.run(["sudo", "installer", "-pkg", str(dest_path), "-target", "/"], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Package installation on macOS failed: {e}")
                raise
        elif system == "Windows":
            try:
                if dest_path.suffix == ".exe":
                    subprocess.run([str(dest_path), "/S", "/V"], check=True)
                elif dest_path.suffix == ".msi":
                    subprocess.run(["msiexec", "/i", str(dest_path), "/quiet", "/norestart"], check=True)
            except subprocess.CalledProcessError as e:
                logger.error(f"Installation on Windows failed: {e}")
                raise
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def extract_rpm_version(self, dest_path):
        """Extract the version from the RPM filename."""
        # Assuming the version is in the filename like fluent-bit-3.1.6-1.centos9.x86_64.rpm
        return dest_path.stem.split('-')[2]  # Extracts '3.1.6' from 'fluent-bit-3.1.6-1.centos9.x86_64'

    def extract_deb_version(self, dest_path):
        """Extract the version from the DEB filename."""
        # Assuming the version is in the filename like fluent-bit_3.1.6-1_amd64.deb
        return dest_path.stem.split('_')[1]  # Extracts '3.1.6-1' from 'fluent-bit_3.1.6-1_amd64'

    def is_package_installed(self, package_name, version):
        """Check if the specific version of a package is already installed."""
        try:
            result = subprocess.run(
                ["rpm", "-q", f"{package_name}-{version}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            return result.returncode == 0
        except Exception as e:
            logger.error(f"Failed to check installed package version: {e}")
            return False

    def is_different_version_installed(self, package_name, version):
        """Check if a different version of the package is installed."""
        try:
            result = subprocess.run(
                ["rpm", "-q", package_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                installed_version = result.stdout.strip().split('-')[-2]
                logger.info(f"Installed version of {package_name}: {installed_version}")
                return installed_version != version
            else:
                return False
        except Exception as e:
            logger.error(f"Failed to check installed package version: {e}")
            return False

    def is_newer_version_installed(self, package_name, version):
        """Check if a newer version of the package is installed."""
        try:
            result = subprocess.run(
                ["rpm", "-q", package_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                installed_version = result.stdout.strip().split('-')[-2]
                logger.info(f"Installed version of {package_name}: {installed_version}")
                return installed_version > version
            else:
                return False
        except Exception as e:
            logger.error(f"Failed to check installed package version: {e}")
            return False
