# osquery_installer.py

import os
import sys
import requests
import platform
import logging
from pathlib import Path
import argparse
import shutil
import tarfile
import zipfile
import subprocess

from agent_core.constants import OSQUERY_DOWNLOAD_DIR, OSQUERY_EXTRACT_DIR

try:
    import distro
except ImportError:
    print("The 'distro' package is required. Install it using 'pip install distro'.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

GITHUB_API_URL = "https://api.github.com"
REPO_OWNER = "osquery"
REPO_NAME = "osquery"


class OsqueryInstaller:

    def __init__(self):
        pass

    def get_latest_release(self):
        """
        Fetches the latest release from the specified GitHub repository.
        """
        url = f"{GITHUB_API_URL}/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
        logger.info(f"Fetching latest release from {url}")
        response = requests.get(url)
        if response.status_code != 200:
            logger.error(f"Failed to fetch latest release: {response.status_code} {response.text}")
            sys.exit(1)
        return response.json()

    def group_assets_by_distribution(self, assets):
        """
        Groups release assets by distribution based on their filenames and prints them for validation.
        """
        distributions = {
            'linux': [],
            'windows': [],
            'macos': [],
            'source': []
        }

        for asset in assets:
            name = asset['name']
            download_url = asset['browser_download_url']

            lower_name = name.lower()

            # Debugging print statement to track the filename
            logger.info(f"Processing asset: {name}")

            if 'linux' in lower_name and (lower_name.endswith('.rpm') or lower_name.endswith('.deb') or lower_name.endswith('.tar.gz')):
                distributions['linux'].append({'name': name, 'url': download_url})
            elif 'windows' in lower_name and (lower_name.endswith('.msi') or lower_name.endswith('.exe') or lower_name.endswith('.zip')):
                distributions['windows'].append({'name': name, 'url': download_url})
            elif ('macos' in lower_name or 'darwin' in lower_name or name.endswith('.pkg')):  # Updated this condition
                distributions['macos'].append({'name': name, 'url': download_url})
            elif 'source code' in lower_name or name.endswith('.tar.gz') or name.endswith('.zip'):
                distributions['source'].append({'name': name, 'url': download_url})

        # Print grouped distributions for validation
        for distro, files in distributions.items():
            logger.debug(f"Distribution: {distro}")
            for file in files:
                logger.info(f"  - {file['name']}")

        return distributions

    def detect_os(self):
        """
        Detects the current operating system.
        """
        os_system = platform.system().lower()
        if os_system.startswith('linux'):
            distro_info = distro.id().lower()
            version = distro.major_version()
            logger.info(f"Detected Linux distribution: {distro_info} {version}")
            return 'linux', distro_info, version
        elif os_system.startswith('darwin'):
            logger.info("Detected macOS.")
            return 'macos', None, None
        elif os_system.startswith('windows'):
            logger.info("Detected Windows.")
            return 'windows', None, None
        else:
            logger.error(f"Unsupported operating system: {os_system}")
            sys.exit(1)

    def select_asset(self, distribution_assets):
        """
        Selects the appropriate asset based on the system architecture and OS type.
        For macOS, it prioritizes .pkg files over other formats.
        """
        if not distribution_assets:
            logger.error("No assets found for the detected distribution.")
            sys.exit(1)

        selected_asset = None
        system_arch = platform.machine().lower()

        for asset in distribution_assets:
            name = asset['name'].lower()

            # Prioritize .pkg for macOS
            if 'macos' in name or 'darwin' in name:
                if system_arch in name and name.endswith('.pkg'):
                    selected_asset = asset
                    break
                elif 'x86_64' in name and name.endswith('.pkg'):
                    selected_asset = asset
                elif 'arm64' in name and name.endswith('.pkg'):
                    selected_asset = asset

        # Fallback to other formats if no .pkg is found
        if not selected_asset:
            logger.warning("No .pkg file found for macOS. Falling back to the first available asset.")
            selected_asset = next((asset for asset in distribution_assets if system_arch in asset['name']), distribution_assets[0])

        logger.info(f"Selected asset: {selected_asset['name']}")
        return selected_asset

    def download_asset(self, asset, download_dir):
        """
        Downloads the specified asset to the download directory.
        """
        download_dir = Path(download_dir)
        download_dir.mkdir(parents=True, exist_ok=True)
        file_path = download_dir / asset['name']

        logger.info(f"Downloading {asset['name']} from {asset['url']} to {file_path}")
        with requests.get(asset['url'], stream=True) as r:
            r.raise_for_status()
            with open(file_path, 'wb') as f:
                shutil.copyfileobj(r.raw, f)
        logger.info(f"Downloaded {asset['name']} successfully.")
        return file_path

    def extract_archive(self, file_path, extract_to):
        """
        Extracts the downloaded archive to the specified directory.
        Supports .tar.gz, .zip files.
        Installer packages like .msi or .pkg are not extracted.
        """
        extract_to = Path(extract_to)
        extract_to.mkdir(parents=True, exist_ok=True)

        if file_path.suffixes[-2:] == ['.tar', '.gz'] or file_path.suffix == '.tgz':
            logger.info(f"Extracting {file_path} to {extract_to}")
            with tarfile.open(file_path, 'r:gz') as tar:
                tar.extractall(path=extract_to)
        elif file_path.suffix == '.zip':
            logger.info(f"Extracting {file_path} to {extract_to}")
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(path=extract_to)
        else:
            logger.info(f"No extraction needed for {file_path}")

    def get_installed_version(self, package_name):
        """
        Retrieve the installed version of the specified package on Linux.
        """
        try:
            result = subprocess.run(['rpm', '-q', package_name, '--queryformat', '%{VERSION}'],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    check=True)
            return result.stdout.decode().strip()
        except subprocess.CalledProcessError:
            return None

    def install_osquery(self, file_path):
        """
        Installs osquery based on the downloaded file and OS. For Linux, checks
        if the package is already installed and updates it if necessary.
        """
        system = platform.system().lower()
        file_path = Path(file_path)
        logger.info(f"osquery package : {file_path}")

        try:
            if system == "linux":
                if file_path.suffix == ".rpm":
                    package_name = "osquery"
                    logger.info(f"Checking if {package_name} is already installed...")

                    # Check if osquery is installed
                    installed_version = self.get_installed_version(package_name)

                    if installed_version:
                        # Extract version from the RPM file name
                        rpm_version = file_path.stem.split('-')[1]
                        if installed_version == rpm_version:
                            logger.info(f"{package_name} version {installed_version} is already up-to-date.")
                            return
                        else:
                            logger.info(f"{package_name} is already installed, updating from version {installed_version} to {rpm_version}.")
                            subprocess.run(["sudo", "rpm", "-Uvh", str(file_path)], check=True)
                    else:
                        logger.info(f"{package_name} is not installed, installing the package.")
                        subprocess.run(["sudo", "rpm", "-ivh", str(file_path)], check=True)
                elif file_path.suffix == ".deb":
                    logger.info(f"Installing DEB package: {file_path}")
                    subprocess.run(["sudo", "dpkg", "-i", str(file_path)], check=True)
                    subprocess.run(["sudo", "apt-get", "-f", "install"], check=True)
                else:
                    logger.warning(f"Unsupported Linux package format: {file_path.suffix}")
            elif system == "darwin":
                logger.info(f"file_path.suffix : {file_path.suffix}")
                if file_path.suffix == ".pkg":
                    logger.info(f"Installing PKG package: {file_path}")
                    subprocess.run(["sudo", "installer", "-pkg", str(file_path), "-target", "/"], check=True)
                else:
                    logger.warning(f"Unsupported macOS package format: {file_path.suffix}")
            elif system == "windows":
                if file_path.suffix == ".msi":
                    logger.info(f"Installing MSI package: {file_path}")
                    subprocess.run([str(file_path), "/quiet", "/norestart"], check=True)
                elif file_path.suffix == ".exe":
                    logger.info(f"Running executable installer: {file_path}")
                    subprocess.run([str(file_path), "/S"], check=True)
                else:
                    logger.warning(f"Unsupported Windows package format: {file_path.suffix}")
            else:
                logger.error(f"Unsupported OS for installation: {system}")
                sys.exit(1)
            logger.info("osquery installation completed successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install osquery: {e}")
            sys.exit(1)

    def install(self, download_dir=OSQUERY_DOWNLOAD_DIR, extract_dir=OSQUERY_EXTRACT_DIR):
        """
        Orchestrates the download, extraction, and installation of osquery.
        """
        latest_release = self.get_latest_release()
        assets = latest_release.get('assets', [])

        if not assets:
            logger.error("No assets found in the latest release.")
            sys.exit(1)

        grouped_assets = self.group_assets_by_distribution(assets)

        os_type, distro_info, version = self.detect_os()

        if os_type == 'linux':
            selected_asset = self.select_asset(grouped_assets['linux'], distro_info, version)
        elif os_type == 'macos':
            selected_asset = self.select_asset(grouped_assets['macos'])
        elif os_type == 'windows':
            selected_asset = self.select_asset(grouped_assets['windows'])
        else:
            logger.error(f"Unsupported operating system: {os_type}")
            sys.exit(1)

        downloaded_file = self.download_asset(selected_asset, download_dir)

        # Determine if extraction is needed based on file type
        if downloaded_file.suffix in ['.tar.gz', '.tgz', '.zip']:
            self.extract_archive(downloaded_file, extract_dir)
            # After extraction, find the installer file
            extracted_files = list(Path(extract_dir).rglob('*'))
            installer_file = None
            for f in extracted_files:
                if f.suffix in ['.rpm', '.deb', '.pkg', '.msi', '.exe']:
                    installer_file = f
                    break
            if installer_file:
                self.install_osquery(installer_file)
            else:
                logger.warning("No installer file found after extraction.")
        else:
            # If it's an installer package, install directly
            self.install_osquery(downloaded_file)

        logger.info("osquery setup process completed successfully.")
        logger.info(f"Downloaded files are located in: {Path(download_dir).resolve()}")
        logger.info(f"Extracted files are located in: {Path(extract_dir).resolve()}")

