import os
import platform
import re
import shutil
import sys
import requests
import logging
import subprocess
from pathlib import Path

from agent_core import SystemUtility
from agent_core.constants import (
    FLUENT_BIT_REPO, FLUENT_BIT_ASSET_PATTERNS, FLUENT_BIT_SERVICE_NAME,
    FLUENT_BIT_CONFIG_DIR_CONF_WINDOWS, FLUENT_BIT_EXE_WINDOWS, FLUENT_BIT_SERVICE_MACOS
)

import tempfile
import hashlib
import distro

try:
    import winreg  # For Windows registry access
except ImportError:
    winreg = None  # Not available on non-Windows systems

# Setup logger
from utils.files import get_temp_file_path

logger = logging.getLogger(__name__)

class FluentBitInstaller:

    def __init__(self, logger=None, quiet_install=False):
        self.repo = FLUENT_BIT_REPO
        self.logger = logging.getLogger(__name__)
        self.logger = logger or logging.getLogger(__name__)
        self.quiet_install = quiet_install

    def parse_asset_name(self, asset_name):
        # Check for macOS and Windows first
        if 'intel.pkg' in asset_name:
            return {'distro': 'macos', 'distro_version': '', 'arch': '', 'extension': 'pkg'}
        elif 'win64.exe' in asset_name or 'win64.zip' in asset_name:
            extension = 'exe' if 'exe' in asset_name else 'zip'
            return {'distro': 'windows', 'distro_version': '', 'arch': '', 'extension': extension}
        else:
            # Expected format: fluent-bit-<version>.<distro>-<distro_version>.<arch>.<extension>
            match = re.match(
                r"fluent-bit-\d+\.\d+\.\d+\.(?P<distro>[^.-]+)-(?P<distro_version>[^.-]+)\.(?P<arch>[^.]+)\.(?P<extension>.+)",
                asset_name
            )
            if match:
                return match.groupdict()
            else:
                self.logger.debug(f"Unrecognized asset format: {asset_name}")
                return None

    def get_latest_release_url(self):
        url = f"https://api.github.com/repos/{self.repo}/releases"
        response = requests.get(url)
        response.raise_for_status()
        releases = response.json()
        latest_release = releases[0]  # Assuming the first one is the latest.
        assets = latest_release["assets"]
        return {asset["name"]: asset["browser_download_url"] for asset in assets}

    def categorize_assets(self, assets):
        categorized = {}
        for asset_name, url in assets.items():
            parsed = self.parse_asset_name(asset_name)
            if parsed:
                key = (parsed['distro'], parsed['distro_version'])
                categorized.setdefault(key, []).append((asset_name, url))
        return categorized

    def select_asset(self, categorized_assets):
        system = platform.system().lower()
        self.logger.debug(f"Detected system: {system}")
        if system == "linux":
            distro_name = distro.id().lower()
            version = distro.major_version()
            self.logger.debug(f"Detected distro: {distro_name} {version}")

            assets = None

            if "centos" in distro_name:
                if version == "8":
                    assets = categorized_assets.get(("centos", "8"))
                elif version == "9":
                    assets = categorized_assets.get(("centos", "9"))
            elif "fedora" in distro_name:
                try:
                    version_num = int(version)
                except ValueError:
                    self.logger.error(f"Invalid Fedora version: {version}")
                    return None
                if 28 <= version_num <= 33:
                    # Use CentOS 8 package for older Fedora versions
                    assets = categorized_assets.get(("centos", "8"))
                elif version_num >= 34:
                    # Use CentOS 9 package for newer Fedora versions
                    assets = categorized_assets.get(("centos", "9"))
            elif "debian" in distro_name:
                # Map Debian versions to available packages
                debian_versions = {
                    '10': 'buster',
                    '11': 'bullseye',
                    '12': 'bookworm',
                }
                debian_codename = debian_versions.get(version)
                if debian_codename:
                    assets = categorized_assets.get(("debian", debian_codename))
            elif "ubuntu" in distro_name:
                ubuntu_versions = {
                    '18': '18',
                    '20': '20',
                    '22': '22',
                }
                ubuntu_version = ubuntu_versions.get(version)
                if ubuntu_version:
                    assets = categorized_assets.get(("ubuntu", ubuntu_version))
            else:
                self.logger.error(f"No matching asset found for distro {distro_name} {version}")
                return None

            if assets:
                self.logger.debug(f"Selected assets for {distro_name} {version}: {assets}")
                return assets[0]  # Return the first matching asset
            else:
                self.logger.error(f"No assets found for key corresponding to {distro_name} {version}")
                return None

        elif system == "darwin":
            key = ('macos', '')
            assets = categorized_assets.get(key)
            if assets:
                self.logger.debug(f"Selected assets for macOS: {assets}")
                return assets[0]
            else:
                self.logger.error("No assets found for macOS.")
                return None

        elif system == "windows":
            key = ('windows', '')
            assets = categorized_assets.get(key)
            if assets:
                self.logger.debug(f"Selected assets for Windows: {assets}")
                return assets[0]
            else:
                self.logger.error("No assets found for Windows.")
                return None

        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def install(self):
        try:
            release_urls = self.get_latest_release_url()
            categorized_assets = self.categorize_assets(release_urls)
            if not categorized_assets:
                raise ValueError("No assets found in the github releases.")
            selected_asset = self.select_asset(categorized_assets)

            if not selected_asset:
                raise ValueError("No suitable asset found for your OS/distribution.")

            asset_name, download_url = selected_asset
            self.logger.debug(f"Selected asset: {asset_name} from {download_url}")

            dest_path = get_temp_file_path(asset_name)

            # Check if file already exists
            if os.path.exists(dest_path):
                self.logger.debug(f"File {asset_name} already exists at {dest_path}. Skipping download.")
            else:
                self.logger.debug(f"Downloading {asset_name} from {download_url} to temporary directory...")
                self.download_binary(download_url, dest_path)

            self.logger.debug(f"Installing {asset_name}...")
            self.run_installation_command(dest_path)

            self.logger.debug("Installation complete.")

            # Attempt to delete the file
            try:
                if os.path.exists(dest_path):
                    os.remove(dest_path)
                    self.logger.debug(f"File {dest_path} deleted successfully.")
                else:
                    self.logger.debug(f"File {dest_path} does not exist, no need to delete.")
            except Exception as e:
                self.logger.error(f"Failed to delete the file {dest_path}: {e}")
        except Exception as e:
            self.logger.error(f"An error occurred during the installation process: {e}")
            raise

    def download_binary(self, download_url, dest_path=None):
        # Use a temporary directory if no dest_path is provided
        if dest_path is None:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                dest_path = temp_file.name
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

        self.logger.debug(f"Downloaded file saved to: {dest_path}")
        return dest_path

    def run_installation_command(self, dest_path):
        system = platform.system().lower()
        dest_path = Path(os.path.expanduser(dest_path))
        if system == "linux":
            if dest_path.suffix == ".rpm":
                package_name = "fluent-bit"
                rpm_version = self.extract_rpm_version(dest_path)

                if self.is_package_installed(package_name, rpm_version, package_type='rpm'):
                    self.logger.debug(f"{package_name} version {rpm_version} is already installed. Skipping installation.")
                    return
                elif self.is_newer_version_installed(package_name, rpm_version, package_type='rpm'):
                    self.logger.debug(f"A newer version of {package_name} is installed. Skipping downgrade to version {rpm_version}.")
                    return
                else:
                    self.logger.debug(f"A different version or no version of {package_name} is installed. Updating to version {rpm_version}.")
                    try:
                        subprocess.run(["sudo", "rpm", "--quiet", "-Uvh", str(dest_path)], check=True)
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"RPM installation failed: {e}")
                        raise
            elif dest_path.suffix == ".deb":
                package_name = "fluent-bit"
                deb_version = self.extract_deb_version(dest_path)

                if self.is_package_installed(package_name, deb_version, package_type='deb'):
                    self.logger.debug(f"{package_name} version {deb_version} is already installed. Skipping installation.")
                    return
                elif self.is_newer_version_installed(package_name, deb_version, package_type='deb'):
                    self.logger.debug(f"A newer version of {package_name} is installed. Skipping downgrade to version {deb_version}.")
                    return
                else:
                    self.logger.debug(f"A different version or no version of {package_name} is installed. Updating to version {deb_version}.")
                    try:
                        subprocess.run(["sudo", "dpkg", "-i", str(dest_path)], check=True)
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"DEB installation failed: {e}")
                        raise
        elif system == "darwin":
            try:
                self.logger.debug(f"Installing {dest_path}...")
                subprocess.run(["sudo", "installer", "-pkg", str(dest_path), "-target", "/"], check=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Package installation on macOS failed: {e}")
                raise
        elif system == "windows":
            try:
                if dest_path.suffix == ".exe":
                    subprocess.run([str(dest_path), "/S", "/V"], check=True)
                elif dest_path.suffix == ".msi":
                    subprocess.run(["msiexec", "/i", str(dest_path), "/quiet", "/norestart"], check=True)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Installation on Windows failed: {e}")
                raise
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def extract_rpm_version(self, dest_path):
        """
        Extracts the version number from the RPM filename.

        Expected Filename Format: fluent-bit-<version>.<distro>-<distro_version>.<arch>.rpm
        Example: fluent-bit-3.1.6.centos-9.x86_64.rpm
        """
        stem = dest_path.stem  # e.g., fluent-bit-3.1.6.centos-9.x86_64
        match = re.match(r"fluent-bit-(\d+\.\d+\.\d+)\.[^.]+-\d+\..*", stem)
        if match:
            return match.group(1)
        else:
            self.logger.error(f"Could not extract version from RPM filename: {stem}")
            raise ValueError(f"Could not extract version from RPM filename: {stem}")

    def extract_deb_version(self, dest_path):
        # Try the original underscore-based logic first
        stem = dest_path.stem  # e.g., fluent-bit_3.1.6-1_amd64 or fluent-bit-3.1.6.ubuntu-22.04.amd64
        # Attempt underscore-based parsing
        parts = stem.split('_')
        if len(parts) > 1:
            # Example: fluent-bit_3.1.6-1_amd64
            ver_release = parts[1]  # '3.1.6-1'
            # Validate the version format using regex
            match = re.match(r"(\d+\.\d+\.\d+(-\d+)?)", ver_release)
            if match:
                extracted_version = match.group(1)
                self.logger.debug(f"Extracted version from underscore format: {extracted_version}")
                return extracted_version
            else:
                self.logger.warning(f"Unexpected version format in DEB filename: {ver_release}")

        # Fallback: dash-based parsing
        match = re.match(r"fluent-bit-(\d+\.\d+\.\d+)(?:\.[^.]+)?-\d+\..*", stem)
        if match:
            extracted_version = match.group(1)
            self.logger.debug(f"Extracted version from dash format: {extracted_version}")
            return extracted_version
        else:
            # Fallback to extracting version before first dot after 'fluent-bit-'
            match = re.match(r"fluent-bit-(\d+\.\d+\.\d+)", stem)
            if match:
                extracted_version = match.group(1)
                self.logger.debug(f"Extracted version from fallback regex: {extracted_version}")
                return extracted_version

        # If all parsing attempts fail, raise an error
        self.logger.error(f"Cannot parse the version from DEB filename: {dest_path.name}")
        raise ValueError(f"Cannot parse the version from DEB filename: {dest_path.name}")

    def is_rpm_based_system(self):
        distro_id = distro.id().lower()
        # RPM-based distributions commonly include: fedora, centos, rhel, rocky, almalinux
        return distro_id in ["fedora", "centos", "rhel", "rocky", "almalinux"]

    def is_deb_based_system(self):
        distro_id = distro.id().lower()
        # DEB-based distributions: ubuntu, debian
        return distro_id in ["ubuntu", "debian"]

    def is_package_installed(self, package_name, version, package_type='rpm'):
        """Check if the specific version of a package is already installed."""
        try:
            if package_type == 'rpm':
                # For RPM: Check exact version
                result = subprocess.run(
                    ["rpm", "-q", f"{package_name}-{version}"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                return result.returncode == 0
            else:
                # For DEB: We have the package_name and version. Check dpkg -s
                result = subprocess.run(
                    ["dpkg", "-s", package_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if result.returncode == 0 and "Status: install ok installed" in result.stdout:
                    for line in result.stdout.split('\n'):
                        if line.startswith("Version:"):
                            installed_ver = line.split(':', 1)[1].strip()
                            return installed_ver == version
                return False
        except Exception as e:
            self.logger.error(f"Failed to check installed package version: {e}")
            return False

    def is_different_version_installed(self, package_name, version, package_type='rpm'):
        """Check if a different version of the package is installed."""
        try:
            if package_type == 'rpm':
                result = subprocess.run(
                    ["rpm", "-q", package_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if result.returncode == 0:
                    # rpm -q fluent-bit -> fluent-bit-3.1.6-1.centos9.x86_64
                    parts = result.stdout.strip().split('-')
                    if len(parts) > 2:
                        installed_version = parts[2]  # Extract the version
                        return installed_version != version
                return False
            else:
                # DEB-based
                result = subprocess.run(
                    ["dpkg", "-s", package_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if result.returncode == 0 and "Status: install ok installed" in result.stdout:
                    for line in result.stdout.split('\n'):
                        if line.startswith("Version:"):
                            installed_ver = line.split(':', 1)[1].strip()
                            return installed_ver != version
                return False
        except Exception as e:
            self.logger.error(f"Failed to check installed package version: {e}")
            return False

    def is_newer_version_installed(self, package_name, version, package_type='rpm'):
        """Check if a newer version of the package is installed."""
        try:
            if package_type == 'rpm':
                result = subprocess.run(
                    ["rpm", "-q", package_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if result.returncode == 0:
                    # Extract installed version
                    parts = result.stdout.strip().split('-')
                    if len(parts) > 2:
                        installed_version = parts[2]
                        # Compare versions lexicographically (simple approach)
                        # If installed_version is '3.1.7' and version is '3.1.6', '3.1.7' > '3.1.6' works lexicographically
                        return installed_version > version
                return False
            else:
                # DEB-based
                result = subprocess.run(
                    ["dpkg", "-s", package_name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                if result.returncode == 0 and "Status: install ok installed" in result.stdout:
                    installed_ver = None
                    for line in result.stdout.split('\n'):
                        if line.startswith("Version:"):
                            installed_ver = line.split(':', 1)[1].strip()
                            break
                    if installed_ver:
                        return installed_ver > version
                return False
        except Exception as e:
            self.logger.error(f"Failed to check installed package version: {e}")
            return False

    def enable_and_start(self):
        """
        Configures Fluent Bit based on the operating system and enables/starts the service.
        """
        os_system = platform.system().lower()
        self.logger.debug(f"Detected operating system: {os_system}")

        try:
            if os_system == 'linux':
                self.configure_linux()
            elif os_system == 'darwin':
                self.configure_macos()
            elif os_system == 'windows':
                self.configure_windows()
            else:
                self.logger.error(f"Unsupported operating system: {os_system}")
                raise NotImplementedError("This installation script does not support the detected OS.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
            self.logger.error(f"Error output: {e.stderr}")
            raise
        except Exception as ex:
            self.logger.error(f"An unexpected error occurred: {ex}")
            raise

        self.logger.debug("Fluent Bit configuration and service start completed.")

    def configure_linux(self):
        try:
            # Log enabling Fluent Bit to start on boot
            self.logger.debug("Enabling Fluent Bit service to start automatically on boot...")

            # Enable Fluent Bit on boot
            result = subprocess.run(['sudo', 'systemctl', 'enable', FLUENT_BIT_SERVICE_NAME],
                                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.debug(f"Enable command output: {result.stdout.strip()}")
            self.logger.debug(f"Fluent Bit service enabled successfully.")

            # Log starting Fluent Bit service
            self.logger.debug("Starting Fluent Bit service...")

            # Start Fluent Bit service
            result = subprocess.run(['sudo', 'systemctl', 'start', FLUENT_BIT_SERVICE_NAME],
                                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.debug(f"Start command output: {result.stdout.strip()}")
            self.logger.debug("Fluent Bit service started successfully.")

        except subprocess.CalledProcessError as e:
            # Log the error details
            self.logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
            self.logger.error(f"Error output: {e.stderr.strip() if e.stderr else 'No error output'}")
            raise

        except Exception as ex:
            # Log any unexpected error
            self.logger.error(f"An unexpected error occurred: {ex}")
            raise

    def configure_macos(self):
        try:
            # Log loading the Fluent Bit service
            self.logger.debug("Loading Fluent Bit service plist...")

            # Load the Fluent Bit service plist
            result = subprocess.run(['sudo', 'launchctl', 'load', FLUENT_BIT_SERVICE_MACOS],
                                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.debug(f"Load command output: {result.stdout.strip()}")
            self.logger.debug("Fluent Bit service loaded successfully.")

            # Log enabling Fluent Bit service for automatic start
            self.logger.debug("Enabling Fluent Bit service to start automatically on boot...")

            # Enable Fluent Bit service to start automatically
            result = subprocess.run(['sudo', 'launchctl', 'enable', 'system/fluent-bit.plist'],
                                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.debug(f"Enable command output: {result.stdout.strip()}")
            self.logger.debug("Fluent Bit service enabled successfully.")

        except subprocess.CalledProcessError as e:
            # Log the error details
            self.logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
            self.logger.error(f"Error output: {e.stderr.strip() if e.stderr else 'No error output'}")
            raise

        except Exception as ex:
            # Log any unexpected error
            self.logger.error(f"An unexpected error occurred: {ex}")
            raise

    def configure_windows(self):

        SystemUtility.request_admin_access()

        # Verify that the Fluent Bit executable exists
        if not Path(FLUENT_BIT_EXE_WINDOWS).exists():
            self.logger.error(f"Fluent Bit executable not found at: {FLUENT_BIT_EXE_WINDOWS}. Please verify the installation path.")
            raise FileNotFoundError(f"Fluent Bit executable not found at {FLUENT_BIT_EXE_WINDOWS}")

        try:
            # Step 1: Check if the service exists
            self.logger.debug(f"Checking if the '{FLUENT_BIT_SERVICE_NAME}' service exists...")
            result = subprocess.run(
                ['sc.exe', 'query', FLUENT_BIT_SERVICE_NAME],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            service_exists = 'SERVICE_NAME: ' + FLUENT_BIT_SERVICE_NAME in result.stdout

            # Step 2: Create the service if it doesn't exist
            if not service_exists:
                self.logger.debug(f"Service '{FLUENT_BIT_SERVICE_NAME}' not found. Creating the service...")
                create_command = [
                    'sc.exe', 'create', FLUENT_BIT_SERVICE_NAME,
                    'binPath=', f'"{FLUENT_BIT_EXE_WINDOWS}" -c "{FLUENT_BIT_CONFIG_DIR_CONF_WINDOWS}"',
                    'start=', 'auto',
                    'obj=', 'LocalSystem'
                ]
                self.logger.debug(f"Creating service with command: {' '.join(create_command)}")
                subprocess.run(create_command, check=True)
                self.logger.info(f"Service '{FLUENT_BIT_SERVICE_NAME}' created successfully.")
            else:
                self.logger.debug(f"Service '{FLUENT_BIT_SERVICE_NAME}' already exists.")

            # Step 3: Ensure the service uses the LocalSystem account and auto-starts on boot
            self.logger.debug(f"Configuring service '{FLUENT_BIT_SERVICE_NAME}' to start with LocalSystem and auto-start on boot...")
            config_command = ['sc.exe', 'config', FLUENT_BIT_SERVICE_NAME, 'obj=', 'LocalSystem', 'start=', 'auto']
            subprocess.run(config_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.logger.info(f"Service '{FLUENT_BIT_SERVICE_NAME}' configured successfully.")

            # Step 4: Check the service status before attempting to start it
            self.logger.debug(f"Checking the status of service '{FLUENT_BIT_SERVICE_NAME}' before starting...")
            query_result = subprocess.run(
                ['sc.exe', 'query', FLUENT_BIT_SERVICE_NAME],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if "RUNNING" in query_result.stdout:
                self.logger.info(f"Service '{FLUENT_BIT_SERVICE_NAME}' is already running. No need to start it.")
            else:
                # Step 5: Start the service if not already running
                self.logger.debug(f"Starting service '{FLUENT_BIT_SERVICE_NAME}'...")
                start_result = subprocess.run(
                    ['sc.exe', 'start', FLUENT_BIT_SERVICE_NAME],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.logger.info(f"Service '{FLUENT_BIT_SERVICE_NAME}' started successfully.")

        except subprocess.CalledProcessError as e:
            if e.returncode == 1056:
                self.logger.warning(f"Service '{FLUENT_BIT_SERVICE_NAME}' is already running. Skipping start.")
            else:
                self.logger.error(f"Command '{' '.join(e.cmd)}' failed with exit status {e.returncode}")
                self.logger.error(f"stdout: {e.stdout.strip()}")
                self.logger.error(f"stderr: {e.stderr.strip() if e.stderr else 'No error output'}")
                raise
        except Exception as ex:
            self.logger.error(f"An unexpected error occurred: {ex}")
            raise

    def stop_and_delete_windows_service(self):

        os_system = platform.system().lower()
        if os_system != 'windows':
            self.logger.warning("The stop_and_delete_windows_service method is intended for Windows platforms.")
            return

        SystemUtility.request_admin_access()

        try:
            self.logger.debug(f"Checking if the '{FLUENT_BIT_SERVICE_NAME}' service exists before stopping and deleting...")
            result = subprocess.run(['sc.exe', 'query', FLUENT_BIT_SERVICE_NAME],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True)
            service_exists = 'SERVICE_NAME: ' + FLUENT_BIT_SERVICE_NAME in result.stdout

            if not service_exists:
                self.logger.warning(f"Service '{FLUENT_BIT_SERVICE_NAME}' not found. Nothing to stop or delete.")
                return

            # Stop the service if it's running
            self.logger.debug(f"Checking if the '{FLUENT_BIT_SERVICE_NAME}' service is running...")
            if "RUNNING" in result.stdout:
                self.logger.debug(f"Service '{FLUENT_BIT_SERVICE_NAME}' is running. Attempting to stop it...")
                stop_command = ['sc.exe', 'stop', FLUENT_BIT_SERVICE_NAME]
                stop_result = subprocess.run(stop_command,
                                             check=True,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             text=True)
                self.logger.info(f"Service '{FLUENT_BIT_SERVICE_NAME}' stopped successfully.")
            else:
                self.logger.info(f"Service '{FLUENT_BIT_SERVICE_NAME}' is not running.")

            # Delete the service
            self.logger.debug(f"Deleting service '{FLUENT_BIT_SERVICE_NAME}'...")
            delete_command = ['sc.exe', 'delete', FLUENT_BIT_SERVICE_NAME]
            delete_result = subprocess.run(delete_command,
                                           check=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           text=True)
            self.logger.info(f"Service '{FLUENT_BIT_SERVICE_NAME}' deleted successfully.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command '{' '.join(e.cmd)}' failed with exit status {e.returncode}")
            self.logger.error(f"stdout: {e.stdout.strip()}")
            self.logger.error(f"stderr: {e.stderr.strip() if e.stderr else 'No error output'}")
            raise
        except Exception as ex:
            self.logger.error(f"An unexpected error occurred: {ex}")
            raise

    def verify_permissions(self, path):
        """
        Verifies that SYSTEM has full control over the provided path (Windows only).
        If not, attempts to fix the permissions.
        """
        self.logger.debug(f"Verifying permissions for SYSTEM on {path}...")

        try:
            result = subprocess.run(
                ['icacls', path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )

            if 'SYSTEM:(F)' not in result.stdout:
                self.logger.error(f"SYSTEM does not have full control on {path}. Attempting to fix permissions...")

                fix_permissions_command = ['icacls', path, '/grant', 'SYSTEM:F']
                fix_result = subprocess.run(fix_permissions_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True, check=True)

                self.logger.debug(f"Fix permissions command output: {fix_result.stdout.strip()}")

                # Re-check permissions after attempting to fix
                result = subprocess.run(
                    ['icacls', path],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
                if 'SYSTEM:(F)' not in result.stdout:
                    self.logger.error(f"Failed to grant SYSTEM full control on {path}.")
                    raise PermissionError(f"Failed to grant SYSTEM full control on {path}.")
                else:
                    self.logger.info(f"SYSTEM was successfully granted full control on {path}.")

            self.logger.info(f"SYSTEM has full control over {path}.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to check or fix permissions for {path} using icacls.")
            self.logger.error(f"stdout: {e.stdout.strip()}")
            self.logger.error(f"stderr: {e.stderr.strip() if e.stderr else 'No error output'}")
            raise
        except Exception as ex:
            self.logger.error(f"An unexpected error occurred while checking or fixing permissions: {ex}")
            raise

    def uninstall(self):
        self.logger.debug("Uninstalling Fluent Bit...")
        system = platform.system().lower()

        if system == "linux":
            self.uninstall_linux()
        elif system == "darwin":
            self.uninstall_macos()
        elif system == "windows":
            self.stop_and_delete_windows_service()
            self.uninstall_windows()
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def uninstall_linux(self):
        package_name = "fluent-bit"
        distro_id = distro.id().lower()
        self.logger.debug(f"Detected Linux distribution: {distro_id}")

        try:
            if distro_id in ["ubuntu", "debian"]:
                self.uninstall_with_apt(package_name)
            elif distro_id in ["fedora", "centos", "rhel", "rocky", "almalinux"]:
                self.uninstall_with_dnf_yum(package_name, distro_id)
            else:
                self.logger.warning(f"Unsupported or unrecognized Linux distribution: {distro_id}. Attempting to use rpm or dpkg directly.")
                self.uninstall_with_rpm_or_dpkg(package_name)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall Fluent Bit: {e}")
            raise

    def uninstall_with_apt(self, package_name):
        self.logger.debug(f"Using apt to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", "apt-get", "remove", "--purge", "-y", package_name], check=True)
            subprocess.run(["sudo", "apt-get", "autoremove", "-y"], check=True)
            self.logger.debug(f"Fluent Bit has been successfully uninstalled using apt.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"apt failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_dnf_yum(self, package_name, distro_id):
        package_manager = "dnf" if distro_id in ["fedora", "rocky", "almalinux"] else "yum"
        self.logger.debug(f"Using {package_manager} to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", package_manager, "remove", "-y", package_name], check=True)
            self.logger.debug(f"Fluent Bit has been successfully uninstalled using {package_manager}.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"{package_manager} failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_rpm_or_dpkg(self, package_name):
        if Path('/usr/bin/dpkg').exists() or Path('/bin/dpkg').exists():
            self.logger.debug(f"Using dpkg to purge {package_name}...")
            subprocess.run(["sudo", "dpkg", "--purge", package_name], check=True)
        elif Path('/usr/bin/rpm').exists() or Path('/bin/rpm').exists():
            self.logger.debug(f"Using rpm to erase {package_name}...")
            subprocess.run(["sudo", "rpm", "-e", package_name], check=True)
        else:
            self.logger.error("Neither dpkg nor rpm package managers are available on this system.")
            raise EnvironmentError("No suitable package manager found for uninstallation.")

        self.logger.debug(f"Fluent Bit has been successfully uninstalled using rpm/dpkg.")

    def uninstall_macos(self):
        """
        Uninstall Fluent Bit from macOS.
        """
        self.logger.debug("Starting Fluent Bit uninstallation process on macOS.")

        try:
            # Step 1: Unload LaunchDaemon
            self.unload_launchdaemon()

            # Step 2: Remove LaunchDaemon plist
            self.remove_launchdaemon_plist()

            # Step 3: Remove installed files and directories
            self.remove_installed_paths()

            # Step 4: Remove package receipt
            self.forget_package_receipt()

            self.logger.info("Fluent Bit has been successfully uninstalled from macOS.")
        except Exception as e:
            self.logger.error(f"Fluent Bit uninstallation failed: {e}")
            raise RuntimeError("Fluent Bit uninstallation failed. Manual intervention may be required.") from e

    def unload_launchdaemon(self):
        """
        Unload the Fluent Bit LaunchDaemon if it exists.
        """
        launch_daemon = FLUENT_BIT_SERVICE_MACOS
        if Path(launch_daemon).exists():
            try:
                self.logger.debug(f"Attempting to unload LaunchDaemon: {launch_daemon}")
                result = subprocess.run(
                    ["sudo", "launchctl", "unload", launch_daemon],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.logger.debug(f"Unload command output: {result.stdout.strip()}")
                self.logger.info(f"Unloaded LaunchDaemon: {launch_daemon}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to unload LaunchDaemon {launch_daemon}: {e.stderr.strip()}")
                raise RuntimeError(f"Failed to unload LaunchDaemon {launch_daemon}: {e.stderr.strip()}") from e
        else:
            self.logger.debug(f"LaunchDaemon plist does not exist, skipping: {launch_daemon}")

    def remove_launchdaemon_plist(self):
        """
        Remove the Fluent Bit LaunchDaemon plist file.
        """
        launch_daemon = FLUENT_BIT_SERVICE_MACOS
        path = Path(launch_daemon)
        if path.exists():
            try:
                self.logger.debug(f"Attempting to remove LaunchDaemon plist: {launch_daemon}")
                result = subprocess.run(
                    ["sudo", "rm", "-f", launch_daemon],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.logger.debug(f"Remove command output: {result.stdout.strip()}")
                self.logger.info(f"Removed LaunchDaemon plist: {launch_daemon}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to remove plist {launch_daemon}: {e.stderr.strip()}")
                raise RuntimeError(f"Failed to remove plist {launch_daemon}: {e.stderr.strip()}") from e
        else:
            self.logger.debug(f"LaunchDaemon plist does not exist, skipping: {launch_daemon}")

    def remove_installed_paths(self):
        """
        Remove Fluent Bit installed files and directories.
        """
        installed_paths = [
            "/opt/fluent-bit/bin/fluent-bit",
            "/opt/fluent-bit",
            "/usr/local/bin/fluent-bit",
            "/usr/local/etc/fluent-bit",
            "/usr/local/var/log/fluent-bit",
            "/usr/local/opt/fluent-bit",
        ]

        for path_str in installed_paths:
            path = Path(path_str)
            if path.exists():
                if path.is_file() or path.is_symlink():
                    try:
                        self.logger.debug(f"Attempting to remove file: {path}")
                        result = subprocess.run(
                            ["sudo", "rm", "-f", path_str],
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        self.logger.debug(f"Remove file command output: {result.stdout.strip()}")
                        self.logger.info(f"Removed file: {path}")
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"Failed to remove file {path}: {e.stderr.strip()}")
                        raise RuntimeError(f"Failed to remove file {path}: {e.stderr.strip()}") from e
                elif path.is_dir():
                    try:
                        self.logger.debug(f"Attempting to remove directory: {path}")
                        result = subprocess.run(
                            ["sudo", "rm", "-rf", path_str],
                            check=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True
                        )
                        self.logger.debug(f"Remove directory command output: {result.stdout.strip()}")
                        self.logger.info(f"Removed directory: {path}")
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"Failed to remove directory {path}: {e.stderr.strip()}")
                        raise RuntimeError(f"Failed to remove directory {path}: {e.stderr.strip()}") from e
            else:
                self.logger.debug(f"Path does not exist, skipping: {path}")

    def forget_package_receipt(self):
        """
        Remove the package receipt using pkgutil.
        """
        package_id = self.get_macos_package_id()
        if package_id:
            try:
                self.logger.debug(f"Found Fluent Bit package ID: {package_id}. Removing package receipt...")
                result = subprocess.run(
                    ["sudo", "pkgutil", "--forget", package_id],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                self.logger.debug(f"Forget package receipt command output: {result.stdout.strip()}")
                self.logger.info(f"Package receipt removed: {package_id}")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to remove package receipt {package_id}: {e.stderr.strip()}")
                raise RuntimeError(f"Failed to remove package receipt {package_id}: {e.stderr.strip()}") from e
        else:
            self.logger.warning("Fluent Bit package ID not found. Skipping pkgutil --forget step.")

    def get_macos_package_id(self):
        """
        Retrieves the Fluent Bit package identifier using pkgutil.
        Assumes the package ID contains 'fluent-bit'.
        """
        try:
            result = subprocess.run(
                ["pkgutil", "--pkgs"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            packages = result.stdout.splitlines()
            for pkg in packages:
                if "fluent-bit" in pkg.lower():
                    self.logger.debug(f"Identified Fluent Bit package ID: {pkg}")
                    return pkg
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to list packages with pkgutil: {e.stderr.strip()}")
        return None

    def uninstall_windows(self):
        self.logger.debug("Attempting to uninstall Fluent Bit on Windows...")
        if not winreg:
            self.logger.error("winreg module is not available. Uninstallation cannot proceed on Windows.")
            return

        try:
            uninstall_command = self.get_windows_uninstall_command("Fluent Bit")
            if uninstall_command:
                self.logger.debug(f"Found uninstall command: {uninstall_command}. Executing...")
                # Determine if it's an MSI or EXE installer
                if "msiexec" in uninstall_command.lower():
                    # Extract the product code
                    parts = uninstall_command.split()
                    product_code = None
                    for part in parts:
                        if part.startswith("{") and part.endswith("}"):
                            product_code = part
                            break
                    if product_code:
                        uninstall_cmd = ["msiexec", "/x", product_code, "/quiet", "/norestart"]
                        self.logger.debug(f"Running MSI uninstall command: {' '.join(uninstall_cmd)}")
                        subprocess.run(uninstall_cmd, check=True)
                    else:
                        self.logger.error("Product code not found in uninstall command.")
                        return
                else:
                    # Assume it's an EXE with silent uninstall flags
                    uninstall_cmd = uninstall_command.split()
                    if not any(flag in uninstall_cmd for flag in ["/S", "/silent", "/quiet"]):
                        uninstall_cmd.append("/S")
                    self.logger.debug(f"Running EXE uninstall command: {' '.join(uninstall_cmd)}")
                    subprocess.run(uninstall_cmd, check=True)
                self.logger.debug("Fluent Bit has been successfully uninstalled from Windows.")
            else:
                self.logger.warning("Uninstall command for Fluent Bit not found in the registry.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall Fluent Bit on Windows: {e}")
            raise
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during Fluent Bit uninstallation on Windows: {e}")
            raise

    def get_windows_uninstall_command(self, product_name):
        """
        Searches the Windows Registry for the uninstall command of the given product.
        """
        uninstall_subkeys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
        ]

        for root in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for subkey in uninstall_subkeys:
                try:
                    registry_key = winreg.OpenKey(root, subkey)
                except FileNotFoundError:
                    continue

                for i in range(0, winreg.QueryInfoKey(registry_key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(registry_key, i)
                        subkey_path = f"{subkey}\\{subkey_name}"
                        with winreg.OpenKey(root, subkey_path) as key:
                            display_name = winreg.QueryValueEx(key, "DisplayName")[0]
                            if product_name.lower() in display_name.lower():
                                uninstall_string = winreg.QueryValueEx(key, "UninstallString")[0]
                                return uninstall_string
                    except FileNotFoundError:
                        continue
                    except Exception as e:
                        self.logger.error(f"Error accessing registry key: {e}")
                        continue
        return None

    def get_installed_version(self, package_name):
        """Returns the installed version of a package or None if not installed."""
        system = platform.system().lower()
        try:
            if system == "linux":
                # Check DEB first
                if Path('/usr/bin/dpkg').exists() or Path('/bin/dpkg').exists():
                    result = subprocess.run(
                        ["dpkg", "-s", package_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    if result.returncode == 0 and "Status: install ok installed" in result.stdout:
                        for line in result.stdout.split('\n'):
                            if line.startswith("Version:"):
                                return line.split(':')[1].strip()
                # Check RPM if not DEB-based
                elif Path('/usr/bin/rpm').exists() or Path('/bin/rpm').exists():
                    result = subprocess.run(
                        ["rpm", "-q", package_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    if result.returncode == 0:
                        # Output like 'fluent-bit-1.7.4-2.el8.x86_64'
                        parts = result.stdout.strip().split('-')
                        if len(parts) > 2:
                            # version is parts[2]
                            return parts[2]
            elif system == "darwin":
                # Implement version retrieval for macOS if needed
                pass
            elif system == "windows":
                # Implement version retrieval for Windows if needed
                pass
        except Exception as e:
            self.logger.error(f"Failed to check installed package version: {e}")
        return None
