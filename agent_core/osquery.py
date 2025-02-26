# osquery_installer.py
import json
import os
import sys
import tempfile
import time

import distro
import requests
import platform
import logging
from pathlib import Path
import argparse
import shutil
import tarfile
import zipfile
import subprocess

from agent_core.constants import OSQUERY_DOWNLOAD_DIR, OSQUERY_EXTRACT_DIR, OSQUERY_CONFIG_PATH_MACOS, \
    OSQUERY_CONFIG_PATH_LINUX, OSQUERY_LOGGER_PATH_WINDOWS, OSQUERY_PIDFILE_PATH_WINDOWS, OSQUERY_DATABASE_PATH_WINDOWS, \
    OSQUERY_CONFIG_EXAMPLE_PATH_LINUX, OSQUERY_CONFIG_EXAMPLE_PATH_MACOS, OSQUERY_CONFIG_PATH_WINDOWS, \
    OSQUERY_CONFIG_EXAMPLE_PATH_WINDOWS, SS_AGENT_SERVICE_NAME, OSQUERY_SERVICE_NAME, OSQUERY_PRODUCT_NAME

try:
    import winreg  # For Windows registry access
except ImportError:
    winreg = None  # Not available on non-Windows systems


# Configure logging
logger = logging.getLogger("InstallationLogger")
quiet_install = (logger.getEffectiveLevel() > logging.DEBUG)

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
        logger.debug(f"Fetching latest release from {url}")
        response = requests.get(url)
        if response.status_code != 200:
            logger.error(f"Failed to fetch latest release: {response.status_code} {response.text}")
            sys.exit(1)
        return response.json()

    def group_assets_by_distribution(self, assets):
        """
        Groups release assets by distribution and package type.
        Differentiates between main packages.

        Args:
            assets (list): List of asset dictionaries from the latest release.

        Returns:
            dict: A dictionary with distribution types as keys and lists of assets as values.
                  Each distribution type contains a list for main packages.
        """
        distributions = {
            'linux': {'main': []},
            'windows': {'main': []},
            'macos': {'main': []},
            'source': []
        }

        for asset in assets:
            name = asset['name']
            download_url = asset['browser_download_url']
            lower_name = name.lower()

            # Debugging print statement to track the filename
            logger.debug(f"Processing asset: {name}")

            # Skip debug symbol and debuginfo packages entirely
            if '-dbgsym' in lower_name or '-dbg' in lower_name or '-debuginfo' in lower_name:
                logger.debug(f"Skipping debug/debuginfo package: {name}")
                continue

            # Linux main packages
            if 'linux' in lower_name and (
                    lower_name.endswith('.rpm') or lower_name.endswith('.deb') or lower_name.endswith('.tar.gz')
            ):
                distributions['linux']['main'].append({'name': name, 'url': download_url})
                logger.debug(f"Asset {name} added to Linux main group.")
            # Windows main packages
            elif 'windows' in lower_name or name.endswith('.msi') or name.endswith('.exe'):
                distributions['windows']['main'].append({'name': name, 'url': download_url})
                logger.debug(f"Asset {name} added to Windows main group.")
            # macOS main packages
            elif 'macos' in lower_name or 'darwin' in lower_name or name.endswith('.pkg') or name.endswith('.dmg'):
                distributions['macos']['main'].append({'name': name, 'url': download_url})
                logger.debug(f"Asset {name} added to macOS main group.")
            # Source code files
            elif 'source code' in lower_name:
                distributions['source'].append({'name': name, 'url': download_url})
                logger.debug(f"Asset {name} added to Source group.")
            else:
                # If it's a .tar.gz or .zip file and hasn't matched yet, consider it source code
                if name.endswith('.tar.gz') or name.endswith('.zip'):
                    distributions['source'].append({'name': name, 'url': download_url})
                    logger.debug(f"Asset {name} added to Source group.")
                else:
                    logger.debug(f"Asset {name} did not match any category and was skipped.")

        # Print grouped distributions for validation
        for distro, files in distributions.items():
            logger.debug(f"Distribution: {distro}")
            if isinstance(files, dict):
                for pkg_type, pkg_files in files.items():
                    logger.debug(f"  - {pkg_type}:")
                    for file in pkg_files:
                        logger.debug(f"    - {file['name']}")
            else:
                for file in files:
                    logger.debug(f"  - {file['name']}")

        return distributions

    def detect_os(self):
        """
        Detects the current operating system.
        """
        os_system = platform.system().lower()
        if os_system.startswith('linux'):
            distro_info = distro.id().lower()
            version = distro.major_version()
            logger.debug(f"Detected Linux distribution: {distro_info} {version}")
            return 'linux', distro_info, version
        elif os_system.startswith('darwin'):
            logger.debug("Detected macOS.")
            return 'macos', None, None
        elif os_system.startswith('windows'):
            logger.debug("Detected Windows.")
            return 'windows', None, None
        else:
            logger.error(f"Unsupported operating system: {os_system}")
            sys.exit(1)

    def select_asset(self, distribution_assets, distro_info=None, version=None):
        """
        Selects the appropriate asset based on the system architecture and OS type.
        Prioritizes assets based on architecture for Linux, macOS, and Windows.

        Args:
            distribution_assets (list): List of assets from the latest release.
            distro_info (str, optional): Identifier for the Linux distribution (e.g., 'ubuntu', 'centos').
            version (str, optional): Version of the Linux distribution.

        Returns:
            dict: Selected asset with 'name' and 'url' keys.
        """
        if not distribution_assets:
            logger.error("No assets found for the detected distribution.")
            sys.exit(1)

        for asset in distribution_assets:
            logger.debug(f"Asset available: {asset}")

        os_system = platform.system().lower()
        selected_asset = None
        system_arch = platform.machine().lower()

        # Define Debian-based distributions for prioritization
        debian_based_distros = ['ubuntu', 'debian', 'linuxmint', 'pop', 'elementary']

        # Define RPM-based distributions
        rpm_based_distros = ['fedora', 'centos', 'rhel', 'rocky', 'almalinux', 'opensuse']

        # Determine if the distribution is Debian-based or RPM-based
        is_debian_based = distro_info in debian_based_distros
        is_rpm_based = distro_info in rpm_based_distros

        logger.debug(f"Operating System: {os_system}")
        logger.debug(f"Distribution Info: {distro_info}")
        logger.debug(f"System Architecture: {system_arch}")
        logger.debug(f"Is Debian-Based: {is_debian_based}")
        logger.debug(f"Is RPM-Based: {is_rpm_based}")

        # Prioritize asset selection based on OS type
        for asset in distribution_assets:
            name = asset['name'].lower()

            # The debug packages are already skipped in the grouping function,
            # but we can add an extra check to be safe.
            if '-dbgsym' in name or '-dbg' in name or '-debuginfo' in name:
                logger.debug(f"Skipping debug/debuginfo package: {name}")
                continue

            # macOS: prioritize .pkg files
            if os_system == 'darwin' and ('macos' in name or 'darwin' in name):
                if system_arch in name and name.endswith('.pkg'):
                    selected_asset = asset
                    logger.debug(f"Selected macOS pkg asset: {name}")
                    break
                elif 'x86_64' in name and name.endswith('.pkg'):
                    selected_asset = asset
                    logger.debug(f"Selected macOS x86_64 pkg asset: {name}")
                elif 'arm64' in name and name.endswith('.pkg'):
                    selected_asset = asset
                    logger.debug(f"Selected macOS arm64 pkg asset: {name}")

            # Windows: prioritize .msi files
            elif os_system == 'windows':
                if 'x86_64' in name or 'amd64' in name:
                    if name.endswith('.msi'):
                        selected_asset = asset
                        logger.debug(f"Selected Windows MSI asset: {name}")
                        break
                    elif name.endswith('.exe'):
                        selected_asset = asset
                        logger.debug(f"Selected Windows EXE asset: {name}")
                elif 'arm64' in name:
                    logger.debug(f"Skipping ARM64 Windows asset: {name}")

            # Linux: prioritize based on distribution and architecture
            elif os_system == 'linux':
                # Debian-Based: prefer .deb packages
                if is_debian_based and name.endswith('.deb'):
                    if system_arch in name or 'amd64' in name or 'x86_64' in name:
                        selected_asset = asset
                        logger.debug(f"Selected Debian-based DEB asset: {name}")
                        break

                # RPM-Based: prefer .rpm packages
                elif is_rpm_based and name.endswith('.rpm'):
                    if system_arch in name or 'amd64' in name or 'x86_64' in name:
                        selected_asset = asset
                        logger.debug(f"Selected RPM-based RPM asset: {name}")
                        break

        # Fallback: Select the first available main asset if no specific format is found
        if not selected_asset:
            for asset in distribution_assets:
                name = asset['name'].lower()
                if '-dbgsym' in name or '-dbg' in name:
                    continue  # Skip debug symbol packages
                if os_system == 'linux':
                    if is_debian_based and name.endswith('.deb'):
                        selected_asset = asset
                        logger.debug(f"Fallback selection: DEB asset for Debian-based distro: {name}")
                        break
                    elif is_rpm_based and name.endswith('.rpm'):
                        selected_asset = asset
                        logger.debug(f"Fallback selection: RPM asset for RPM-based distro: {name}")
                        break
                else:
                    selected_asset = asset
                    logger.debug(f"Fallback selection: {name}")
                    break

        if selected_asset:
            logger.debug(f"Final selected asset: {selected_asset['name']}")
            return selected_asset
        else:
            logger.error("No suitable asset found for installation.")
            sys.exit(1)

    def download_asset(self, asset):
        """
        Downloads the specified asset to the download directory.
        """
        download_dir = Path(tempfile.gettempdir())
        download_dir.mkdir(parents=True, exist_ok=True)
        file_path = download_dir / asset['name']

        logger.debug(f"Downloading osquery package:")
        logger.debug(f"  - Package name: {asset['name']}")
        logger.debug(f"  - Download URL: {asset['url']}")
        logger.debug(f"  - Download target: {file_path}")
        
        with requests.get(asset['url'], stream=True) as r:
            r.raise_for_status()
            content_size = int(r.headers.get('content-length', 0))
            logger.debug(f"  - Package size: {content_size/1024/1024:.2f} MB")
            
            with open(file_path, 'wb') as f:
                shutil.copyfileobj(r.raw, f)
            
        logger.debug(f"Downloaded successfully to {file_path}")
        logger.debug(f"File size on disk: {os.path.getsize(file_path)/1024/1024:.2f} MB")
        return file_path

    def extract_archive(self, file_path, extract_to):
        """
        Extracts the downloaded archive to the specified directory.
        Supports .tar.gz, .zip files.
        Installer packages like .msi or .pkg are not extracted.
        """
        extract_to = Path(extract_to)
        extract_to.mkdir(parents=True, exist_ok=True)

        logger.debug(f"Extracting package:")
        logger.debug(f"  - Source file: {file_path}")
        logger.debug(f"  - Extract destination: {extract_to}")
        
        if file_path.suffixes[-2:] == ['.tar', '.gz'] or file_path.suffix == '.tgz':
            logger.debug(f"Detected tar.gz archive format")
            with tarfile.open(file_path, 'r:gz') as tar:
                file_count = len(tar.getmembers())
                logger.debug(f"Archive contains {file_count} files/directories")
                tar.extractall(path=extract_to)
        elif file_path.suffix == '.zip':
            logger.debug(f"Detected zip archive format")
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                file_count = len(zip_ref.namelist())
                logger.debug(f"Archive contains {file_count} files/directories")
                zip_ref.extractall(path=extract_to)
        else:
            logger.debug(f"No extraction needed for {file_path.suffix} format")
        
        logger.debug(f"Extraction completed successfully")

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
        logger.debug(f"osquery package : {file_path}")

        try:
            if system == "linux":
                if file_path.suffix == ".rpm":
                    package_name = "osquery"
                    logger.debug(f"Checking if {package_name} is already installed...")

                    installed_version = self.get_installed_version(package_name)

                    if installed_version:
                        rpm_version = file_path.stem.split('-')[1]
                        if installed_version == rpm_version:
                            logger.debug(f"{package_name} version {installed_version} is already up-to-date.")
                            return
                        else:
                            logger.debug(f"{package_name} is already installed, updating from version {installed_version} to {rpm_version}.")
                            logger.debug(f"Running command: sudo rpm -Uvh {file_path}")
                            subprocess.run(["sudo", "rpm", "-Uvh", str(file_path)], check=True)
                            logger.debug(f"Successfully updated {package_name} to version {rpm_version}.")
                    else:
                        logger.debug(f"{package_name} is not installed, installing the package.")
                        logger.debug(f"Running command: sudo rpm -ivh {file_path}")
                        subprocess.run(["sudo", "rpm", "-ivh", str(file_path)], check=True)
                        logger.debug(f"Successfully installed {package_name}.")
                elif file_path.suffix == ".deb":
                    logger.debug(f"Installing DEB package: {file_path}")
                    logger.debug(f"Running command: sudo dpkg -i {file_path}")
                    subprocess.run(["sudo", "dpkg", "-i", str(file_path)], check=True)
                    logger.debug("Running command: sudo apt-get -f install")
                    subprocess.run(["sudo", "apt-get", "-f", "install"], check=True)
                    logger.debug(f"Successfully installed {file_path}.")
                else:
                    logger.warning(f"Unsupported Linux package format: {file_path.suffix}")
            elif system == "darwin":
                logger.debug(f"file_path.suffix : {file_path.suffix}")
                if file_path.suffix == ".pkg":
                    logger.debug(f"Installing PKG package: {file_path}")
                    logger.debug(f"Running command: sudo installer -pkg {file_path} -target /")
                    subprocess.run(["sudo", "installer", "-pkg", str(file_path), "-target", "/"], check=True)
                    logger.debug(f"Successfully installed {file_path}.")
                else:
                    logger.warning(f"Unsupported macOS package format: {file_path.suffix}")
            elif system == "windows":
                if file_path.suffix == ".msi":
                    logger.debug(f"Installing MSI package: {file_path}")
                    logger.debug(f"Running command: msiexec /i {file_path} /quiet /norestart")
                    try:
                        subprocess.run(["msiexec", "/i", str(file_path), "/quiet", "/norestart"], check=True)
                        logger.debug(f"Successfully installed {file_path}.")
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Failed to install MSI package: {e}")
                        raise
                elif file_path.suffix == ".exe":
                    logger.debug(f"Running executable installer: {file_path}")
                    logger.debug(f"Running command: {file_path} /S")
                    try:
                        subprocess.run([str(file_path), "/S"], check=True)
                        logger.debug(f"Successfully installed {file_path}.")
                    except subprocess.CalledProcessError as e:
                        logger.error(f"Failed to install EXE package: {e}")
                        raise
                else:
                    logger.warning(f"Unsupported Windows package format: {file_path.suffix}")
                    sys.exit(1)
            logger.info("osquery installation completed successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess failed with error: {e}")
            sys.exit(1)

    def install(self, extract_dir=OSQUERY_EXTRACT_DIR):
        """
        Orchestrates the download, extraction, and installation of osquery.
        """
        logger.info("Installing osquery...")
        latest_release = self.get_latest_release()
        assets = latest_release.get('assets', [])

        if not assets:
            logger.error("No assets found in the latest release.")
            sys.exit(1)

        grouped_assets = self.group_assets_by_distribution(assets)

        os_type, distro_info, version = self.detect_os()

        if os_type == 'linux':
            # Use 'main' assets for Linux
            distribution_assets = grouped_assets['linux']['main']
            selected_asset = self.select_asset(distribution_assets, distro_info, version)
        elif os_type == 'macos':
            distribution_assets = grouped_assets['macos']['main']
            selected_asset = self.select_asset(distribution_assets)
        elif os_type == 'windows':
            distribution_assets = grouped_assets['windows']['main']
            selected_asset = self.select_asset(distribution_assets)
        else:
            logger.error(f"Unsupported operating system: {os_type}")
            sys.exit(1)

        downloaded_file = self.download_asset(selected_asset)

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
        logger.debug(f"Downloaded files are located in: {Path(downloaded_file).resolve()}")
        logger.debug(f"Extracted files are located in: {Path(extract_dir).resolve()}")

    def configure_and_start(self):
        """
        Configures osquery based on the operating system.
        """
        os_system = platform.system().lower()
        logger.info(f"configuring osquery for OS: {os_system}..")
        try:
            if os_system == 'linux':
                self.configure_linux()
            elif os_system == 'darwin':
                self.configure_macos()
            elif os_system == 'windows':
                self.configure_windows()
            else:
                logger.error(f"Unsupported operating system: {os_system}")
                raise NotImplementedError("This installation script does not support the detected OS.")

        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
            logger.error(f"Error output: {e.stderr}")
            raise
        except Exception as ex:
            logger.error(f"An unexpected error occurred: {ex}")
            raise
        logger.info("osquery configuration completed successfully.")

    def log_subprocess_result(self, result):
        """
        Logs the output and errors from subprocess commands.
        """
        if result.stdout:
            logger.debug(f"Subprocess output: {result.stdout}")
        if result.stderr:
            logger.error(f"Subprocess error: {result.stderr}")

    def configure_linux(self):
        # Linux-specific installation commands
        subprocess.run(['sudo', 'cp', OSQUERY_CONFIG_EXAMPLE_PATH_LINUX, OSQUERY_CONFIG_PATH_LINUX],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['sudo', 'systemctl', 'enable', 'osqueryd'],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['sudo', 'systemctl', 'start', 'osqueryd'],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info("osquery installed and started on Linux.")

    def configure_macos(self):
        # macOS-specific installation commands
        subprocess.run(['sudo', 'cp', OSQUERY_CONFIG_EXAMPLE_PATH_MACOS, OSQUERY_CONFIG_PATH_MACOS],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['sudo', 'cp', '/var/osquery/io.osquery.agent.plist', '/Library/LaunchDaemons'],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['sudo', 'launchctl', 'load', '/Library/LaunchDaemons/io.osquery.agent.plist'],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['sudo', 'launchctl', 'enable', 'system/io.osquery.agent'],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info("osquery installed and started on macOS.")

    def get_service_state(self, service_name):
        """
        Retrieves the current state of the given service.
        Returns the state as a string, e.g., 'RUNNING', 'STOPPED', etc.
        """
        try:
            result = subprocess.run(['sc.exe', 'query', service_name],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True,
                                    check=True)
            for line in result.stdout.splitlines():
                if 'STATE' in line:
                    # Example line: "STATE              : 4  RUNNING"
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        state_text = parts[3]
                        return state_text.upper()
            return 'UNKNOWN'
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to query service {service_name}: {e}")
            return 'UNKNOWN'

    def configure_windows(self):
        """
        Configures osquery for Windows after MSI installation.
        Sets up configuration files, ensures the service exists, and starts the service.
        """
        try:
            config_path = Path(OSQUERY_CONFIG_PATH_WINDOWS)
            example_config_path = Path(OSQUERY_CONFIG_EXAMPLE_PATH_WINDOWS)

            # Handle configuration file
            if config_path.exists():
                logger.debug(f"Config file already exists at {config_path}. No need to copy.")
            else:
                if example_config_path.exists():
                    shutil.copyfile(example_config_path, config_path)
                    logger.debug(f"Copied osquery example config to {config_path}")
                else:
                    logger.warning(
                        f"Example config file not found: {example_config_path}. Creating a default osquery.conf"
                    )
                    default_config = {
                        "options": {
                            "config_plugin": "filesystem",
                            "logger_plugin": "filesystem",
                            "logger_path": OSQUERY_LOGGER_PATH_WINDOWS,
                            "pidfile": OSQUERY_PIDFILE_PATH_WINDOWS,
                            "database_path": OSQUERY_DATABASE_PATH_WINDOWS
                        },
                        "schedule": {}
                    }
                    try:
                        with open(config_path, 'w') as f:
                            json.dump(default_config, f, indent=2)
                        logger.debug(f"Created default osquery config at {config_path}")
                    except Exception as e:
                        logger.error(f"Failed to create default osquery config: {e}")
                        raise

            # Check if the osqueryd service exists
            if self.service_exists(OSQUERY_SERVICE_NAME):
                service_state = self.get_service_state(OSQUERY_SERVICE_NAME)
                logger.debug(f"osqueryd service state: {service_state}")

                if service_state == 'RUNNING':
                    logger.debug("osqueryd service is already running.")
                elif service_state in ['START_PENDING', 'STOP_PENDING']:
                    logger.debug(f"osqueryd service is in state {service_state}. Waiting before attempting to start.")
                    self.wait_for_service_state(OSQUERY_SERVICE_NAME, desired_states=['RUNNING'], timeout=30)
                elif service_state == 'STOPPED':
                    logger.debug("osqueryd service is stopped. Attempting to start.")
                    self.start_service(OSQUERY_SERVICE_NAME)
                else:
                    logger.warning(f"osqueryd service is in an unexpected state: {service_state}")
            else:
                logger.debug(f"osqueryd service does not exist. Creating service '{OSQUERY_SERVICE_NAME}'.")
                osqueryd_path = self.locate_osqueryd_executable()
                if not osqueryd_path:
                    logger.error("osqueryd executable not found. Cannot create the service.")
                    raise FileNotFoundError("osqueryd executable not found.")

                self.create_service(OSQUERY_SERVICE_NAME, osqueryd_path)
                self.start_service(OSQUERY_SERVICE_NAME)

            # Optional: Enable Windows Event Log support
            self.enable_event_log_support()

        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{' '.join(e.cmd)}' failed with exit status {e.returncode}")
            logger.error(f"Error output: {e.stderr}")
            raise
        except FileNotFoundError as ex:
            logger.error(f"An expected file was not found: {ex}")
            raise
        except Exception as ex:
            logger.error(f"An unexpected error occurred: {ex}")
            raise

    def wait_for_service_state(self, service_name, desired_states, timeout=30, interval=5):
        """
        Waits until the service reaches one of the desired states or times out.
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            state = self.get_service_state(service_name)
            if state in desired_states:
                logger.debug(f"Service '{service_name}' reached desired state: {state}")
                return
            logger.debug(f"Waiting for service '{service_name}' to reach states {desired_states}. Current state: {state}")
            time.sleep(interval)
        logger.error(f"Service '{service_name}' did not reach desired states {desired_states} within {timeout} seconds.")
        raise TimeoutError(f"Service '{service_name}' did not reach desired states {desired_states} within {timeout} seconds.")

    def start_service(self, service_name):
        """
        Attempts to start a Windows service.
        """
        logger.info(f"Starting service '{service_name}'...")
        result = subprocess.run(
            ['sc.exe', 'start', service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            logger.debug(f"Service '{service_name}' started successfully.")
            self.wait_for_service_state(service_name, desired_states=['RUNNING'], timeout=30)
        else:
            logger.error(f"Failed to start service '{service_name}'. Error: {result.stderr.strip()}")
            if '1060' in result.stderr or 'does not exist' in result.stderr.lower():
                logger.warning(f"Service '{service_name}' does not exist. Attempting to create the service.")
                osqueryd_path = self.locate_osqueryd_executable()
                if not osqueryd_path:
                    logger.error("osqueryd executable not found. Cannot create the service.")
                    raise FileNotFoundError("osqueryd executable not found.")

                self.create_service(service_name, osqueryd_path)
                self.start_service(service_name)
            else:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    ['sc.exe', 'start', service_name],
                    output=result.stdout,
                    stderr=result.stderr
                )

    def service_exists(self, service_name):
        """
        Checks if a Windows service exists.
        """
        result = subprocess.run(
            ['sc.exe', 'query', service_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            logger.debug(f"Service '{service_name}' exists.")
            return True
        else:
            logger.debug(f"Service '{service_name}' does not exist. Error: {result.stderr.strip()}")
            return False

    def create_service(self, service_name, executable_path):
        """
        Creates a Windows service using sc.exe.
        """
        create_cmd = [
            'sc.exe', 'create', service_name,
            'binPath=', f'"{executable_path}"',
            'start=', 'auto'
        ]
        logger.debug(f"Creating service with command: {' '.join(create_cmd)}")
        result = subprocess.run(
            create_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if result.returncode == 0:
            logger.debug(f"Service '{service_name}' created successfully.")
        else:
            logger.error(f"Failed to create service '{service_name}'. Error: {result.stderr.strip()}")
            raise subprocess.CalledProcessError(
                result.returncode,
                create_cmd,
                output=result.stdout,
                stderr=result.stderr
            )

    def enable_event_log_support(self):
        """
        Enables Windows Event Log support for osquery.
        """
        wevtutil_path = r'C:\Program Files\osquery\osquery.man'
        if Path(wevtutil_path).exists():
            logger.debug(f"Enabling Windows Event Log support using {wevtutil_path}...")
            result = subprocess.run(
                ['wevtutil', 'im', wevtutil_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if result.returncode == 0:
                logger.debug("Windows Event Log support enabled for osquery.")
            else:
                logger.error(f"Failed to enable Windows Event Log support: {result.stderr.strip()}")
                raise subprocess.CalledProcessError(
                    result.returncode,
                    ['wevtutil', 'im', wevtutil_path],
                    output=result.stdout,
                    stderr=result.stderr
                )
        else:
            logger.warning(f"Windows Event Log support file not found: {wevtutil_path}")

    def locate_osqueryd_executable(self):
        """
        Attempts to locate the osqueryd executable on the system.
        Returns the full path if found, else None.
        """
        possible_paths = [Path("C:/Program Files/osquery/osqueryd.exe"),
                          Path("C:/Program Files/osquery/osqueryd/osqueryd.exe"),
                          Path("C:/Program Files (x86)/osquery/osqueryd.exe"),
                          Path("C:/osquery/osqueryd.exe")]

        for path in possible_paths:
            if path.exists():
                logger.debug(f"osqueryd executable found at: {path}")
                return str(path)
        logger.error("osqueryd executable not found in standard installation directories.")
        return None

    def uninstall(self):
        """
        Orchestrates the uninstallation of osquery based on the operating system.
        """
        logger.info("Uninstalling osquery...")
        system = platform.system().lower()

        if system == "linux":
            self.uninstall_linux()
        elif system == "darwin":
            self.uninstall_macos()
        elif system == "windows":
            self.uninstall_windows()
        else:
            logger.error(f"Unsupported OS for uninstallation: {system}")
            sys.exit(1)

    def stop_and_disable_service_linux(self):
        """
        Stops and disables the osqueryd service on Linux. It first checks if the service exists,
        then attempts to stop and disable it. Detailed logging is provided for each step.
        """
        logger.debug("Checking if osqueryd service exists before attempting to stop and disable it.")

        # Check if osqueryd service exists
        try:
            result_status = subprocess.run(['sudo', 'systemctl', 'status', OSQUERY_SERVICE_NAME],
                                           check=False,
                                           text=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
            if result_status.returncode != 0:
                logger.warning(f"osqueryd service is not loaded or does not exist: {result_status.stderr}")
                return  # If the service doesn't exist, no need to proceed further
            else:
                logger.debug("osqueryd service exists. Proceeding with stop and disable steps.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to check osqueryd service status: {e.stderr}")
            raise

        # Stop the service
        try:
            logger.debug("Stopping osqueryd service...")
            result_stop = subprocess.run(['sudo', 'systemctl', 'stop', OSQUERY_SERVICE_NAME],
                                         check=False,
                                         text=True,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            if result_stop.returncode == 0:
                logger.debug("osqueryd service stopped successfully.")
            else:
                logger.warning(f"Failed to stop osqueryd service: {result_stop.stderr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error while stopping osqueryd service: {e.stderr}")
            raise

        # Disable the service
        try:
            logger.debug("Disabling osqueryd service...")
            result_disable = subprocess.run(['sudo', 'systemctl', 'disable', OSQUERY_SERVICE_NAME],
                                            check=False,
                                            text=True,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
            if result_disable.returncode == 0:
                logger.debug("osqueryd service disabled successfully.")
            else:
                logger.warning(f"Failed to disable osqueryd service: {result_disable.stderr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error while disabling osqueryd service: {e.stderr}")
            raise

        # Reload systemd to ensure changes are applied
        try:
            logger.debug("Reloading systemd daemon to apply changes...")
            result_reload = subprocess.run(['sudo', 'systemctl', 'daemon-reload'],
                                           check=False,
                                           text=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
            if result_reload.returncode == 0:
                logger.debug("Systemd daemon reloaded successfully.")
            else:
                logger.warning(f"Failed to reload systemd daemon: {result_reload.stderr}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error while reloading systemd daemon: {e.stderr}")
            raise

    def uninstall_linux(self):
        """
        Uninstalls osquery on Linux using the appropriate package manager.
        """
        package_name = "osquery"
        distro_id = distro.id().lower()
        logger.debug(f"Detected Linux distribution: {distro_id}")

        self.stop_and_disable_service_linux()

        try:
            if distro_id in ["ubuntu", "debian"]:
                self.uninstall_with_apt(package_name)
            elif distro_id in ["fedora", "centos", "rhel", "rocky", "almalinux"]:
                self.uninstall_with_dnf_yum(package_name, distro_id)
            else:
                logger.warning(f"Unsupported or unrecognized Linux distribution: {distro_id}. Attempting to use rpm or dpkg directly.")
                self.uninstall_with_rpm_or_dpkg(package_name)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to uninstall osquery: {e}")
            raise

    def uninstall_with_apt(self, package_name):
        """
        Uninstalls osquery using apt on Debian-based systems.
        """
        logger.debug(f"Using apt to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", "apt-get", "remove", "--purge", "-y", package_name], check=True)
            subprocess.run(["sudo", "apt-get", "autoremove", "-y"], check=True)
            logger.debug(f"{package_name} has been successfully uninstalled using apt.")
        except subprocess.CalledProcessError as e:
            logger.error(f"apt failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_dnf_yum(self, package_name, distro_id):
        """
        Uninstalls osquery using dnf or yum on Fedora-based systems.
        """
        package_manager = "dnf" if distro_id in ["fedora", "rocky", "almalinux"] else "yum"
        logger.debug(f"Using {package_manager} to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", package_manager, "remove", "-y", package_name], check=True)
            logger.debug(f"{package_name} has been successfully uninstalled using {package_manager}.")
        except subprocess.CalledProcessError as e:
            logger.error(f"{package_manager} failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_rpm_or_dpkg(self, package_name):
        """
        Fallback method to uninstall osquery using rpm or dpkg directly.
        """
        if Path('/usr/bin/dpkg').exists() or Path('/bin/dpkg').exists():
            logger.debug(f"Using dpkg to purge {package_name}...")
            subprocess.run(["sudo", "dpkg", "--purge", package_name], check=True)
        elif Path('/usr/bin/rpm').exists() or Path('/bin/rpm').exists():
            logger.debug(f"Using rpm to erase {package_name}...")
            subprocess.run(["sudo", "rpm", "-e", package_name], check=True)
        else:
            logger.error("Neither dpkg nor rpm package managers are available on this system.")
            raise EnvironmentError("No suitable package manager found for uninstallation.")

        logger.debug(f"{package_name} has been successfully uninstalled using rpm/dpkg.")

    def stop_and_disable_service_macos(self):
        """
        Stops and disables the osqueryd service on macOS.
        """
        logger.debug("Stopping and disabling osquery agent on macOS.")
        try:
            subprocess.run(['sudo', 'launchctl', 'unload', '/Library/LaunchDaemons/io.osquery.agent.plist'],
                           check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(['sudo', 'launchctl', 'disable', 'system/io.osquery.agent'],
                           check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            logger.debug("osquery agent service stopped and disabled on macOS.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop or disable osquery agent on macOS: {e.stderr}")
            raise

    def uninstall_macos(self):
        """
        Uninstalls osquery on macOS by removing package receipts, binaries, configuration files, and launch daemons.
        """
        logger.debug("Attempting to uninstall osquery on macOS...")

        self.stop_and_disable_service_macos()

        try:
            # Step 1: Remove the package receipt using pkgutil
            package_id = self.get_macos_package_id()
            if package_id:
                logger.debug(f"Found osquery package ID: {package_id}. Removing package receipt...")
                subprocess.run(["sudo", "pkgutil", "--forget", package_id], check=True)
                logger.debug("Package receipt removed.")
            else:
                logger.warning("osquery package ID not found. Skipping pkgutil --forget step.")

            # Step 2: Stop and remove LaunchDaemon
            launch_daemon = "/Library/LaunchDaemons/io.osquery.agent.plist"
            if Path(launch_daemon).exists():
                try:
                    logger.debug(f"Unloading LaunchDaemon: {launch_daemon}")
                    subprocess.run(["sudo", "launchctl", "unload", launch_daemon], check=True)
                    logger.debug(f"Removed LaunchDaemon: {launch_daemon}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to unload LaunchDaemon {launch_daemon}: {e}")

            # Step 3: Remove installed files and directories
            installed_paths = ["/usr/local/bin/osqueryd", "/usr/local/bin/osqueryi", "/usr/local/etc/osquery/",
                "/usr/local/var/osquery/", "/Library/LaunchDaemons/io.osquery.agent.plist",
                "/Library/Preferences/io.osquery.agent.plist"]

            for path_str in installed_paths:
                path = Path(path_str)
                if path.exists():
                    if path.is_file() or path.is_symlink():
                        try:
                            path.unlink()
                            logger.debug(f"Removed file: {path}")
                        except Exception as e:
                            logger.error(f"Failed to remove file {path}: {e}")
                    elif path.is_dir():
                        try:
                            shutil.rmtree(path)
                            logger.debug(f"Removed directory: {path}")
                        except Exception as e:
                            logger.error(f"Failed to remove directory {path}: {e}")
                else:
                    logger.debug(f"Path does not exist, skipping: {path}")

            logger.debug("osquery has been successfully uninstalled from macOS.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to uninstall osquery on macOS: {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during osquery uninstallation on macOS: {e}")
            raise

    def stop_and_disable_service_windows(self):
        """
        Stops and deletes the osqueryd service on Windows.
        """
        service_name = OSQUERY_SERVICE_NAME

        try:
            # Check if the service exists
            check_cmd = f'sc query {service_name}'
            logger.debug(f"Checking if {service_name} service exists with command: {check_cmd}")
            check_result = subprocess.run(check_cmd,
                                          shell=True,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          text=True)

            if "FAILED" in check_result.stdout or "does not exist" in check_result.stdout:
                logger.debug(f"{service_name} service does not exist. No need to stop or delete.")
                return

            # Stop the service
            stop_cmd = f'sc stop {service_name}'
            logger.debug(f"Stopping {service_name} service with command: {stop_cmd}")
            stop_result = subprocess.run(stop_cmd,
                                         shell=True,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         text=True)

            if stop_result.returncode == 0:
                logger.debug(f"{service_name} service stopped successfully.")
            else:
                logger.error(f"Failed to stop {service_name} service: {stop_result.stderr}")

            # Wait a few seconds to ensure the service stops
            time.sleep(5)

            # Delete the service
            delete_cmd = f'sc delete {service_name}'
            logger.debug(f"Deleting {service_name} service with command: {delete_cmd}")
            delete_result = subprocess.run(delete_cmd,
                                           shell=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           text=True)

            if delete_result.returncode == 0:
                logger.debug(f"{service_name} service deleted successfully.")
            else:
                logger.error(f"Failed to delete {service_name} service: {delete_result.stderr}")
                raise RuntimeError(f"Failed to delete {service_name} service.")

        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
            logger.error(f"Error output: {e.stderr}")
            raise
        except Exception as ex:
            logger.error(f"An unexpected error occurred while stopping and deleting {service_name}: {ex}")
            raise

    def uninstall_windows(self):
        """
        Uninstalls osquery on Windows by executing the uninstall command from the registry.
        """
        logger.debug("Attempting to uninstall osquery on Windows...")
        if not winreg:
            logger.error("winreg module is not available. Uninstallation cannot proceed on Windows.")
            return

        self.stop_and_disable_service_windows()

        try:
            uninstall_command = self.get_windows_uninstall_command(OSQUERY_PRODUCT_NAME)
            if uninstall_command:
                logger.debug(f"Found uninstall command: {uninstall_command}. Executing...")
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
                        logger.debug(f"Running MSI uninstall command: {' '.join(uninstall_cmd)}")
                        subprocess.run(uninstall_cmd, check=True)
                    else:
                        logger.error("Product code not found in uninstall command.")
                        return
                else:
                    # Assume it's an EXE with silent uninstall flags
                    uninstall_cmd = uninstall_command.split()
                    # Append silent flags if not already present
                    if not any(flag in uninstall_cmd for flag in ["/S", "/silent", "/quiet"]):
                        uninstall_cmd.append("/S")
                    logger.debug(f"Running EXE uninstall command: {' '.join(uninstall_cmd)}")
                    subprocess.run(uninstall_cmd, check=True)
                logger.debug("osquery has been successfully uninstalled from Windows.")
            else:
                logger.warning("Uninstall command for osquery not found in the registry.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to uninstall osquery on Windows: {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during osquery uninstallation on Windows: {e}")
            raise

    def get_macos_package_id(self):
        """
        Retrieves the osquery package identifier using pkgutil.
        Assumes the package ID contains 'osquery'.
        """
        try:
            result = subprocess.run(["pkgutil", "--pkgs"],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True,
                                    check=True)
            packages = result.stdout.splitlines()
            for pkg in packages:
                if "osquery" in pkg.lower():
                    return pkg
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to list packages with pkgutil: {e}")
        return None

    def get_windows_uninstall_command(self, product_name):
        """
        Searches the Windows Registry for the uninstall command of the given product.
        """
        uninstall_subkeys = [r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"]

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
                        logger.error(f"Error accessing registry key: {e}")
                        continue
        return None