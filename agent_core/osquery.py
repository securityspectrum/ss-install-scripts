# osquery_installer.py

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
        self.logger = logging.getLogger(__name__)

    def get_latest_release(self):
        """
        Fetches the latest release from the specified GitHub repository.
        """
        url = f"{GITHUB_API_URL}/repos/{REPO_OWNER}/{REPO_NAME}/releases/latest"
        self.logger.debug(f"Fetching latest release from {url}")
        response = requests.get(url)
        if response.status_code != 200:
            self.logger.error(f"Failed to fetch latest release: {response.status_code} {response.text}")
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
            self.logger.debug(f"Processing asset: {name}")

            # Linux files
            if 'linux' in lower_name and (
                    lower_name.endswith('.rpm') or lower_name.endswith('.deb') or lower_name.endswith('.tar.gz')):
                distributions['linux'].append({'name': name, 'url': download_url})
                self.logger.debug(f"Asset {name} added to Linux group.")
            # Windows files (.msi, .exe, or .zip)
            elif 'windows' in lower_name or name.endswith('.msi'):
                distributions['windows'].append({'name': name, 'url': download_url})
                self.logger.debug(f"Asset {name} added to Windows group.")
            # macOS files (.pkg or .dmg)
            elif 'macos' in lower_name or 'darwin' in lower_name or name.endswith('.pkg'):
                distributions['macos'].append({'name': name, 'url': download_url})
                self.logger.debug(f"Asset {name} added to macOS group.")
            # Source code files
            elif 'source code' in lower_name or name.endswith('.tar.gz') or name.endswith('.zip'):
                distributions['source'].append({'name': name, 'url': download_url})
                self.logger.debug(f"Asset {name} added to Source group.")

        # Print grouped distributions for validation
        for distro, files in distributions.items():
            self.logger.debug(f"Distribution: {distro}")
            for file in files:
                self.logger.debug(f"  - {file['name']}")

        return distributions

    def detect_os(self):
        """
        Detects the current operating system.
        """
        os_system = platform.system().lower()
        if os_system.startswith('linux'):
            distro_info = distro.id().lower()
            version = distro.major_version()
            self.logger.debug(f"Detected Linux distribution: {distro_info} {version}")
            return 'linux', distro_info, version
        elif os_system.startswith('darwin'):
            self.logger.debug("Detected macOS.")
            return 'macos', None, None
        elif os_system.startswith('windows'):
            self.logger.debug("Detected Windows.")
            return 'windows', None, None
        else:
            self.logger.error(f"Unsupported operating system: {os_system}")
            sys.exit(1)

    def select_asset(self, distribution_assets, distro_info=None, version=None):
        """
        Selects the appropriate asset based on the system architecture and OS type.
        Prioritizes assets based on architecture for Linux, macOS, and Windows.
        """
        if not distribution_assets:
            self.logger.error("No assets found for the detected distribution.")
            sys.exit(1)

        for asset in distribution_assets:
            self.logger.debug(f"Asset: {asset}")

        os_system = platform.system().lower()
        selected_asset = None
        system_arch = platform.machine().lower()

        # Prioritizing asset based on OS and architecture
        for asset in distribution_assets:
            name = asset['name'].lower()

            # macOS: prioritize .pkg files
            if os_system == 'darwin' and ('macos' in name or 'darwin' in name):
                if system_arch in name and name.endswith('.pkg'):
                    selected_asset = asset
                    break
                elif 'x86_64' in name and name.endswith('.pkg'):
                    selected_asset = asset
                elif 'arm64' in name and name.endswith('.pkg'):
                    selected_asset = asset

            # Windows: prioritize .msi files
            elif os_system == 'windows':
                if 'x86_64' in name or 'amd64' in name:  # Prefer x86_64 or amd64 packages
                    if name.endswith('.msi'):
                        selected_asset = asset
                        break
                    elif name.endswith('.exe'):  # Fallback to .exe
                        selected_asset = asset
                elif 'arm64' in name:
                    self.logger.debug(f"Skipping ARM64 asset: {name}")

            # Linux: prioritize based on architecture
            elif os_system == 'linux':
                if system_arch in name and (name.endswith('.rpm') or name.endswith('.deb')):
                    selected_asset = asset
                    break
                # Fallback for common x86_64 package names
                elif 'x86_64' in name and (name.endswith('.rpm') or name.endswith('.deb')):
                    selected_asset = asset
                elif 'aarch64' in name and system_arch == 'aarch64' and (
                        name.endswith('.rpm') or name.endswith('.deb')):
                    selected_asset = asset

        # Fallback: Select the first available asset if no specific format is found
        if not selected_asset:
            self.logger.warning(f"No specific installer format found for {os_system}. Falling back to the first available asset.")
            selected_asset = distribution_assets[0]

        self.logger.debug(f"Selected asset: {selected_asset['name']}")
        return selected_asset

    def download_asset(self, asset):
        """
        Downloads the specified asset to the download directory.
        """
        download_dir = Path(tempfile.gettempdir())
        download_dir.mkdir(parents=True, exist_ok=True)
        file_path = download_dir / asset['name']

        self.logger.debug(f"Downloading {asset['name']} from {asset['url']} to {file_path}")
        with requests.get(asset['url'], stream=True) as r:
            r.raise_for_status()
            with open(file_path, 'wb') as f:
                shutil.copyfileobj(r.raw, f)
        self.logger.debug(f"Downloaded {asset['name']} successfully.")
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
            self.logger.debug(f"Extracting {file_path} to {extract_to}")
            with tarfile.open(file_path, 'r:gz') as tar:
                tar.extractall(path=extract_to)
        elif file_path.suffix == '.zip':
            self.logger.debug(f"Extracting {file_path} to {extract_to}")
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(path=extract_to)
        else:
            self.logger.debug(f"No extraction needed for {file_path}")

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
        self.logger.debug(f"osquery package : {file_path}")

        try:
            if system == "linux":
                if file_path.suffix == ".rpm":
                    package_name = "osquery"
                    self.logger.debug(f"Checking if {package_name} is already installed...")

                    installed_version = self.get_installed_version(package_name)

                    if installed_version:
                        rpm_version = file_path.stem.split('-')[1]
                        if installed_version == rpm_version:
                            self.logger.debug(f"{package_name} version {installed_version} is already up-to-date.")
                            return
                        else:
                            self.logger.debug(f"{package_name} is already installed, updating from version {installed_version} to {rpm_version}.")
                            self.logger.debug(f"Running command: sudo rpm -Uvh {file_path}")
                            subprocess.run(["sudo", "rpm", "-Uvh", str(file_path)], check=True)
                            self.logger.debug(f"Successfully updated {package_name} to version {rpm_version}.")
                    else:
                        self.logger.debug(f"{package_name} is not installed, installing the package.")
                        self.logger.debug(f"Running command: sudo rpm -ivh {file_path}")
                        subprocess.run(["sudo", "rpm", "-ivh", str(file_path)], check=True)
                        self.logger.debug(f"Successfully installed {package_name}.")
                elif file_path.suffix == ".deb":
                    self.logger.debug(f"Installing DEB package: {file_path}")
                    self.logger.debug(f"Running command: sudo dpkg -i {file_path}")
                    subprocess.run(["sudo", "dpkg", "-i", str(file_path)], check=True)
                    self.logger.debug("Running command: sudo apt-get -f install")
                    subprocess.run(["sudo", "apt-get", "-f", "install"], check=True)
                    self.logger.debug(f"Successfully installed {file_path}.")
                else:
                    self.logger.warning(f"Unsupported Linux package format: {file_path.suffix}")
            elif system == "darwin":
                self.logger.debug(f"file_path.suffix : {file_path.suffix}")
                if file_path.suffix == ".pkg":
                    self.logger.debug(f"Installing PKG package: {file_path}")
                    self.logger.debug(f"Running command: sudo installer -pkg {file_path} -target /")
                    subprocess.run(["sudo", "installer", "-pkg", str(file_path), "-target", "/"], check=True)
                    self.logger.debug(f"Successfully installed {file_path}.")
                else:
                    self.logger.warning(f"Unsupported macOS package format: {file_path.suffix}")
            elif system == "windows":
                if file_path.suffix == ".msi":
                    self.logger.debug(f"Installing MSI package: {file_path}")
                    self.logger.debug(f"Running command: msiexec /i {file_path} /quiet /norestart")
                    try:
                        subprocess.run(["msiexec", "/i", str(file_path), "/quiet", "/norestart"], check=True)
                        self.logger.debug(f"Successfully installed {file_path}.")
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"Failed to install MSI package: {e}")
                        raise
                elif file_path.suffix == ".exe":
                    self.logger.debug(f"Running executable installer: {file_path}")
                    self.logger.debug(f"Running command: {file_path} /S")
                    try:
                        subprocess.run([str(file_path), "/S"], check=True)
                        self.logger.debug(f"Successfully installed {file_path}.")
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"Failed to install EXE package: {e}")
                        raise
                else:
                    self.logger.warning(f"Unsupported Windows package format: {file_path.suffix}")
                    sys.exit(1)
            self.logger.info("osquery installation completed successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Subprocess failed with error: {e}")
            sys.exit(1)

    def install(self, extract_dir=OSQUERY_EXTRACT_DIR):
        """
        Orchestrates the download, extraction, and installation of osquery.
        """
        latest_release = self.get_latest_release()
        assets = latest_release.get('assets', [])

        if not assets:
            self.logger.error("No assets found in the latest release.")
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
            self.logger.error(f"Unsupported operating system: {os_type}")
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
                self.logger.warning("No installer file found after extraction.")
        else:
            # If it's an installer package, install directly
            self.install_osquery(downloaded_file)

        self.logger.debug("osquery setup process completed successfully.")
        self.logger.debug(f"Downloaded files are located in: {Path(downloaded_file).resolve()}")
        self.logger.debug(f"Extracted files are located in: {Path(extract_dir).resolve()}")


    def configure_and_start(self):
        """
        Configures osquery based on the operating system.
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

        self.logger.debug("osquery configuration and service start completed.")

    def log_subprocess_result(self, result):
        """
        Logs the output and errors from subprocess commands.
        """
        if result.stdout:
            self.logger.debug(f"Subprocess output: {result.stdout}")
        if result.stderr:
            self.logger.error(f"Subprocess error: {result.stderr}")

    def configure_linux(self):
        # Linux-specific installation commands
        subprocess.run(['sudo', 'cp', OSQUERY_CONFIG_EXAMPLE_PATH_LINUX, OSQUERY_CONFIG_PATH_LINUX],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['sudo', 'systemctl', 'enable', 'osqueryd'],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(['sudo', 'systemctl', 'start', 'osqueryd'],
                       check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.logger.debug("osquery installed and started on Linux.")

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
        self.logger.debug("osquery installed and started on macOS.")

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
            self.logger.error(f"Failed to query service {service_name}: {e}")
            return 'UNKNOWN'

    def configure_windows(self):
        """
        Configures osquery for Windows after MSI installation.
        Sets up configuration files, starts the service, and handles service creation if it doesn't exist.
        """
        try:
            config_path = Path(OSQUERY_CONFIG_PATH_WINDOWS)
            example_config_path = Path(OSQUERY_CONFIG_EXAMPLE_PATH_WINDOWS)

            # Check if the destination config file already exists
            if config_path.exists():
                self.logger.debug(f"Config file already exists at {config_path}. No need to copy.")
            else:
                # Check if the source example config file exists
                if example_config_path.exists():
                    shutil.copyfile(example_config_path, config_path)
                    self.logger.debug(f"Copied osquery example config to {config_path}")
                else:
                    self.logger.warning(f"Example config file not found: {example_config_path}. Creating a default osquery.conf")
                    # Create a minimal osquery.conf
                    osquery_config = f"""
                    {{
                      "options": {{
                        "config_plugin": "filesystem",
                        "logger_plugin": "filesystem",
                        "logger_path": "{OSQUERY_LOGGER_PATH_WINDOWS}",
                        "pidfile": "{OSQUERY_PIDFILE_PATH_WINDOWS}",
                        "database_path": "{OSQUERY_DATABASE_PATH_WINDOWS}"
                      }},
                      "schedule": {{}}
                    }}
                    """
                    self.logger.debug(f"Default osquery config:\n{osquery_config}")
                    try:
                        with open(config_path, 'w') as f:
                            f.write(osquery_config)
                        self.logger.debug(f"Created default osquery config at {config_path}")
                    except Exception as e:
                        self.logger.error(f"Failed to create default osquery config: {e}")
                        raise

            # Check the current state of the osqueryd service
            service_state = self.get_service_state(OSQUERY_SERVICE_NAME)
            self.logger.debug(f"osqueryd service state: {service_state}")

            if service_state == 'RUNNING':
                self.logger.debug("osqueryd service is already running.")
            elif service_state in ['START_PENDING', 'STOP_PENDING']:
                self.logger.debug(f"osqueryd service is in state {service_state}. Waiting before attempting to start.")
                wait_time = 5  # seconds
                max_retries = 5
                for attempt in range(max_retries):
                    self.logger.debug(f"Waiting {wait_time} seconds before retrying to start the service... (Attempt {attempt + 1}/{max_retries})")
                    time.sleep(wait_time)
                    service_state = self.get_service_state(OSQUERY_SERVICE_NAME)
                    self.logger.debug(f"Attempt {attempt + 1}/{max_retries}: osqueryd service state: {service_state}")
                    if service_state == 'RUNNING':
                        self.logger.debug("osqueryd service started successfully after waiting.")
                        break
                    elif service_state == 'START_PENDING':
                        continue
                    else:
                        self.logger.debug(f"Service state after waiting: {service_state}")
                        break
                else:
                    self.logger.error("Service did not start after multiple attempts.")
                    raise RuntimeError("Failed to start osqueryd service after waiting.")
            elif service_state in ['STOPPED', 'UNKNOWN']:
                # Attempt to start the service
                self.logger.debug("Starting osqueryd service...")
                result = subprocess.run(['sc.exe', 'start', OSQUERY_SERVICE_NAME],
                                        check=False,
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        text=True)

                if result.returncode == 0:
                    self.logger.debug("osqueryd service started successfully on Windows.")
                else:
                    self.logger.error(f"Command '['sc.exe', 'start', {OSQUERY_SERVICE_NAME}]' failed with exit status {result.returncode}")
                    self.logger.error(f"Error output: {result.stderr}")

                    # Check if the error is due to the service not existing
                    if '1060' in result.stderr or 'does not exist' in result.stderr.lower():
                        self.logger.warning(f"{OSQUERY_SERVICE_NAME} service does not exist. Attempting to create the service.")

                        # Locate the osqueryd executable
                        osqueryd_path = self.locate_osqueryd_executable()
                        if not osqueryd_path:
                            self.logger.error("osqueryd executable not found. Cannot create the service.")
                            raise FileNotFoundError("osqueryd executable not found.")

                        # Create the service
                        create_service_cmd = ['sc.exe', 'create', OSQUERY_SERVICE_NAME, 'binPath=',
                            f'"{osqueryd_path}"', 'start=', 'auto']
                        self.logger.debug(f"Creating service with command: {' '.join(create_service_cmd)}")
                        create_result = subprocess.run(create_service_cmd,
                                                       check=False,
                                                       stdout=subprocess.PIPE,
                                                       stderr=subprocess.PIPE,
                                                       text=True)

                        if create_result.returncode == 0:
                            self.logger.debug(f"Service {OSQUERY_SERVICE_NAME} created successfully.")
                            # Start the newly created service
                            start_service_cmd = ['sc.exe', 'start', OSQUERY_SERVICE_NAME]
                            self.logger.debug(f"Starting the newly created service with command: {' '.join(start_service_cmd)}")
                            start_result = subprocess.run(start_service_cmd,
                                                          check=False,
                                                          stdout=subprocess.PIPE,
                                                          stderr=subprocess.PIPE,
                                                          text=True)
                            if start_result.returncode == 0:
                                self.logger.debug(f"Service {OSQUERY_SERVICE_NAME} started successfully after creation.")
                            else:
                                self.logger.error(f"Failed to start service {OSQUERY_SERVICE_NAME} after creation: {start_result.stderr}")
                                raise subprocess.CalledProcessError(start_result.returncode,
                                                                    start_service_cmd,
                                                                    output=start_result.stdout,
                                                                    stderr=start_result.stderr)
                        else:
                            self.logger.error(f"Failed to create service {OSQUERY_SERVICE_NAME}: {create_result.stderr}")
                            raise subprocess.CalledProcessError(create_result.returncode,
                                                                create_service_cmd,
                                                                output=create_result.stdout,
                                                                stderr=create_result.stderr)
                    else:
                        raise subprocess.CalledProcessError(result.returncode,
                                                            ['sc.exe', 'start', OSQUERY_SERVICE_NAME],
                                                            output=result.stdout,
                                                            stderr=result.stderr)

            # Optional: Enable Windows Event Log support (if needed)
            wevtutil_path = r'C:\Program Files\osquery\osquery.man'
            if Path(wevtutil_path).exists():
                self.logger.debug(f"Enabling Windows Event Log support using {wevtutil_path}...")
                subprocess.run(['wevtutil', 'im', wevtutil_path],
                               check=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
                self.logger.debug("Windows Event Log support enabled for osquery.")
            else:
                self.logger.warning(f"Windows Event Log support file not found: {wevtutil_path}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
            self.logger.error(f"Error output: {e.stderr}")
            raise
        except FileNotFoundError as ex:
            self.logger.error(f"An expected file was not found: {ex}")
            raise
        except Exception as ex:
            self.logger.error(f"An unexpected error occurred: {ex}")
            raise


    def locate_osqueryd_executable(self):
        """
        Attempts to locate the osqueryd executable on the system.
        Returns the full path if found, else None.
        """
        possible_paths = [Path("C:/Program Files/osquery/osqueryd.exe"),
            Path("C:/Program Files (x86)/osquery/osqueryd.exe"), Path("C:/osquery/osqueryd.exe")]

        for path in possible_paths:
            if path.exists():
                self.logger.debug(f"osqueryd executable found at: {path}")
                return str(path)
        self.logger.error("osqueryd executable not found in standard installation directories.")
        return None

    def uninstall(self):
        """
        Orchestrates the uninstallation of osquery based on the operating system.
        """
        self.logger.debug("Starting osquery uninstallation process...")
        system = platform.system().lower()

        if system == "linux":
            self.uninstall_linux()
        elif system == "darwin":
            self.uninstall_macos()
        elif system == "windows":
            self.uninstall_windows()
        else:
            self.logger.error(f"Unsupported OS for uninstallation: {system}")
            sys.exit(1)

    def stop_and_disable_service_linux(self):
        """
        Stops and disables the osqueryd service on Linux. It first checks if the service exists,
        then attempts to stop and disable it. Detailed logging is provided for each step.
        """
        self.logger.debug("Checking if osqueryd service exists before attempting to stop and disable it.")

        # Check if osqueryd service exists
        try:
            result_status = subprocess.run(['sudo', 'systemctl', 'status', OSQUERY_SERVICE_NAME],
                                           check=False,
                                           text=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
            if result_status.returncode != 0:
                self.logger.warning(f"osqueryd service is not loaded or does not exist: {result_status.stderr}")
                return  # If the service doesn't exist, no need to proceed further
            else:
                self.logger.debug("osqueryd service exists. Proceeding with stop and disable steps.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to check osqueryd service status: {e.stderr}")
            raise

        # Stop the service
        try:
            self.logger.debug("Stopping osqueryd service...")
            result_stop = subprocess.run(['sudo', 'systemctl', 'stop', OSQUERY_SERVICE_NAME],
                                         check=False,
                                         text=True,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
            if result_stop.returncode == 0:
                self.logger.debug("osqueryd service stopped successfully.")
            else:
                self.logger.warning(f"Failed to stop osqueryd service: {result_stop.stderr}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error while stopping osqueryd service: {e.stderr}")
            raise

        # Disable the service
        try:
            self.logger.debug("Disabling osqueryd service...")
            result_disable = subprocess.run(['sudo', 'systemctl', 'disable', OSQUERY_SERVICE_NAME],
                                            check=False,
                                            text=True,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE)
            if result_disable.returncode == 0:
                self.logger.debug("osqueryd service disabled successfully.")
            else:
                self.logger.warning(f"Failed to disable osqueryd service: {result_disable.stderr}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error while disabling osqueryd service: {e.stderr}")
            raise

        # Reload systemd to ensure changes are applied
        try:
            self.logger.debug("Reloading systemd daemon to apply changes...")
            result_reload = subprocess.run(['sudo', 'systemctl', 'daemon-reload'],
                                           check=False,
                                           text=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
            if result_reload.returncode == 0:
                self.logger.debug("Systemd daemon reloaded successfully.")
            else:
                self.logger.warning(f"Failed to reload systemd daemon: {result_reload.stderr}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error while reloading systemd daemon: {e.stderr}")
            raise

    def uninstall_linux(self):
        """
        Uninstalls osquery on Linux using the appropriate package manager.
        """
        package_name = "osquery"
        distro_id = distro.id().lower()
        self.logger.debug(f"Detected Linux distribution: {distro_id}")

        self.stop_and_disable_service_linux()

        try:
            if distro_id in ["ubuntu", "debian"]:
                self.uninstall_with_apt(package_name)
            elif distro_id in ["fedora", "centos", "rhel", "rocky", "almalinux"]:
                self.uninstall_with_dnf_yum(package_name, distro_id)
            else:
                self.logger.warning(f"Unsupported or unrecognized Linux distribution: {distro_id}. Attempting to use rpm or dpkg directly.")
                self.uninstall_with_rpm_or_dpkg(package_name)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall osquery: {e}")
            raise

    def uninstall_with_apt(self, package_name):
        """
        Uninstalls osquery using apt on Debian-based systems.
        """
        self.logger.debug(f"Using apt to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", "apt-get", "remove", "--purge", "-y", package_name], check=True)
            subprocess.run(["sudo", "apt-get", "autoremove", "-y"], check=True)
            self.logger.debug(f"{package_name} has been successfully uninstalled using apt.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"apt failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_dnf_yum(self, package_name, distro_id):
        """
        Uninstalls osquery using dnf or yum on Fedora-based systems.
        """
        package_manager = "dnf" if distro_id in ["fedora", "rocky", "almalinux"] else "yum"
        self.logger.debug(f"Using {package_manager} to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", package_manager, "remove", "-y", package_name], check=True)
            self.logger.debug(f"{package_name} has been successfully uninstalled using {package_manager}.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"{package_manager} failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_rpm_or_dpkg(self, package_name):
        """
        Fallback method to uninstall osquery using rpm or dpkg directly.
        """
        if Path('/usr/bin/dpkg').exists() or Path('/bin/dpkg').exists():
            self.logger.debug(f"Using dpkg to purge {package_name}...")
            subprocess.run(["sudo", "dpkg", "--purge", package_name], check=True)
        elif Path('/usr/bin/rpm').exists() or Path('/bin/rpm').exists():
            self.logger.debug(f"Using rpm to erase {package_name}...")
            subprocess.run(["sudo", "rpm", "-e", package_name], check=True)
        else:
            self.logger.error("Neither dpkg nor rpm package managers are available on this system.")
            raise EnvironmentError("No suitable package manager found for uninstallation.")

        self.logger.debug(f"{package_name} has been successfully uninstalled using rpm/dpkg.")

    def stop_and_disable_service_macos(self):
        """
        Stops and disables the osqueryd service on macOS.
        """
        self.logger.debug("Stopping and disabling osquery agent on macOS.")
        try:
            subprocess.run(['sudo', 'launchctl', 'unload', '/Library/LaunchDaemons/io.osquery.agent.plist'],
                           check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(['sudo', 'launchctl', 'disable', 'system/io.osquery.agent'],
                           check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.debug("osquery agent service stopped and disabled on macOS.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to stop or disable osquery agent on macOS: {e.stderr}")
            raise

    def uninstall_macos(self):
        """
        Uninstalls osquery on macOS by removing package receipts, binaries, configuration files, and launch daemons.
        """
        self.logger.debug("Attempting to uninstall osquery on macOS...")

        self.stop_and_disable_service_macos()

        try:
            # Step 1: Remove the package receipt using pkgutil
            package_id = self.get_macos_package_id()
            if package_id:
                self.logger.debug(f"Found osquery package ID: {package_id}. Removing package receipt...")
                subprocess.run(["sudo", "pkgutil", "--forget", package_id], check=True)
                self.logger.debug("Package receipt removed.")
            else:
                self.logger.warning("osquery package ID not found. Skipping pkgutil --forget step.")

            # Step 2: Stop and remove LaunchDaemon
            launch_daemon = "/Library/LaunchDaemons/io.osquery.agent.plist"
            if Path(launch_daemon).exists():
                try:
                    self.logger.debug(f"Unloading LaunchDaemon: {launch_daemon}")
                    subprocess.run(["sudo", "launchctl", "unload", launch_daemon], check=True)
                    self.logger.debug(f"Removed LaunchDaemon: {launch_daemon}")
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Failed to unload LaunchDaemon {launch_daemon}: {e}")

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
                            self.logger.debug(f"Removed file: {path}")
                        except Exception as e:
                            self.logger.error(f"Failed to remove file {path}: {e}")
                    elif path.is_dir():
                        try:
                            shutil.rmtree(path)
                            self.logger.debug(f"Removed directory: {path}")
                        except Exception as e:
                            self.logger.error(f"Failed to remove directory {path}: {e}")
                else:
                    self.logger.debug(f"Path does not exist, skipping: {path}")

            self.logger.debug("osquery has been successfully uninstalled from macOS.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall osquery on macOS: {e}")
            raise
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during osquery uninstallation on macOS: {e}")
            raise

    def stop_and_disable_service_windows(self):
        """
        Stops and deletes the osqueryd service on Windows.
        """
        service_name = OSQUERY_SERVICE_NAME

        try:
            # Check if the service exists
            check_cmd = f'sc query {service_name}'
            self.logger.debug(f"Checking if {service_name} service exists with command: {check_cmd}")
            check_result = subprocess.run(check_cmd,
                                          shell=True,
                                          stdout=subprocess.PIPE,
                                          stderr=subprocess.PIPE,
                                          text=True)

            if "FAILED" in check_result.stdout or "does not exist" in check_result.stdout:
                self.logger.debug(f"{service_name} service does not exist. No need to stop or delete.")
                return

            # Stop the service
            stop_cmd = f'sc stop {service_name}'
            self.logger.debug(f"Stopping {service_name} service with command: {stop_cmd}")
            stop_result = subprocess.run(stop_cmd,
                                         shell=True,
                                         stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE,
                                         text=True)

            if stop_result.returncode == 0:
                self.logger.debug(f"{service_name} service stopped successfully.")
            else:
                self.logger.error(f"Failed to stop {service_name} service: {stop_result.stderr}")

            # Wait a few seconds to ensure the service stops
            time.sleep(5)

            # Delete the service
            delete_cmd = f'sc delete {service_name}'
            self.logger.debug(f"Deleting {service_name} service with command: {delete_cmd}")
            delete_result = subprocess.run(delete_cmd,
                                           shell=True,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           text=True)

            if delete_result.returncode == 0:
                self.logger.debug(f"{service_name} service deleted successfully.")
            else:
                self.logger.error(f"Failed to delete {service_name} service: {delete_result.stderr}")
                raise RuntimeError(f"Failed to delete {service_name} service.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
            self.logger.error(f"Error output: {e.stderr}")
            raise
        except Exception as ex:
            self.logger.error(f"An unexpected error occurred while stopping and deleting {service_name}: {ex}")
            raise

    def uninstall_windows(self):
        """
        Uninstalls osquery on Windows by executing the uninstall command from the registry.
        """
        self.logger.debug("Attempting to uninstall osquery on Windows...")
        if not winreg:
            self.logger.error("winreg module is not available. Uninstallation cannot proceed on Windows.")
            return

        self.stop_and_disable_service_windows()

        try:
            uninstall_command = self.get_windows_uninstall_command(OSQUERY_PRODUCT_NAME)
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
                    # Append silent flags if not already present
                    if not any(flag in uninstall_cmd for flag in ["/S", "/silent", "/quiet"]):
                        uninstall_cmd.append("/S")
                    self.logger.debug(f"Running EXE uninstall command: {' '.join(uninstall_cmd)}")
                    subprocess.run(uninstall_cmd, check=True)
                self.logger.debug("osquery has been successfully uninstalled from Windows.")
            else:
                self.logger.warning("Uninstall command for osquery not found in the registry.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall osquery on Windows: {e}")
            raise
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during osquery uninstallation on Windows: {e}")
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
            self.logger.error(f"Failed to list packages with pkgutil: {e}")
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
                        self.logger.error(f"Error accessing registry key: {e}")
                        continue
        return None