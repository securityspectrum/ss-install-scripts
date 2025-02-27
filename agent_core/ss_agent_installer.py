import sys
import textwrap
import zipfile
import time
import distro
import requests

from agent_core import SystemUtility
from agent_core.constants import (SS_AGENT_REPO, DOWNLOAD_DIR_LINUX, DOWNLOAD_DIR_WINDOWS, DOWNLOAD_DIR_MACOS,
                                  SS_AGENT_SERVICE_MACOS, SS_AGENT_SERVICE_NAME, SS_AGENT_CONFIG_DIR_WINDOWS,
                                  SS_AGENT_CONFIG_DIR_MACOS, SS_AGENT_CONFIG_DIR_LINUX, SS_AGENT_SERVICE_LINUX,
                                  SS_AGENT_SERVICE_BINARY_WINDOWS, SS_AGENT_PRODUCT_NAME, )
import shutil
import platform
import subprocess
import os
from pathlib import Path
import logging
from agent_core.constants import (SS_AGENT_EXECUTABLE_PATH_LINUX, SS_AGENT_EXECUTABLE_PATH_MACOS,
                                  SS_AGENT_EXECUTABLE_PATH_WINDOWS, )

try:
    import winreg  # For Windows registry access
except ImportError:
    winreg = None  # Not available on non-Windows systems
# Setup logger

logger = logging.getLogger("InstallationLogger")
quiet_install = (logger.getEffectiveLevel() > logging.DEBUG)

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

        system = platform.system().lower()

        logger.info("Installing Security Spectrum agent...")

        # Determine the appropriate download directory based on the OS
        if system == "linux":
            dest_path = DOWNLOAD_DIR_LINUX / asset_name
        elif system == "darwin":
            dest_path = DOWNLOAD_DIR_MACOS / asset_name
        elif system == "windows":
            dest_path = DOWNLOAD_DIR_WINDOWS / asset_name
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

        logger.info(f"Downloading {asset_name} from {download_url}..")
        self.download_binary(download_url, dest_path)

        logger.info(f"Installing {asset_name}..")

        final_executable_path = self.determine_executable_installation_path()
        self.install_and_verify_binary(dest_path, final_executable_path)

        logger.info(f"{asset_name} installation completed.")

    def download_binary(self, download_url, dest_path=None):
        # Expand the ~ to the user's home directory
        dest_path = os.path.expanduser(dest_path)
        # Ensure the directory exists
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        
        # Download the file
        logger.debug(f"Starting download of Security Spectrum agent from URL: {download_url}")
        logger.debug(f"Target download location: {os.path.abspath(dest_path)}")
        
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        
        # Get content size for logging
        content_size = int(response.headers.get('content-length', 0))
        logger.debug(f"Download size: {content_size/1024/1024:.2f} MB")
        
        # Write the file in chunks
        with open(dest_path, 'wb') as file:
            bytes_downloaded = 0
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)
                bytes_downloaded += len(chunk)
            
        logger.debug(f"Download completed successfully: {os.path.abspath(dest_path)}")
        logger.debug(f"File size on disk: {os.path.getsize(dest_path)/1024/1024:.2f} MB")
        return dest_path

    def determine_executable_installation_path(self):
        """
        Determines the installation path for the agent's executable based on the current operating system.
        Ensures the necessary directories exist for Windows.
        """
        os_to_executable_path_map = {"Linux": SS_AGENT_EXECUTABLE_PATH_LINUX, "Darwin": SS_AGENT_EXECUTABLE_PATH_MACOS,
                                     "Windows": SS_AGENT_EXECUTABLE_PATH_WINDOWS}

        current_os = platform.system()

        # Validate the current OS and retrieve the executable path
        if current_os in os_to_executable_path_map:
            executable_path = Path(os_to_executable_path_map[current_os])
        else:
            raise NotImplementedError(f"Unsupported OS: {current_os}")

        # Ensure the directory exists for Windows
        if current_os == "Windows":
            executable_path.parent.mkdir(parents=True, exist_ok=True)

        return executable_path

    def install_and_verify_binary(self, source_binary_path, final_executable_path):
        """
        Installs a binary to the appropriate OS-specific location, makes it executable (if applicable),
        and verifies the installation by running the binary.
        """
        current_os = platform.system().lower()  # Convert to lowercase for case-insensitive comparison

        # Expand the ~ in the source_binary_path if present
        source_binary_path = os.path.expanduser(source_binary_path)
        source_binary_path_abs = os.path.abspath(source_binary_path)
        final_executable_path_abs = os.path.abspath(str(final_executable_path))

        logger.debug(f"Installing Security Spectrum agent binary:")
        logger.debug(f"  - Source: {source_binary_path_abs}")
        logger.debug(f"  - Destination: {final_executable_path_abs}")
        logger.debug(f"  - Operating system: {current_os}")

        # Check if the downloaded file actually exists
        if not Path(source_binary_path).exists():
            logger.error(f"Source file not found: {source_binary_path_abs}")
            raise FileNotFoundError(f"Source file not found: {source_binary_path}")

        # Ensure the target directory exists
        if not final_executable_path.parent.exists():
            logger.debug(f"Creating destination directory: {final_executable_path.parent}")
            final_executable_path.parent.mkdir(parents=True, exist_ok=True)

        # Move the binary to the final location
        try:
            logger.debug(f"Moving file from {source_binary_path_abs} to {final_executable_path_abs}")
            shutil.move(str(source_binary_path), str(final_executable_path))
            logger.debug(f"File moved successfully")
        except Exception as e:
            logger.error(f"Failed to move the file to {final_executable_path_abs}: {e}")
            raise

        # Make the binary executable on Linux and macOS
        if current_os in ["linux", "darwin"]:  # Case-insensitive OS comparison
            try:
                logger.debug(f"Setting executable permissions (chmod 755) on {final_executable_path_abs}")
                final_executable_path.chmod(0o755)
                logger.debug(f"Permissions set successfully")
            except Exception as e:
                logger.error(f"Failed to change permissions for {final_executable_path_abs}: {e}")
                raise

        # Run the binary to verify installation
        try:
            logger.debug(f"Verifying installation by running: {final_executable_path_abs} version")
            result = subprocess.run([str(final_executable_path), "version"], check=True, capture_output=True, text=True)
            logger.debug(f"Verification successful - binary version: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Verification failed for {final_executable_path_abs}: {e}")
            logger.error(f"Command stderr: {e.stderr}")
            raise

    def enable_and_start(self, executable_path):
        system = platform.system().lower()
        logger.info(f"Enabling and starting the service: {executable_path} for {system}..")
        if system == 'linux':
            self.setup_systemd_service(executable_path)
        elif system == 'darwin':
            self.setup_launchd_service(executable_path)
        elif system == 'windows':
            self.setup_windows_service(executable_path)
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def service_exists(self, service_name):
        system = platform.system().lower()
        logger.debug(f"Operating System detected: {system}")

        try:
            if system == 'windows':
                return self._service_exists_windows(service_name)
            elif system == 'linux':
                return self._service_exists_linux(service_name)
            elif system == 'darwin':
                return self._service_exists_macos(service_name)
            else:
                raise NotImplementedError(f"Unsupported OS: {system}")
        except Exception as e:
            logger.error(f"Error checking service existence: {e}")
            return False

    def _service_exists_windows(self, service_name):
        logger.debug(f"Checking existence of Windows service: {service_name}")
        try:
            # 'sc.exe query' returns 0 if the service exists, non-zero otherwise
            result = subprocess.run(['sc.exe', 'query', service_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True)
            if result.returncode == 0:
                logger.debug(f"Service '{service_name}' exists on Windows.")
                return True
            else:
                logger.debug(f"Service '{service_name}' does not exist on Windows.")
                return False
        except FileNotFoundError:
            logger.error("sc.exe not found. Ensure you are running this on a Windows system.")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while checking Windows service: {e}")
            return False

    def _service_exists_linux(self, service_name):
        logger.debug(f"Checking existence of Linux service: {service_name}")
        try:
            # 'systemctl list-unit-files' lists all service unit files
            result = subprocess.run(['systemctl', 'list-unit-files', service_name + '.service'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True)
            if result.returncode == 0 and service_name + '.service' in result.stdout:
                logger.debug(f"Service '{service_name}' exists on Linux.")
                return True
            else:
                logger.debug(f"Service '{service_name}' does not exist on Linux.")
                return False
        except FileNotFoundError:
            logger.error("systemctl not found. Ensure you are running this on a Linux system with systemd.")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while checking Linux service: {e}")
            return False

    def _service_exists_macos(self, service_name):
        logger.debug(f"Checking existence of macOS service: {service_name}")
        try:
            # 'launchctl list' returns 0 if the service is loaded
            result = subprocess.run(['launchctl', 'list', service_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True)
            if result.returncode == 0:
                logger.debug(f"Service '{service_name}' exists on macOS.")
                return True
            else:
                logger.debug(f"Service '{service_name}' does not exist on macOS.")
                return False
        except FileNotFoundError:
            logger.error("launchctl not found. Ensure you are running this on a macOS system.")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while checking macOS service: {e}")
            return False

    def setup_systemd_service(self, executable_path):
        """
        Sets up a systemd service for the SS Agent on Linux.
        The service uses the 'ss-agent --debug start' command to start.
        """
        SS_AGENT_SERVICE_LINUX = "/etc/systemd/system/ss-agent.service"
        service_name = SS_AGENT_SERVICE_NAME
        if self.service_exists(service_name):
            logger.debug(f"Service {service_name} already exists. Skipping creation.")
        else:
            logger.debug("Setting up systemd service for ss-agent..")
            service_content = textwrap.dedent(f"""\
                [Unit]
                Description=ss-agent Service
                After=network.target

                [Service]
                Type=simple
                ExecStart={executable_path} --debug start
                Restart=always
                User=root

                [Install]
                WantedBy=multi-user.target
                """)

            try:
                # Write service file to a temporary location
                temp_service_path = '/tmp/ss-agent.service'
                with open(temp_service_path, 'w') as f:
                    f.write(service_content)

                logger.debug(f"Service file written to {temp_service_path}.")

                # Move the service file to the system directory with proper permissions
                SystemUtility.move_with_sudo(temp_service_path, SS_AGENT_SERVICE_LINUX)
                logger.debug(f"Service file moved to {SS_AGENT_SERVICE_LINUX}.")

                # Set correct permissions (optional but recommended)
                subprocess.run(['sudo', 'chmod', '644', SS_AGENT_SERVICE_LINUX], check=True)
                logger.debug(f"Permissions set for {SS_AGENT_SERVICE_LINUX}.")

                # Reload systemd to recognize the new service
                daemon_reload_command = ['sudo', 'systemctl', 'daemon-reload']
                if SystemUtility.run_command_with_retries(daemon_reload_command, logger):
                    logger.debug("systemd daemon reloaded.")
                else:
                    logger.error("Failed to reload systemd daemon.")

                # Enable the service to start on boot
                enable_command = ['sudo', 'systemctl', 'enable', service_name]
                if SystemUtility.run_command_with_retries(enable_command, logger):
                    logger.debug(f"Service '{service_name}' enabled to start on boot.")
                else:
                    logger.error(f"Failed to enable service '{service_name}'.")
                    return

                # Start the service immediately
                start_command = ['sudo', 'systemctl', 'start', service_name]
                if SystemUtility.run_command_with_retries(start_command, logger):
                    logger.debug(f"Service '{service_name}' started successfully.")
                else:
                    logger.error(f"Failed to start service '{service_name}'. Check the service logs for details.")

            except subprocess.CalledProcessError as e:
                logger.error(f"Command '{e.cmd}' failed with exit code {e.returncode}.")
                raise
            except Exception as e:
                logger.error(f"Failed to set up systemd service: {e}")
                raise

    def setup_launchd_service(self, executable_path):
        """
        Sets up a launchd service for the ss-agent on macOS.
        The service uses the 'ss-agent --debug start' command to start.
        """
        service_name = "com.ss-agent"
        if self.service_exists(service_name):
            logger.debug(f"Service {service_name} already exists. Skipping creation.")
        else:
            logger.debug("Setting up launchd service for ss-agent..")
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple Inc//DTD PLIST 1.0//EN" \
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>{service_name}</string>
            <key>ProgramArguments</key>
            <array>
                <string>{executable_path}</string>
                <string>--debug</string>
                <string>start</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardOutPath</key>
            <string>/var/log/ss-agent.log</string>
            <key>StandardErrorPath</key>
            <string>/var/log/ss-agent.err</string>
        </dict>
        </plist>
        """

            try:
                temp_plist_path = '/tmp/com.ss-agent.plist'
                with open(temp_plist_path, 'w') as f:
                    f.write(plist_content)

                # Move the plist file to the system directory with proper permissions
                SystemUtility.move_with_sudo(temp_plist_path, SS_AGENT_SERVICE_MACOS)

                # Load and enable the launchd service
                subprocess.run(['sudo', 'launchctl', 'load', SS_AGENT_SERVICE_MACOS], check=True)
                subprocess.run(['sudo', 'launchctl', 'enable', 'system/com.ss-agent'], check=True)
                logger.debug("ss-agent service installed and started (launchd).")

            except Exception as e:
                logger.error(f"Failed to set up launchd service: {e}")
                raise

    def setup_windows_service(self, executable_path):
        """
        Sets up a Windows service for the ss-agent.
        The service uses the 'ss-agent --debug start' command to start.
        """
        service_name = SS_AGENT_SERVICE_NAME
        if self.service_exists(service_name):
            logger.debug(f"Service {service_name} already exists. Skipping creation.")
        else:
            logger.debug("Setting up Windows service for ss-agent.")
            try:
                # Install the service using sc.exe with the '--debug start' command
                install_cmd = f'sc create {service_name} binPath= "{executable_path} --debug start" start= auto'
                logger.debug(f"Running command: {install_cmd}")
                install_proc = subprocess.run(
                    install_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=True
                )
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Service creation output:\n{install_proc.stdout.strip()}")
                else:
                    logger.info("Service created successfully.")

                # Configure the service to restart automatically on failure
                failure_cmd = f'sc failure {service_name} reset= 60 actions= restart/6000/restart/6000/restart/6000'
                logger.debug(f"Setting up automatic restart: {failure_cmd}")
                failure_proc = subprocess.run(
                    failure_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=True
                )
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Automatic restart configuration output:\n{failure_proc.stdout.strip()}")

                # Start the service
                start_cmd = f'sc start {service_name}'
                logger.debug(f"Starting service: {start_cmd}")
                start_proc = subprocess.run(
                    start_cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=True
                )
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Service start output:\n{start_proc.stdout.strip()}")
                else:
                    logger.info("Service started successfully.")

            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to set up Windows service for ss-agent: {e}")
                raise

    def stop_and_delete_windows_service(self):
        service_name = SS_AGENT_SERVICE_NAME

        os_system = platform.system().lower()
        if os_system != 'windows':
            logger.warning("The stop_and_delete_windows_service method is intended for Windows platforms.")
            return

        try:
            # Step 1: Check if the service exists
            logger.debug(f"Checking if the '{service_name}' service exists before stopping and deleting...")
            result = subprocess.run(['sc.exe', 'query', service_name],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
            if result.returncode == 1060:
                logger.debug(f"Service '{service_name}' not found (error 1060). Nothing to stop or delete.")
                return
            service_exists = f"SERVICE_NAME: {service_name}" in result.stdout
            if not service_exists:
                logger.debug(f"Service '{service_name}' not found. Nothing to stop or delete.")
                return

            # Step 2: Stop the service if it's running
            logger.debug(f"Checking if the '{service_name}' service is running...")
            if "RUNNING" in result.stdout:
                logger.debug(f"Service '{service_name}' is running. Attempting to stop it...")
                stop_command = ['sc.exe', 'stop', service_name]
                stop_result = subprocess.run(stop_command,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             text=True,
                                             check=True)
                logger.info(f"Service '{service_name}' stopped successfully.")
            else:
                logger.info(f"Service '{service_name}' is not running.")

            # Step 3: Delete the service
            logger.debug(f"Attempting to delete service '{service_name}'...")
            delete_command = ['sc.exe', 'delete', service_name]
            delete_result = subprocess.run(delete_command,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE,
                                           text=True,
                                           check=False)  # Set check=False to handle errors manually

            if delete_result.returncode == 0:
                logger.info(f"Service '{service_name}' deleted successfully.")
            elif delete_result.returncode == 1072:
                logger.warning(f"Service '{service_name}' is already marked for deletion.")
                # Optionally, implement a retry mechanism
                retry_attempts = 3
                for attempt in range(1, retry_attempts + 1):
                    logger.debug(f"Retrying deletion attempt {attempt} after waiting for 2 seconds...")

                    time.sleep(2)  # Wait for 2 seconds before retrying
                    retry_result = subprocess.run(delete_command,
                                                 stdout=subprocess.PIPE,
                                                 stderr=subprocess.PIPE,
                                                 text=True,
                                                 check=False)
                    if retry_result.returncode == 0:
                        logger.info(f"Service '{service_name}' deleted successfully on retry attempt {attempt}.")
                        break
                    elif retry_result.returncode == 1072:
                        logger.warning(f"Service '{service_name}' is still marked for deletion on retry attempt {attempt}.")
                    else:
                        logger.error(f"Failed to delete service '{service_name}' on retry attempt {attempt}.")
                        logger.error(f"stdout: {retry_result.stdout.strip()}")
                        logger.error(f"stderr: {retry_result.stderr.strip() if retry_result.stderr else 'No error output'}")
                        break
                else:
                    logger.warning(f"Service '{service_name}' is still marked for deletion after {retry_attempts} attempts.")
            else:
                logger.error(f"Failed to delete service '{service_name}'.")
                logger.error(f"stdout: {delete_result.stdout.strip()}")
                logger.error(f"stderr: {delete_result.stderr.strip() if delete_result.stderr else 'No error output'}")
                # Decide whether to raise an exception or continue
                # Here, we'll continue without raising to make the process more resilient
        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{' '.join(e.cmd)}' failed with exit status {e.returncode}")
            logger.error(f"stdout: {e.stdout.strip()}")
            logger.error(f"stderr: {e.stderr.strip() if e.stderr else 'No error output'}")
            # Optionally, decide to raise or continue
            # Here, we'll continue without raising to make the process more resilient
        except Exception as ex:
            logger.error(f"An unexpected error occurred: {ex}")
            # Optionally, decide to raise or continue
            # Here, we'll continue without raising to make the process more resilient


    def stop_linux_service(self, service_name):
        stop_cmd = ['systemctl', 'stop', service_name]
        logger.debug(f"Stopping service: {stop_cmd}")
        try:
            SystemUtility.run_command(stop_cmd, check=True)
            logger.debug(f"Service {service_name} stopped successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop the service {service_name}: {e}")
            raise

    def stop_macos_service(self, service_name):
        stop_cmd = ['sudo', 'launchctl', 'unload', SS_AGENT_SERVICE_MACOS]
        logger.debug(f"Stopping service: {service_name}")
        try:
            subprocess.run(stop_cmd, shell=True, check=True)
            logger.debug(f"Service {service_name} stopped successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop the service {service_name}: {e}")
            raise

    def stop_windows_service(self, service_name):
        try:
            # Step 1: Check if the service exists
            result = subprocess.run(['sc.exe', 'query', service_name],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)
            if result.returncode == 1060:
                logger.debug(f"Service '{service_name}' not found (error 1060). Nothing to stop or delete.")
                return
            service_exists = 'SERVICE_NAME: ' + service_name in result.stdout
            if not service_exists:
                logger.debug(f"Service '{service_name}' not found. Nothing to stop or delete.")
                return

            # Step 2: Stop the service if it's running
            logger.debug(f"Checking if the '{service_name}' service is running...")
            if "RUNNING" in result.stdout:
                logger.debug(f"Service '{service_name}' is running. Attempting to stop it...")
                stop_command = ['sc.exe', 'stop', service_name]
                stop_result = subprocess.run(stop_command,
                                             check=True,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE,
                                             text=True)
                logger.info(f"Service '{service_name}' stopped successfully.")
            else:
                logger.info(f"Service '{service_name}' is not running.")

        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{' '.join(e.cmd)}' failed with exit status {e.returncode}")
            logger.error(f"stdout: {e.stdout.strip()}")
            logger.error(f"stderr: {e.stderr.strip() if e.stderr else 'No error output'}")
            raise
        except Exception as ex:
            logger.error(f"An unexpected error occurred: {ex}")
            raise

    def is_service_running(self, service_name, fix_command=None):
        """
        Check if the service is installed and running on the system.
        Optionally attempt to fix the service state using fix_command.

        Args:
            service_name (str): The name of the service to check.
            fix_command (list, optional): The command to execute to fix the service state.

        Returns:
            bool: True if the service is running, False otherwise.
        """
        system = platform.system().lower()
        logger.debug(f"Operating System detected: {system}")

        try:
            if system == 'linux':
                status_cmd = ['systemctl', 'is-active', service_name]

                # Define a custom predicate: treat return code 0 as active,
                # and return code 3 as acceptable (meaning inactive, which is not a failure of the check).
                def is_active_predicate(result):
                    return result.returncode in (0, 3)

                result = SystemUtility.run_command_with_retries(status_cmd,
                    logger,
                    retries=1,
                    success_predicate=is_active_predicate)

                if result is not None:
                    if result.returncode == 0 and result.stdout.strip() == 'active':
                        logger.debug(f"Service '{service_name}' is active on Linux.")
                        return True
                    if result.returncode == 3:
                        logger.debug(f"Service '{service_name}' is not active (return code 3).")
                        return False
                    logger.warning(f"Service '{service_name}' returned unexpected code {result.returncode}. stdout: '{result.stdout.strip()}'")
                    return False
                else:
                    logger.warning(f"Failed to determine the status of '{service_name}' after 1 attempt.")
                    return False

            elif system == 'darwin':
                # Check status with launchctl for macOS
                status_cmd = ['launchctl', 'list', service_name]
                result = SystemUtility.run_command_with_retries(status_cmd, logger, retries=1)
                if result and service_name in result.stdout:
                    logger.debug(f"Service '{service_name}' is running on macOS.")
                    return True
                logger.debug(f"Service '{service_name}' is not running on macOS.")
                return False

            elif system == 'windows':
                # Use sc query on Windows to check service status
                status_cmd = ['sc', 'query', service_name]
                result = SystemUtility.run_command_with_retries(status_cmd, logger, retries=1)
                if result and 'RUNNING' in result.stdout:
                    logger.debug(f"Service '{service_name}' is running on Windows.")
                    return True
                logger.debug(f"Service '{service_name}' is not running on Windows.")
                return False

            else:
                logger.error(f"Unsupported OS: {system}")
                return False

        except Exception as e:
            logger.error(f"Error checking service status on {system}: {e}")
            return False


    def start_all_services_ss_agent(self):
        """
        Stop all services using the ss-agent command if the service is running.
        """
        if self.is_service_running(SS_AGENT_SERVICE_NAME):
            logger.debug(f"{SS_AGENT_SERVICE_NAME} is running. Attempting to stop all services..")
            try:
                system = platform.system().lower()
                if system == 'linux' or system == 'darwin':
                    cmd = ['sudo', 'ss-agent', 'service', 'restart', 'all']
                elif system == 'windows':
                    cmd = [SS_AGENT_SERVICE_BINARY_WINDOWS, 'service', 'restart', 'all']
                else:
                    logger.error(f"Unsupported OS: {system}")
                    return
                subprocess.run(cmd, check=True)
                logger.debug("All services started successfully.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to started services: {e}")
        else:
            logger.debug(f"{SS_AGENT_SERVICE_NAME} is not running or not installed.")


    def stop_all_services_ss_agent(self):
        """
        Stop all services using the ss-agent command if the service is running.
        Gracefully handles cases where the binary doesn't exist.
        """
        if not self.is_service_running(SS_AGENT_SERVICE_NAME):
            logger.debug(f"{SS_AGENT_SERVICE_NAME} is not running or not installed.")
            return

        logger.debug(f"{SS_AGENT_SERVICE_NAME} is running. Attempting to stop all services..")
        system = platform.system().lower()

        # Check if system is supported and set stop_cmd
        if system not in ['linux', 'darwin', 'windows']:
            logger.warning(f"Unsupported system: {system}. Skipping service stop.")
            return

        try:
            # Get the executable path using the existing method
            executable_path = self.determine_executable_installation_path()

            # Check if the executable exists
            if not os.path.exists(executable_path):
                logger.warning(f"ss-agent binary not found at {executable_path}. Skipping service stop.")
                return

            # Set the appropriate command based on the system
            if system == 'linux' or system == 'darwin':
                stop_cmd = ['sudo', str(executable_path), 'service', 'stop', 'all']
            elif system == 'windows':
                stop_cmd = [str(executable_path), 'service', 'stop', 'all']
        except Exception as e:
            logger.warning(f"Failed to determine executable path: {e}. Skipping service stop.")
            return

        # Attempt to stop the services
        try:
            result = subprocess.run(stop_cmd, capture_output=True, text=True, timeout=30)

            # Log the output
            if result.stdout:
                logger.debug(f"Command output: {result.stdout}")
            if result.stderr:
                logger.debug(f"Command error output: {result.stderr}")  # Changed to debug instead of error

            # Check return code instead of parsing output
            if result.returncode == 0:
                logger.debug("All services stopped successfully.")
            else:
                logger.warning(f"Command returned non-zero exit status {result.returncode}. Continuing anyway.")

        except subprocess.TimeoutExpired:
            logger.warning("Timeout when stopping services. Continuing anyway.")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to stop services: {e}. Continuing anyway.")
        except Exception as e:
            logger.warning(f"Unexpected error when stopping services: {e}. Continuing anyway.")

    def stop_ss_agent(self):
        """
        Stop the ss-agent service with improved error handling.
        Uses determine_executable_installation_path for consistency.
        """
        if not self.is_service_running(SS_AGENT_SERVICE_NAME):
            logger.debug(f"{SS_AGENT_SERVICE_NAME} is not running or not installed.")
            return

        logger.info(f"{SS_AGENT_SERVICE_NAME} is running. Attempting to stop the service..")

        try:
            # Check if the executable exists before attempting to stop the service
            try:
                executable_path = self.determine_executable_installation_path()
                if not os.path.exists(executable_path):
                    logger.warning(f"ss-agent binary not found at {executable_path}. Skipping service stop.")
                    return
            except Exception as e:
                logger.warning(f"Failed to determine executable path: {e}. Skipping service stop.")
                return

            system = platform.system().lower()
            if system == 'linux':
                try:
                    self.stop_linux_service(SS_AGENT_SERVICE_NAME)
                    logger.info("Service stopped successfully.")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to stop Linux service: {e}. Continuing anyway.")
            elif system == 'darwin':
                try:
                    self.stop_macos_service(SS_AGENT_SERVICE_MACOS)
                    logger.info("Service stopped successfully.")
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to stop macOS service: {e}. Continuing anyway.")
            elif system == 'windows':
                try:
                    self.stop_and_delete_windows_service()
                    logger.info("Service stopped successfully.")
                except Exception as e:
                    logger.warning(f"Failed to stop Windows service: {e}. Continuing anyway.")
            else:
                logger.warning(f"Unsupported system: {system}. Skipping service stop.")
        except Exception as e:
            logger.warning(f"Unexpected error when stopping service: {e}. Continuing anyway.")


    def uninstall(self):
        """
        Orchestrates the uninstallation of the ss-agent based on the operating system.
        """
        logger.info("Uninstalling the ss-agent..")
        system = platform.system().lower()

        if system == "linux":
            self.uninstall_linux()
            self.cleanup_linux()
        elif system == "darwin":
            self.uninstall_macos()
            self.cleanup_macos()
        elif system == "windows":
            self.uninstall_windows()
            self.cleanup_windows()
        else:
            logger.error(f"Unsupported OS for uninstallation: {system}")
            sys.exit(1)

    def uninstall_linux(self):
        """
        Uninstalls the ss-agent on Linux using the appropriate package manager.
        """
        try:
            result = subprocess.run(["sudo", "rm", "-f", SS_AGENT_EXECUTABLE_PATH_LINUX], check=True)
            if result.returncode == 0:
                logger.info(f"Successfully removed {SS_AGENT_EXECUTABLE_PATH_LINUX}")
            else:
                logger.info(f"No file to remove at {SS_AGENT_EXECUTABLE_PATH_LINUX}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove {SS_AGENT_EXECUTABLE_PATH_LINUX}: {e}")

    def uninstall_with_apt(self, package_name):
        """
        Uninstalls the ss-agent using apt on Debian-based systems.
        """
        logger.debug(f"Using apt to uninstall {package_name}...")
        try:
            result_remove = subprocess.run(["sudo", "apt-get", "remove", "--purge", "-y", package_name], check=True)
            result_autoremove = subprocess.run(["sudo", "apt-get", "autoremove", "-y"], check=True)

            if result_remove.returncode == 0 and result_autoremove.returncode == 0:
                logger.debug(f"{package_name} has been successfully uninstalled using apt.")
            else:
                logger.debug(f"{package_name} was not fully removed using apt. Some components may remain.")
        except subprocess.CalledProcessError as e:
            logger.error(f"apt failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_dnf_yum(self, package_name, distro_id):
        """
        Uninstalls the ss-agent using dnf or yum on Fedora-based systems.
        """
        package_manager = "dnf" if distro_id in ["fedora", "rocky", "almalinux"] else "yum"
        logger.debug(f"Using {package_manager} to uninstall {package_name}...")
        try:
            result = subprocess.run(["sudo", package_manager, "remove", "-y", package_name], check=True)

            if result.returncode == 0:
                logger.debug(f"{package_name} has been successfully uninstalled using {package_manager}.")
            else:
                logger.debug(f"{package_name} was not fully removed using {package_manager}. Some components may remain.")
        except subprocess.CalledProcessError as e:
            logger.error(f"{package_manager} failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_rpm_or_dpkg(self, package_name):
        """
        Fallback method to uninstall the ss-agent using rpm or dpkg directly.
        """
        try:
            if Path('/usr/bin/dpkg').exists() or Path('/bin/dpkg').exists():
                logger.debug(f"Using dpkg to purge {package_name}...")
                result = subprocess.run(["sudo", "dpkg", "--purge", package_name], check=True)
                if result.returncode == 0:
                    logger.debug(f"{package_name} has been successfully uninstalled using dpkg.")
            elif Path('/usr/bin/rpm').exists() or Path('/bin/rpm').exists():
                logger.debug(f"Using rpm to erase {package_name}...")
                result = subprocess.run(["sudo", "rpm", "-e", package_name], check=True)
                if result.returncode == 0:
                    logger.debug(f"{package_name} has been successfully uninstalled using rpm.")
            else:
                logger.error("Neither dpkg nor rpm package managers are available on this system.")
                raise EnvironmentError("No suitable package manager found for uninstallation.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to uninstall {package_name}: {e}")
            raise


    def uninstall_macos(self):
        """
        Uninstalls the ss-agent on macOS by removing package receipts, binaries, configuration files, and launch daemons.
        """
        logger.debug("Attempting to uninstall ss-agent on macOS...")
        try:
            # Step 1: Remove the package receipt using pkgutil
            package_id = self.get_macos_package_id()
            if package_id:
                logger.debug(f"Found ss-agent package ID: {package_id}. Removing package receipt...")
                result_pkgutil = subprocess.run(["sudo", "pkgutil", "--forget", package_id], check=True)
                if result_pkgutil.returncode == 0:
                    logger.debug("Package receipt removed.")
                else:
                    logger.warning(f"Failed to remove package receipt for {package_id}.")
            else:
                logger.warning("ss-agent package ID not found. Skipping pkgutil --forget step.")

            # Step 2: Stop and remove LaunchDaemon
            launch_daemon = SS_AGENT_SERVICE_MACOS
            if Path(launch_daemon).exists():
                try:
                    logger.debug(f"Unloading LaunchDaemon: {launch_daemon}")
                    result_launchctl = subprocess.run(["sudo", "launchctl", "unload", launch_daemon], check=True)
                    if result_launchctl.returncode == 0:
                        logger.debug(f"Removed LaunchDaemon: {launch_daemon}")
                    else:
                        logger.warning(f"Failed to unload LaunchDaemon: {launch_daemon}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to unload LaunchDaemon {launch_daemon}: {e}")

            # Step 3: Remove installed files and directories
            installed_paths = [SS_AGENT_EXECUTABLE_PATH_MACOS, SS_AGENT_SERVICE_MACOS, SS_AGENT_CONFIG_DIR_MACOS, ]

            for path_str in installed_paths:
                path = Path(path_str)
                if path.exists():
                    self.remove_file(path)
                else:
                    logger.debug(f"Path does not exist, skipping: {path}")

            logger.debug("ss-agent has been successfully uninstalled from macOS.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to uninstall ss-agent on macOS: {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during ss-agent uninstallation on macOS: {e}")
            raise

    def remove_file(self, path):
        """
        Remove a file or directory using sudo.

        :param path: Path object representing the file or directory to remove.
        """
        try:
            if path.is_dir():
                subprocess.run(["sudo", "rm", "-rf", str(path)], check=True)
                logger.debug(f"Removed directory: {path}")
            else:
                subprocess.run(["sudo", "rm", "-f", str(path)], check=True)
                logger.debug(f"Removed file: {path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove {path}: {e}")
            # Continue execution without halting the script
        except Exception as e:
            logger.error(f"An unexpected error occurred while removing {path}: {e}")
            # Continue execution without halting the script


    def uninstall_windows(self):
        """
        Uninstalls the ss-agent on Windows by executing the uninstall command from the registry.
        """
        logger.debug("Attempting to uninstall ss-agent on Windows...")
        if not SystemUtility.has_winreg():
            logger.error("winreg module is not available. Uninstallation cannot proceed on Windows.")
            return

        try:
            uninstall_command = self.get_windows_uninstall_command(SS_AGENT_PRODUCT_NAME)
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
                logger.debug("ss-agent has been successfully uninstalled from Windows.")
            else:
                logger.warning("Uninstall command for ss-agent not found in the registry.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to uninstall ss-agent on Windows: {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during ss-agent uninstallation on Windows: {e}")
            raise

    def get_macos_package_id(self):
        """
        Retrieves the SS Agent package identifier using pkgutil.
        Assumes the package ID contains 'ss-agent'.
        """
        try:
            result = subprocess.run(["pkgutil", "--pkgs"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            packages = result.stdout.splitlines()
            for pkg in packages:
                if "ss-agent" in pkg.lower():
                    return pkg
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to list packages with pkgutil: {e}")
        return None

    def get_windows_uninstall_command(self, product_name):
        """
        Searches the Windows Registry for the uninstall command of the given product.
        """
        try:
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
                            logger.error(f"Error accessing registry key: {e}")
                            continue
            return None
        except Exception as e:
            logger.error(f"An unexpected error occurred while accessing the registry: {e}")
            return None

    def cleanup_linux(self):
        """
        Cleans up Linux installation by removing binaries and configuration files.
        """
        package_name = "ss-agent"
        executable_path = Path(SS_AGENT_EXECUTABLE_PATH_LINUX)
        config_path = Path(SS_AGENT_CONFIG_DIR_LINUX)
        service_file = Path(SS_AGENT_SERVICE_LINUX)

        paths_to_remove = [executable_path, config_path, service_file]

        for path in paths_to_remove:
            if path.exists():
                try:
                    if path.is_file() or path.is_symlink():
                        # Use subprocess to remove files with sudo
                        logger.debug(f"Attempting to remove file: {path}")
                        subprocess.run(['sudo', 'rm', '-f', str(path)], check=True)
                        logger.debug(f"Removed file: {path}")
                    elif path.is_dir():
                        # Use subprocess to remove directories with sudo
                        logger.debug(f"Attempting to remove directory: {path}")
                        subprocess.run(['sudo', 'rm', '-rf', str(path)], check=True)
                        logger.debug(f"Removed directory: {path}")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to remove {path}: {e}")
            else:
                logger.debug(f"Path does not exist, skipping: {path}")

    def cleanup_macos(self):
        """
        Cleans up macOS installation by removing binaries, configuration files, and LaunchDaemon plist.
        """
        logger.debug("Cleaning up macOS installation...")
        self.cleanup_macos_files()

    def cleanup_macos_files(self):
        """
        Removes binaries, configuration files, and LaunchDaemon plist on macOS.
        """
        executable_path = Path(SS_AGENT_EXECUTABLE_PATH_MACOS)
        config_path = Path(SS_AGENT_CONFIG_DIR_MACOS)

        paths_to_remove = [
            executable_path,
            config_path,
            SS_AGENT_SERVICE_MACOS
        ]

        for path_str in paths_to_remove:
            path = Path(path_str)
            if path.exists():
                try:
                    if path.is_file() or path.is_symlink():
                        path.unlink()
                        logger.debug(f"Removed file: {path}")
                    elif path.is_dir():
                        shutil.rmtree(path)
                        logger.debug(f"Removed directory: {path}")
                except Exception as e:
                    logger.error(f"Failed to remove {path}: {e}")
            else:
                logger.debug(f"Path does not exist, skipping: {path}")

    def cleanup_windows(self):
        """
        Cleans up Windows installation by removing binaries and configuration files.
        """
        executable_path = Path(SS_AGENT_EXECUTABLE_PATH_WINDOWS)
        config_path = Path(SS_AGENT_CONFIG_DIR_WINDOWS)

        paths_to_remove = [
            executable_path,
            config_path,
        ]

        for path in paths_to_remove:
            if path.exists():
                try:
                    if path.is_file() or path.is_symlink():
                        path.unlink()
                        logger.debug(f"Removed file: {path}")
                    elif path.is_dir():
                        shutil.rmtree(path)
                        logger.debug(f"Removed directory: {path}")
                except Exception as e:
                    logger.error(f"Failed to remove {path}: {e}")
            else:
                logger.debug(f"Path does not exist, skipping: {path}")

    def uninstall_linux_cleanup(self):
        """
        Performs cleanup after uninstalling the SS Agent on Linux.
        """
        logger.debug("Cleaning up Linux installation...")
        self.cleanup_linux()

    def uninstall_macos_cleanup(self):
        """
        Performs cleanup after uninstalling the SS Agent on macOS.
        """
        logger.debug("Cleaning up macOS installation...")
        self.cleanup_macos()

    def uninstall_windows_cleanup(self):
        """
        Performs cleanup after uninstalling the SS Agent on Windows.
        """
        logger.debug("Cleaning up Windows installation...")
        self.cleanup_windows()

    # -------------------- Service Management Methods -------------------- #

    def stop_service(self):
        """
        Stops the SS Agent service based on the operating system.
        """
        system = platform.system().lower()
        if system == 'linux':
            self.stop_linux_service(SS_AGENT_SERVICE_NAME)
        elif system == 'darwin':
            self.stop_macos_service(SS_AGENT_SERVICE_MACOS)
        elif system == 'windows':
            self.stop_windows_service(SS_AGENT_SERVICE_NAME)
        else:
            logger.error(f"Unsupported OS for stopping service: {system}")
            raise NotImplementedError(f"Unsupported OS: {system}")
