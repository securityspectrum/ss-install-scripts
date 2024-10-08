import sys
import zipfile

import distro
import requests

from agent_core import SystemUtility
from agent_core.constants import (SS_AGENT_REPO, DOWNLOAD_DIR_LINUX, DOWNLOAD_DIR_WINDOWS, DOWNLOAD_DIR_MACOS,
                                  SS_AGENT_SERVICE_MACOS, SS_AGENT_SERVICE_NAME_WINDOWS, SS_AGENT_SERVICE_NAME,
                                  SS_AGENT_CONFIG_DIR_WINDOWS, SS_AGENT_CONFIG_DIR_MACOS, SS_AGENT_CONFIG_DIR_LINUX,
                                  SS_AGENT_SERVICE_LINUX, )
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
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

SS_AGENT_ASSET_PATTERNS = {"linux": "ss-agent-linux", "darwin": "ss-agent-darwin", "windows": "ss-agent-win.exe", }


class SSAgentInstaller:

    def __init__(self):
        self.repo = SS_AGENT_REPO
        self.logger = logging.getLogger(__name__)
        self.logger.info("INFO Starting fluent-bit installation..")
        self.logger.debug("DEBUG Starting fluent-bit installation..")

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
        self.logger.info(f"Detected system: {system}")
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

        # Determine the appropriate download directory based on the OS
        if system == "linux":
            dest_path = DOWNLOAD_DIR_LINUX / asset_name
        elif system == "darwin":
            dest_path = DOWNLOAD_DIR_MACOS / asset_name
        elif system == "windows":
            dest_path = DOWNLOAD_DIR_WINDOWS / asset_name
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

        self.logger.info(f"Downloading {asset_name} from {download_url}..")
        self.download_binary(download_url, dest_path)

        self.logger.info(f"Installing {asset_name}..")

        final_executable_path = self.determine_executable_installation_path()
        self.install_and_verify_binary(dest_path, final_executable_path)

        self.setup_service(final_executable_path)

        self.logger.info("Installation complete.")

    def download_binary(self, download_url, dest_path=None):
        # Expand the ~ to the user's home directory
        dest_path = os.path.expanduser(dest_path)
        # Ensure the directory exists
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        # Download the file
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        # Write the file in chunks
        with open(dest_path, 'wb') as file:
            for chunk in response.iter_content(chunk_size=8192):
                file.write(chunk)

        self.logger.info(f"Downloaded file saved to: {dest_path}")
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

        # Check if the downloaded file actually exists
        if not Path(source_binary_path).exists():
            raise FileNotFoundError(f"Source file not found: {source_binary_path}")

        # Ensure the target directory exists
        if not final_executable_path.parent.exists():
            final_executable_path.parent.mkdir(parents=True, exist_ok=True)

        # Move the binary to the final location
        try:
            self.logger.info(f"Moving {source_binary_path} to {final_executable_path}..")
            shutil.move(str(source_binary_path), str(final_executable_path))
            self.logger.info(f"{final_executable_path} has been installed successfully.")
        except Exception as e:
            self.logger.error(f"Failed to move the file to {final_executable_path}: {e}")
            raise

        # Make the binary executable on Linux and macOS
        if current_os in ["linux", "darwin"]:  # Case-insensitive OS comparison
            try:
                final_executable_path.chmod(0o755)
                self.logger.info(f"{final_executable_path} is now executable.")
            except Exception as e:
                self.logger.error(f"Failed to change permissions for {final_executable_path}: {e}")
                raise

        # Run the binary to verify installation
        try:
            self.logger.info(f"Running {final_executable_path} to verify installation..")
            result = subprocess.run([str(final_executable_path), "version"], check=True, capture_output=True, text=True)
            self.logger.info(f"Installed binary version: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Running {final_executable_path} failed: {e}")
            raise

    def setup_service(self, executable_path):
        system = platform.system().lower()
        if system == 'linux':
            self.setup_systemd_service(executable_path)
        elif system == 'darwin':
            self.setup_launchd_service(executable_path)
        elif system == 'windows':
            self.setup_windows_service(executable_path)
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def setup_systemd_service(self, executable_path):
        """
        Sets up a systemd service for the SS Agent on Linux.
        The service uses the 'ss-agent --debug start' command to start.
        """
        self.logger.info("Setting up systemd service for SS Agent..")
        service_content = f"""[Unit]
    Description=SS Agent Service
    After=network.target

    [Service]
    Type=simple
    ExecStart={executable_path} --debug start
    Restart=always
    User=root

    [Install]
    WantedBy=multi-user.target
    """

        service_path = '/etc/systemd/system/ss-agent.service'
        try:
            # Write service file to a temporary location
            temp_service_path = '/tmp/ss-agent.service'
            with open(temp_service_path, 'w') as f:
                f.write(service_content)

            # Move the service file to the system directory with proper permissions
            SystemUtility.move_with_sudo(temp_service_path, service_path)

            # Reload systemd, enable and start the service
            subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
            subprocess.run(['sudo', 'systemctl', 'enable', 'ss-agent'], check=True)
            subprocess.run(['sudo', 'systemctl', 'start', 'ss-agent'], check=True)
            self.logger.info("SS Agent service installed and started (systemd).")

        except Exception as e:
            self.logger.error(f"Failed to set up systemd service: {e}")
            raise

    def setup_launchd_service(self, executable_path):
        """
        Sets up a launchd service for the SS Agent on macOS.
        The service uses the 'ss-agent --debug start' command to start.
        """
        self.logger.info("Setting up launchd service for SS Agent..")
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple Inc//DTD PLIST 1.0//EN" \
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
        <key>Label</key>
        <string>com.ss-agent</string>
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
            self.logger.info("SS Agent service installed and started (launchd).")

        except Exception as e:
            self.logger.error(f"Failed to set up launchd service: {e}")
            raise

    def setup_windows_service(self, executable_path):
        """
        Sets up a Windows service for the SS Agent.
        The service uses the 'ss-agent --debug start' command to start.
        """
        self.logger.info("Setting up Windows service for SS Agent..")
        display_name = "SS Agent Service"

        try:
            # Install the service using sc.exe with the '--debug start' command
            install_cmd = f'sc create {SS_AGENT_SERVICE_NAME_WINDOWS} binPath= "{executable_path} --debug start" DisplayName= "{display_name}" start= auto'
            self.logger.info(f"Running command: {install_cmd}")
            subprocess.run(install_cmd, shell=True, check=True)
            self.logger.info(f"Service {SS_AGENT_SERVICE_NAME_WINDOWS} created successfully.")

            # Configure the service to restart automatically on failure
            failure_cmd = f'sc failure {SS_AGENT_SERVICE_NAME_WINDOWS} reset= 60 actions= restart/6000/restart/6000/restart/6000'
            self.logger.info(f"Setting up automatic restart: {failure_cmd}")
            subprocess.run(failure_cmd, shell=True, check=True)
            self.logger.info(f"Service {SS_AGENT_SERVICE_NAME_WINDOWS} configured for automatic restarts.")

            # Start the service
            start_cmd = f'sc start {SS_AGENT_SERVICE_NAME_WINDOWS}'
            self.logger.info(f"Starting service: {start_cmd}")
            subprocess.run(start_cmd, shell=True, check=True)
            self.logger.info(f"Service {SS_AGENT_SERVICE_NAME_WINDOWS} started successfully.")

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to set up Windows service for SS Agent: {e}")
            raise

    def stop_windows_service(self, service_name):
        """
        Stops a Windows service.
        """
        stop_cmd = f'sc stop {service_name}'
        self.logger.info(f"Stopping service: {stop_cmd}")
        try:
            subprocess.run(stop_cmd, shell=True, check=True)
            self.logger.info(f"Service {service_name} stopped successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to stop the service {service_name}: {e}")
            raise

    def stop_linux_service(self, service_name):
        """
        Stops a Windows service.
        """
        stop_cmd = ['systemctl', 'stop', service_name]
        self.logger.info(f"Stopping service: {stop_cmd}")
        try:
            SystemUtility.run_command(stop_cmd, check=True)
            self.logger.info(f"Service {service_name} stopped successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to stop the service {service_name}: {e}")
            raise

    def stop_macos_service(self, service_name):
        """
        Stops a Windows service.
        """
        stop_cmd = ['sudo', 'launchctl', 'unload', SS_AGENT_SERVICE_MACOS]
        self.logger.info(f"Stopping service: {service_name}")
        try:
            subprocess.run(stop_cmd, shell=True, check=True)
            self.logger.info(f"Service {service_name} stopped successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to stop the service {service_name}: {e}")
            raise

    def is_service_running(self, service_name):
        """
        Check if the service is installed and running on the system.
        """
        system = platform.system().lower()
        try:
            if system == 'linux' or system == 'darwin':
                # Use systemctl on Linux and launchctl on macOS to check service status
                if system == 'linux':
                    status_cmd = ['systemctl', 'is-active', service_name]
                else:
                    status_cmd = ['launchctl', 'list', service_name]

                result = subprocess.run(status_cmd, text=True, capture_output=True, check=False)
                if result.returncode == 0 and 'active' in result.stdout:
                    return True
                elif system == 'darwin' and service_name in result.stdout:
                    return True
                return False

            elif system == 'windows':
                # Use sc query on Windows to check service status
                result = subprocess.run(['sc', 'query', service_name], text=True, capture_output=True, check=False)
                return 'RUNNING' in result.stdout

        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error checking service status: {e}")
            return False

        return False


    def stop_all_services_ss_agent(self):
        """
        Stop all services using the ss-agent command if the service is running.
        """
        if self.is_service_running(SS_AGENT_SERVICE_NAME):
            self.logger.info(f"{SS_AGENT_SERVICE_NAME} is running. Attempting to stop all services..")
            try:
                system = platform.system().lower()
                if system == 'linux' or system == 'darwin':
                    stop_cmd = ['sudo', 'ss-agent', 'service', 'stop', 'all']
                elif system == 'windows':
                    stop_cmd = ['ss-agent.exe', 'service', 'stop', 'all']

                subprocess.run(stop_cmd, check=True)
                self.logger.info("All services stopped successfully.")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to stop services: {e}")
        else:
            self.logger.info(f"{SS_AGENT_SERVICE_NAME} is not running or not installed.")

    def stop_ss_agent(self):
        """
        Stop the SS Agent service.
        """
        if self.is_service_running(SS_AGENT_SERVICE_NAME):
            self.logger.info(f"{SS_AGENT_SERVICE_NAME} is running. Attempting to stop the service..")
            try:
                system = platform.system().lower()
                if system == 'linux':
                    self.stop_linux_service(SS_AGENT_SERVICE_NAME)
                elif system == 'darwin':
                    self.stop_macos_service(SS_AGENT_SERVICE_NAME)
                elif system == 'windows':
                    self.stop_windows_service(SS_AGENT_SERVICE_NAME_WINDOWS)
                self.logger.info("Service stopped successfully.")
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to stop service: {e}")
        else:
            self.logger.info(f"{SS_AGENT_SERVICE_NAME} is not running or not installed.")


    def uninstall(self):
        """
        Orchestrates the uninstallation of the SS Agent based on the operating system.
        """
        self.logger.info("Starting SS Agent uninstallation process...")
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
            self.logger.error(f"Unsupported OS for uninstallation: {system}")
            sys.exit(1)

    def uninstall_linux(self):
        """
        Uninstalls the SS Agent on Linux using the appropriate package manager.
        """
        package_name = "ss-agent"
        distro_id = distro.id().lower()
        try:
            subprocess.run(["sudo", "rm", "-f", SS_AGENT_EXECUTABLE_PATH_LINUX], check=True)
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to remove {SS_AGENT_EXECUTABLE_PATH_LINUX}: {e}")

    def uninstall_with_apt(self, package_name):
        """
        Uninstalls the SS Agent using apt on Debian-based systems.
        """
        self.logger.info(f"Using apt to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", "apt-get", "remove", "--purge", "-y", package_name], check=True)
            subprocess.run(["sudo", "apt-get", "autoremove", "-y"], check=True)
            self.logger.info(f"{package_name} has been successfully uninstalled using apt.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"apt failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_dnf_yum(self, package_name, distro_id):
        """
        Uninstalls the SS Agent using dnf or yum on Fedora-based systems.
        """
        package_manager = "dnf" if distro_id in ["fedora", "rocky", "almalinux"] else "yum"
        self.logger.info(f"Using {package_manager} to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", package_manager, "remove", "-y", package_name], check=True)
            self.logger.info(f"{package_name} has been successfully uninstalled using {package_manager}.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"{package_manager} failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_rpm_or_dpkg(self, package_name):
        """
        Fallback method to uninstall the SS Agent using rpm or dpkg directly.
        """
        if Path('/usr/bin/dpkg').exists() or Path('/bin/dpkg').exists():
            self.logger.info(f"Using dpkg to purge {package_name}...")
            subprocess.run(["sudo", "dpkg", "--purge", package_name], check=True)
        elif Path('/usr/bin/rpm').exists() or Path('/bin/rpm').exists():
            self.logger.info(f"Using rpm to erase {package_name}...")
            subprocess.run(["sudo", "rpm", "-e", package_name], check=True)
        else:
            self.logger.error("Neither dpkg nor rpm package managers are available on this system.")
            raise EnvironmentError("No suitable package manager found for uninstallation.")

        self.logger.info(f"{package_name} has been successfully uninstalled using rpm/dpkg.")

    def uninstall_macos(self):
        """
        Uninstalls the SS Agent on macOS by removing package receipts, binaries, configuration files, and launch daemons.
        """
        self.logger.info("Attempting to uninstall SS Agent on macOS...")
        try:
            # Step 1: Remove the package receipt using pkgutil
            package_id = self.get_macos_package_id()
            if package_id:
                self.logger.info(f"Found SS Agent package ID: {package_id}. Removing package receipt...")
                subprocess.run(["sudo", "pkgutil", "--forget", package_id], check=True)
                self.logger.info("Package receipt removed.")
            else:
                self.logger.warning("SS Agent package ID not found. Skipping pkgutil --forget step.")

            # Step 2: Stop and remove LaunchDaemon
            launch_daemon = SS_AGENT_SERVICE_MACOS
            if Path(launch_daemon).exists():
                try:
                    self.logger.info(f"Unloading LaunchDaemon: {launch_daemon}")
                    subprocess.run(["sudo", "launchctl", "unload", launch_daemon], check=True)
                    self.logger.info(f"Removed LaunchDaemon: {launch_daemon}")
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Failed to unload LaunchDaemon {launch_daemon}: {e}")

            # Step 3: Remove installed files and directories
            installed_paths = [
                SS_AGENT_EXECUTABLE_PATH_MACOS,
                SS_AGENT_SERVICE_MACOS
            ]

            for path_str in installed_paths:
                path = Path(path_str)
                if path.exists():
                    if path.is_file() or path.is_symlink():
                        try:
                            path.unlink()
                            self.logger.info(f"Removed file: {path}")
                        except Exception as e:
                            self.logger.error(f"Failed to remove file {path}: {e}")
                    elif path.is_dir():
                        try:
                            shutil.rmtree(path)
                            self.logger.info(f"Removed directory: {path}")
                        except Exception as e:
                            self.logger.error(f"Failed to remove directory {path}: {e}")
                else:
                    self.logger.debug(f"Path does not exist, skipping: {path}")

            self.logger.info("SS Agent has been successfully uninstalled from macOS.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall SS Agent on macOS: {e}")
            raise
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during SS Agent uninstallation on macOS: {e}")
            raise

    def uninstall_windows(self):
        """
        Uninstalls the SS Agent on Windows by executing the uninstall command from the registry.
        """
        self.logger.info("Attempting to uninstall SS Agent on Windows...")
        if not SystemUtility.has_winreg():
            self.logger.error("winreg module is not available. Uninstallation cannot proceed on Windows.")
            return

        try:
            uninstall_command = self.get_windows_uninstall_command("SS Agent")
            if uninstall_command:
                self.logger.info(f"Found uninstall command: {uninstall_command}. Executing...")
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
                        self.logger.info(f"Running MSI uninstall command: {' '.join(uninstall_cmd)}")
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
                    self.logger.info(f"Running EXE uninstall command: {' '.join(uninstall_cmd)}")
                    subprocess.run(uninstall_cmd, check=True)
                self.logger.info("SS Agent has been successfully uninstalled from Windows.")
            else:
                self.logger.warning("Uninstall command for SS Agent not found in the registry.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall SS Agent on Windows: {e}")
            raise
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during SS Agent uninstallation on Windows: {e}")
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
            self.logger.error(f"Failed to list packages with pkgutil: {e}")
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
                            self.logger.error(f"Error accessing registry key: {e}")
                            continue
            return None
        except Exception as e:
            self.logger.error(f"An unexpected error occurred while accessing the registry: {e}")
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
                        self.logger.info(f"Attempting to remove file: {path}")
                        subprocess.run(['sudo', 'rm', '-f', str(path)], check=True)
                        self.logger.info(f"Removed file: {path}")
                    elif path.is_dir():
                        # Use subprocess to remove directories with sudo
                        self.logger.info(f"Attempting to remove directory: {path}")
                        subprocess.run(['sudo', 'rm', '-rf', str(path)], check=True)
                        self.logger.info(f"Removed directory: {path}")
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Failed to remove {path}: {e}")
            else:
                self.logger.debug(f"Path does not exist, skipping: {path}")

    def cleanup_macos(self):
        """
        Cleans up macOS installation by removing binaries, configuration files, and LaunchDaemon plist.
        """
        self.logger.info("Cleaning up macOS installation...")
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
                        self.logger.info(f"Removed file: {path}")
                    elif path.is_dir():
                        shutil.rmtree(path)
                        self.logger.info(f"Removed directory: {path}")
                except Exception as e:
                    self.logger.error(f"Failed to remove {path}: {e}")
            else:
                self.logger.debug(f"Path does not exist, skipping: {path}")

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
                        self.logger.info(f"Removed file: {path}")
                    elif path.is_dir():
                        shutil.rmtree(path)
                        self.logger.info(f"Removed directory: {path}")
                except Exception as e:
                    self.logger.error(f"Failed to remove {path}: {e}")
            else:
                self.logger.debug(f"Path does not exist, skipping: {path}")

    def uninstall_linux_cleanup(self):
        """
        Performs cleanup after uninstalling the SS Agent on Linux.
        """
        self.logger.info("Cleaning up Linux installation...")
        self.cleanup_linux()

    def uninstall_macos_cleanup(self):
        """
        Performs cleanup after uninstalling the SS Agent on macOS.
        """
        self.logger.info("Cleaning up macOS installation...")
        self.cleanup_macos()

    def uninstall_windows_cleanup(self):
        """
        Performs cleanup after uninstalling the SS Agent on Windows.
        """
        self.logger.info("Cleaning up Windows installation...")
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
            self.stop_windows_service(SS_AGENT_SERVICE_NAME_WINDOWS)
        else:
            self.logger.error(f"Unsupported OS for stopping service: {system}")
            raise NotImplementedError(f"Unsupported OS: {system}")

    def stop_linux_service(self, service_name):
        """
        Stops a systemd service on Linux.
        """
        stop_cmd = ['sudo', 'systemctl', 'stop', service_name]
        self.logger.info(f"Stopping service: {' '.join(stop_cmd)}")
        try:
            subprocess.run(stop_cmd, check=True)
            self.logger.info(f"Service {service_name} stopped successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to stop service {service_name}: {e}")
            raise

    def stop_macos_service(self, plist_path):
        """
        Stops a launchd service on macOS.
        """
        stop_cmd = ['sudo', 'launchctl', 'unload', plist_path]
        self.logger.info(f"Stopping service: {' '.join(stop_cmd)}")
        try:
            subprocess.run(stop_cmd, check=True)
            self.logger.info(f"Service {plist_path} unloaded successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to unload service {plist_path}: {e}")
            raise

    def stop_windows_service(self, service_name):
        """
        Stops a Windows service.
        """
        stop_cmd = f'sc stop {service_name}'
        self.logger.info(f"Stopping service: {stop_cmd}")
        try:
            subprocess.run(stop_cmd, shell=True, check=True)
            self.logger.info(f"Service {service_name} stopped successfully.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to stop service {service_name}: {e}")
            raise