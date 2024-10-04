import zipfile

import requests

from agent_core import SystemUtility
from agent_core.constants import (SS_AGENT_REPO, DOWNLOAD_DIR_LINUX, DOWNLOAD_DIR_WINDOWS, DOWNLOAD_DIR_MACOS, )
import shutil
import platform
import subprocess
import os
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

        final_executable_path = self.determine_executable_installation_path()
        self.install_and_verify_binary(dest_path, final_executable_path)

        self.setup_service(final_executable_path)

        logger.info("Installation complete.")

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

        logger.info(f"Downloaded file saved to: {dest_path}")
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
            logger.info(f"Moving {source_binary_path} to {final_executable_path}...")
            shutil.move(str(source_binary_path), str(final_executable_path))
            logger.info(f"{final_executable_path} has been installed successfully.")
        except Exception as e:
            logger.error(f"Failed to move the file to {final_executable_path}: {e}")
            raise

        # Make the binary executable on Linux and macOS
        if current_os in ["linux", "darwin"]:  # Case-insensitive OS comparison
            try:
                final_executable_path.chmod(0o755)
                logger.info(f"{final_executable_path} is now executable.")
            except Exception as e:
                logger.error(f"Failed to change permissions for {final_executable_path}: {e}")
                raise

        # Run the binary to verify installation
        try:
            logger.info(f"Running {final_executable_path} to verify installation...")
            result = subprocess.run([str(final_executable_path), "version"], check=True, capture_output=True, text=True)
            logger.info(f"Installed binary version: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Running {final_executable_path} failed: {e}")
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
        logger.info("Setting up systemd service for SS Agent...")
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
            logger.info("SS Agent service installed and started (systemd).")

        except Exception as e:
            logger.error(f"Failed to set up systemd service: {e}")
            raise

    def setup_launchd_service(self, executable_path):
        """
        Sets up a launchd service for the SS Agent on macOS.
        The service uses the 'ss-agent --debug start' command to start.
        """
        logger.info("Setting up launchd service for SS Agent...")
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

        plist_path = '/Library/LaunchDaemons/com.ss-agent.plist'
        try:
            temp_plist_path = '/tmp/com.ss-agent.plist'
            with open(temp_plist_path, 'w') as f:
                f.write(plist_content)

            # Move the plist file to the system directory with proper permissions
            SystemUtility.move_with_sudo(temp_plist_path, plist_path)

            # Load and enable the launchd service
            subprocess.run(['sudo', 'launchctl', 'load', plist_path], check=True)
            subprocess.run(['sudo', 'launchctl', 'enable', 'system/com.ss-agent'], check=True)
            logger.info("SS Agent service installed and started (launchd).")

        except Exception as e:
            logger.error(f"Failed to set up launchd service: {e}")
            raise

    def setup_windows_service(self, executable_path):
        """
        Sets up a Windows service for the SS Agent.
        The service uses the 'ss-agent --debug start' command to start.
        """
        logger.info("Setting up Windows service for SS Agent...")
        service_name = "SSAgentService"
        display_name = "SS Agent Service"

        try:
            # Install the service using sc.exe with the '--debug start' command
            install_cmd = f'sc create {service_name} binPath= "{executable_path} --debug start" DisplayName= "{display_name}" start= auto'
            logger.info(f"Running command: {install_cmd}")
            subprocess.run(install_cmd, shell=True, check=True)
            logger.info(f"Service {service_name} created successfully.")

            # Configure the service to restart automatically on failure
            failure_cmd = f'sc failure {service_name} reset= 60 actions= restart/6000/restart/6000/restart/6000'
            logger.info(f"Setting up automatic restart: {failure_cmd}")
            subprocess.run(failure_cmd, shell=True, check=True)
            logger.info(f"Service {service_name} configured for automatic restarts.")

            # Start the service
            start_cmd = f'sc start {service_name}'
            logger.info(f"Starting service: {start_cmd}")
            subprocess.run(start_cmd, shell=True, check=True)
            logger.info(f"Service {service_name} started successfully.")

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to set up Windows service for SS Agent: {e}")
            raise
