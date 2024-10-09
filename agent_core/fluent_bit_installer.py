import os
import platform
import shutil

import requests
import logging
import subprocess
from pathlib import Path
from agent_core.constants import (
    FLUENT_BIT_REPO,
    FLUENT_BIT_ASSET_PATTERNS,
)

import os
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
logging.basicConfig(level=logging.INFO)


class FluentBitInstaller:

    def __init__(self):
        self.repo = FLUENT_BIT_REPO
        self.logger = logging.getLogger(__name__)
        self.logger.info("INFO Starting fluent-bit installation...")
        self.logger.debug("DEBUG Starting fluent-bit installation...")

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
        self.logger.info(f"Detected system: {system}")
        if system == "linux":
            distro_name = distro.id().lower()
            version = distro.major_version()
            self.logger.info(f"Detected distro: {distro_name} {version}")
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

        dest_path = get_temp_file_path(asset_name)

        # Check if file already exists
        if dest_path.exists():
            self.logger.info(f"File {asset_name} already exists at {dest_path}. Skipping download.")
        else:
            self.logger.info(f"Downloading {asset_name} from {download_url} to temporary directory...")
            self.download_binary(download_url, dest_path)

        self.logger.info(f"Installing {asset_name}...")
        self.run_installation_command(dest_path)

        self.logger.info("Installation complete.")

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

        self.logger.info(f"Downloaded file saved to: {dest_path}")
        return dest_path

    def run_installation_command(self, dest_path):
        system = platform.system().lower()
        dest_path = Path(os.path.expanduser(dest_path))
        if system == "linux":
            if dest_path.suffix == ".rpm":
                package_name = "fluent-bit"
                rpm_version = self.extract_rpm_version(dest_path)

                if self.is_package_installed(package_name, rpm_version):
                    self.logger.info(f"{package_name} version {rpm_version} is already installed. Skipping installation.")
                    return
                elif self.is_newer_version_installed(package_name, rpm_version):
                    self.logger.info(f"A newer version of {package_name} is installed. Skipping downgrade to version {rpm_version}.")
                    return
                else:
                    self.logger.info(f"A different version of {package_name} is installed. Updating to version {rpm_version}.")
                    try:
                        subprocess.run(["sudo", "rpm", "-Uvh", str(dest_path)], check=True)
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"RPM installation failed: {e}")
                        raise
            elif dest_path.suffix == ".deb":
                package_name = "fluent-bit"
                deb_version = self.extract_deb_version(dest_path)

                if self.is_package_installed(package_name, deb_version):
                    self.logger.info(f"{package_name} version {deb_version} is already installed. Skipping installation.")
                    return
                elif self.is_newer_version_installed(package_name, deb_version):
                    self.logger.info(f"A newer version of {package_name} is installed. Skipping downgrade to version {deb_version}.")
                    return
                else:
                    self.logger.info(f"A different version of {package_name} is installed. Updating to version {deb_version}.")
                    try:
                        subprocess.run(["sudo", "dpkg", "-i", str(dest_path)], check=True)
                    except subprocess.CalledProcessError as e:
                        self.logger.error(f"DEB installation failed: {e}")
                        raise
        elif system == "darwin":
            try:
                self.logger.info(f"Installing {dest_path}...")
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
            self.logger.error(f"Failed to check installed package version: {e}")
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
                self.logger.info(f"Installed version of {package_name}: {installed_version}")
                return installed_version != version
            else:
                return False
        except Exception as e:
            self.logger.error(f"Failed to check installed package version: {e}")
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
                self.logger.info(f"Installed version of {package_name}: {installed_version}")
                return installed_version > version
            else:
                return False
        except Exception as e:
            self.logger.error(f"Failed to check installed package version: {e}")
            return False

    def configure_linux(self):
        try:
            # Log enabling Fluent Bit to start on boot
            self.logger.info("Enabling Fluent Bit service to start automatically on boot...")

            # Enable Fluent Bit on boot
            result = subprocess.run(['sudo', 'systemctl', 'enable', 'fluent-bit'],
                                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.info(f"Enable command output: {result.stdout.strip()}")
            self.logger.info(f"Fluent Bit service enabled successfully.")

            # Log starting Fluent Bit service
            self.logger.info("Starting Fluent Bit service...")

            # Start Fluent Bit service
            result = subprocess.run(['sudo', 'systemctl', 'start', 'fluent-bit'],
                                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.info(f"Start command output: {result.stdout.strip()}")
            self.logger.info("Fluent Bit service started successfully.")

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
            self.logger.info("Loading Fluent Bit service plist...")

            # Load the Fluent Bit service plist
            result = subprocess.run(['sudo', 'launchctl', 'load', '/Library/LaunchDaemons/fluent-bit.plist'],
                                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.info(f"Load command output: {result.stdout.strip()}")
            self.logger.info("Fluent Bit service loaded successfully.")

            # Log enabling Fluent Bit service for automatic start
            self.logger.info("Enabling Fluent Bit service to start automatically on boot...")

            # Enable Fluent Bit service to start automatically
            result = subprocess.run(['sudo', 'launchctl', 'enable', '/Library/LaunchDaemons/fluent-bit.plist'],
                                    check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.info(f"Enable command output: {result.stdout.strip()}")
            self.logger.info("Fluent Bit service enabled successfully.")

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
        try:
            # Windows-specific installation commands
            self.logger.info("Starting the Fluent Bit service...")

            subprocess.run(['sc.exe', 'start', 'fluent-bit'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.info("Fluent Bit service started successfully.")

            self.logger.info("Configuring Fluent Bit service to start automatically on boot...")
            subprocess.run(['sc.exe', 'config', 'fluent-bit', 'start=', 'auto'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.logger.info("Fluent Bit service set to start automatically on boot.")
        except subprocess.CalledProcessError as e:
            # Log the error with the command, return code, and output
            self.logger.error(f"Command '{e.cmd}' failed with exit status {e.returncode}")
            self.logger.error(f"Error output: {e.stderr.decode() if e.stderr else 'No error output'}")
            raise

        except Exception as ex:
            # Log any unexpected errors
            self.logger.error(f"An unexpected error occurred: {ex}")
            raise

    def uninstall(self):
        self.logger.info("Uninstalling Fluent Bit...")
        system = platform.system().lower()

        if system == "linux":
            self.uninstall_linux()
        elif system == "darwin":
            self.uninstall_macos()
        elif system == "windows":
            self.uninstall_windows()
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    def uninstall_linux(self):
        package_name = "fluent-bit"
        distro_id = distro.id().lower()
        self.logger.info(f"Detected Linux distribution: {distro_id}")

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
        self.logger.info(f"Using apt to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", "apt-get", "remove", "--purge", "-y", package_name], check=True)
            subprocess.run(["sudo", "apt-get", "autoremove", "-y"], check=True)
            self.logger.info(f"Fluent Bit has been successfully uninstalled using apt.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"apt failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_dnf_yum(self, package_name, distro_id):
        package_manager = "dnf" if distro_id in ["fedora", "rocky", "almalinux"] else "yum"
        self.logger.info(f"Using {package_manager} to uninstall {package_name}...")
        try:
            subprocess.run(["sudo", package_manager, "remove", "-y", package_name], check=True)
            self.logger.info(f"Fluent Bit has been successfully uninstalled using {package_manager}.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"{package_manager} failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_rpm_or_dpkg(self, package_name):
        if Path('/usr/bin/dpkg').exists() or Path('/bin/dpkg').exists():
            self.logger.info(f"Using dpkg to purge {package_name}...")
            subprocess.run(["sudo", "dpkg", "--purge", package_name], check=True)
        elif Path('/usr/bin/rpm').exists() or Path('/bin/rpm').exists():
            self.logger.info(f"Using rpm to erase {package_name}...")
            subprocess.run(["sudo", "rpm", "-e", package_name], check=True)
        else:
            self.logger.error("Neither dpkg nor rpm package managers are available on this system.")
            raise EnvironmentError("No suitable package manager found for uninstallation.")

        self.logger.info(f"Fluent Bit has been successfully uninstalled using rpm/dpkg.")

    def uninstall_macos(self):
        self.logger.info("Attempting to uninstall Fluent Bit on macOS...")
        try:
            # Step 1: Remove the package receipt using pkgutil
            package_id = self.get_macos_package_id()
            if package_id:
                self.logger.info(f"Found Fluent Bit package ID: {package_id}. Removing package receipt...")
                subprocess.run(["sudo", "pkgutil", "--forget", package_id], check=True)
                self.logger.info("Package receipt removed.")
            else:
                self.logger.warning("Fluent Bit package ID not found. Skipping pkgutil --forget step.")

            # Step 2: Remove installed files and directories
            installed_paths = [
                "/opt/fluent-bit/bin/fluent-bit",
                "/opt/fluent-bit",
                "/usr/local/bin/fluent-bit",
                "/usr/local/etc/fluent-bit",
                "/usr/local/var/log/fluent-bit",
                "/usr/local/opt/fluent-bit",
                "/Library/LaunchDaemons/fluent-bit.plist",
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

            # Step 3: Unload and remove LaunchDaemon if exists
            launch_daemon = "/Library/LaunchDaemons/fluent-bit.plist"
            if Path(launch_daemon).exists():
                try:
                    subprocess.run(["sudo", "launchctl", "unload", launch_daemon], check=True)
                    self.logger.info(f"Unloaded LaunchDaemon: {launch_daemon}")
                except subprocess.CalledProcessError as e:
                    self.logger.error(f"Failed to unload LaunchDaemon {launch_daemon}: {e}")

            self.logger.info("Fluent Bit has been successfully uninstalled from macOS.")
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to uninstall Fluent Bit on macOS: {e}")
            raise
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during Fluent Bit uninstallation on macOS: {e}")
            raise

    def get_macos_package_id(self):
        """
        Retrieves the Fluent Bit package identifier using pkgutil.
        Assumes the package ID contains 'fluent-bit'.
        """
        try:
            result = subprocess.run(["pkgutil", "--pkgs"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            packages = result.stdout.splitlines()
            for pkg in packages:
                if "fluent-bit" in pkg.lower():
                    return pkg
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to list packages with pkgutil: {e}")
        return None

    def uninstall_windows(self):
        self.logger.info("Attempting to uninstall Fluent Bit on Windows...")
        if not winreg:
            self.logger.error("winreg module is not available. Uninstallation cannot proceed on Windows.")
            return

        try:
            uninstall_command = self.get_windows_uninstall_command("Fluent Bit")
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
                self.logger.info("Fluent Bit has been successfully uninstalled from Windows.")
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
                elif Path('/usr/bin/rpm').exists() or Path('/bin/rpm').exists():
                    result = subprocess.run(
                        ["rpm", "-q", package_name],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    if result.returncode == 0:
                        # Output like 'fluent-bit-1.7.4-2.el8.x86_64'
                        return '-'.join(result.stdout.strip().split('-')[1:3])
            elif system == "darwin":
                # Implement version retrieval for macOS if needed
                pass
            elif system == "windows":
                # Implement version retrieval for Windows if needed
                pass
        except Exception as e:
            self.logger.error(f"Failed to check installed package version: {e}")
        return None