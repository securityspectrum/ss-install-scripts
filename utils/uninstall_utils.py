import logging
import platform
import subprocess
import shutil
from pathlib import Path
import os
import sys
import tempfile
import distro

try:
    import winreg
except ImportError:
    winreg = None
logger = logging.getLogger("InstallationLogger")
quiet_install = (logger.getEffectiveLevel() > logging.DEBUG)


class UninstallUtils:
    @staticmethod
    def stop_and_remove_service(service_name, service_path=None):
        """
        Generic method to stop and remove a service across different platforms.

        Args:
            service_name: Name of the service to stop and remove
            service_path: Path to service definition file (for Linux/macOS)
        """
        system = platform.system().lower()
        logger.info(f"Stopping service: {service_name}")

        if system == "windows":
            UninstallUtils.stop_and_remove_windows_service(service_name)
        elif system == "linux":
            UninstallUtils.stop_and_remove_linux_service(service_name, service_path)
        elif system == "darwin":
            UninstallUtils.stop_and_remove_macos_service(service_name, service_path)
        else:
            logger.warning(f"Unsupported OS: {system} for service removal")

    @staticmethod
    def stop_and_remove_windows_service(service_name):
        """Stop and remove a Windows service."""
        try:
            # Check if service exists
            result = subprocess.run(['sc.exe', 'query', service_name],
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    text=True)

            service_exists = 'SERVICE_NAME: ' + service_name in result.stdout
            if not service_exists:
                logger.debug(f"Service '{service_name}' not found. Nothing to stop or delete.")
                return
            # Stop service if running
            if "RUNNING" in result.stdout:
                logger.debug(f"Stopping service: {service_name}")
                subprocess.run(['sc.exe', 'stop', service_name],
                               check=True,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               text=True)

            # Delete service
            logger.debug(f"Removing service: {service_name}")
            subprocess.run(['sc.exe', 'delete', service_name],
                           check=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           text=True)

            logger.debug(f"Service '{service_name}' removed successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to stop/remove service {service_name}: {e}")  # Continue with uninstallation even if service removal fails
        except Exception as ex:
            logger.error(f"Unexpected error when removing service {service_name}: {ex}")

    @staticmethod
    def stop_and_remove_linux_service(service_name, service_path=None):
        """Stop and remove a Linux systemd service."""
        try:
            # Attempt to stop the service
            logger.debug(f"Stopping service: {service_name}")
            subprocess.run(['systemctl', 'stop', service_name],
                           check=False,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

            # Disable service to prevent automatic restart
            logger.debug(f"Disabling service: {service_name}")
            subprocess.run(['systemctl', 'disable', service_name],
                           check=False,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

            # If service path is provided, remove the service file
            if service_path and Path(service_path).exists():
                logger.debug(f"Removing service file: {service_path}")
                subprocess.run(['sudo', 'rm', service_path],
                               check=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

                # Reload systemd
                logger.debug("Reloading systemd daemon")
                subprocess.run(['systemctl', 'daemon-reload'],
                               check=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

            logger.debug(f"Service '{service_name}' removed successfully")
        except Exception as e:
            logger.error(f"Failed to stop/remove service {service_name}: {e}")

    @staticmethod
    def stop_and_remove_macos_service(service_name, service_path=None):
        """Stop and remove a macOS service (launchd plist)."""
        try:
            service_path = service_path or f"/Library/LaunchDaemons/{service_name}.plist"
            # Attempt to stop the service
            logger.debug(f"Stopping service: {service_name}")
            subprocess.run(['sudo', 'launchctl', 'unload', service_path],
                           check=False,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)

            # Remove the service plist if path is provided
            if Path(service_path).exists():
                logger.debug(f"Removing service plist: {service_path}")
                subprocess.run(['sudo', 'rm', service_path],
                               check=False,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

            logger.debug(f"Service '{service_name}' removed successfully")
        except Exception as e:
            logger.error(f"Failed to stop/remove service {service_name}: {e}")

    @staticmethod
    def remove_configurations(paths_to_remove, component_name):
        """
        Generic method to remove configuration files and directories.
        Handles both files and directories, and cleans up empty parent directories.

        Args:
            paths_to_remove: List of Path objects or strings to remove
            component_name: Name of the component for logging purposes
        """
        logger.info(f"Removing {component_name} configurations...")
        removed = False
        system = platform.system().lower()

        # Convert all paths to Path objects
        paths = [Path(p) if not isinstance(p, Path) else p for p in paths_to_remove]

        # Track parent directories for cleanup
        unique_dirs = set()

        for path in paths:
            if not path.exists():
                logger.debug(f"Path does not exist, skipping: {path}")
                continue

            try:
                if path.is_dir():
                    unique_dirs.add(path)
                    logger.debug(f"Removing directory: {path}")
                    # Use sudo on Linux/macOS systems for directories
                    if system in ["linux", "darwin"]:
                        subprocess.run(['sudo', 'rm', '-rf', str(path)],
                                       check=False,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                    else:
                        shutil.rmtree(path)
                    removed = True
                elif path.is_file() or path.is_symlink():
                    unique_dirs.add(path.parent)
                    logger.debug(f"Removing file: {path}")
                    # Use sudo on Linux/macOS systems for files
                    if system in ["linux", "darwin"]:
                        subprocess.run(['sudo', 'rm', '-f', str(path)],
                                       check=False,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                    else:
                        path.unlink()
                    removed = True
            except Exception as e:
                logger.error(f"Failed to remove {path}: {e}")

        # Clean up empty parent directories
        for dir_path in unique_dirs:
            if dir_path.exists() and dir_path.is_dir():
                try:
                    # Check if directory is empty
                    is_empty = not any(dir_path.iterdir())
                    if is_empty:
                        logger.debug(f"Removing empty directory: {dir_path}")
                        # Use sudo on Linux/macOS systems
                        if system in ["linux", "darwin"]:
                            subprocess.run(['sudo', 'rmdir', str(dir_path)],
                                           check=False,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                        else:
                            dir_path.rmdir()
                except Exception as e:
                    logger.error(f"Failed to remove empty directory {dir_path}: {e}")

        if removed:
            logger.debug(f"{component_name} configurations removed successfully")
        else:
            logger.debug(f"No {component_name} configurations were found to remove")

    @staticmethod
    def remove_paths(paths, remove_empty_parents=True):
        """
        Safely remove files and directories.

        Args:
            paths: List of Path objects or strings to remove
            remove_empty_parents: Whether to remove empty parent directories after removal
        """
        paths = [Path(p) if not isinstance(p, Path) else p for p in paths]
        removed_paths = []
        system = platform.system().lower()

        for path in paths:
            if not path.exists():
                logger.debug(f"Path does not exist, skipping: {path}")
                continue

            try:
                if path.is_file() or path.is_symlink():
                    logger.debug(f"Removing file: {path}")
                    # Use sudo on Linux/macOS systems
                    if system in ["linux", "darwin"]:
                        subprocess.run(['sudo', 'rm', '-f', str(path)],
                                       check=False,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                    else:
                        path.unlink()
                    removed_paths.append(path)
                elif path.is_dir():
                    logger.debug(f"Removing directory: {path}")
                    # Use sudo on Linux/macOS systems
                    if system in ["linux", "darwin"]:
                        subprocess.run(['sudo', 'rm', '-rf', str(path)],
                                       check=False,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
                    else:
                        shutil.rmtree(path)
                    removed_paths.append(path)
            except Exception as e:
                logger.error(f"Failed to remove {path}: {e}")

        # Remove empty parent directories if requested
        if remove_empty_parents:
            parent_dirs = {p.parent for p in removed_paths if p.parent.exists()}
            for parent in parent_dirs:
                try:
                    # Check if directory is empty
                    is_empty = parent.exists() and not any(parent.iterdir())
                    if is_empty:
                        logger.debug(f"Removing empty parent directory: {parent}")
                        # Use sudo on Linux/macOS systems
                        if system in ["linux", "darwin"]:
                            subprocess.run(['sudo', 'rmdir', str(parent)],
                                           check=False,
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
                        else:
                            parent.rmdir()
                except Exception as e:
                    logger.error(f"Failed to remove empty parent directory {parent}: {e}")

    @staticmethod
    def uninstall_with_package_manager(package_name, options=None):
        """
        Uninstall a package using the appropriate package manager for the current OS.

        Args:
            package_name: Name of the package to uninstall
            options: Additional options to pass to the package manager
        """
        options = options or []
        system = platform.system().lower()
        logger.info(f"Uninstalling package {package_name}...")

        if system == "linux":
            # Determine the package manager
            dist_id = distro.id().lower()

            try:
                if dist_id in ["debian", "ubuntu"] or os.path.exists("/usr/bin/apt-get"):
                    logger.debug(f"Using apt-get to remove {package_name}")
                    cmd = ["sudo", "apt-get", "remove", "--purge", "-y", package_name] + options
                    subprocess.run(cmd, check=False)

                elif dist_id in ["centos", "rhel", "fedora"] or os.path.exists("/usr/bin/rpm"):
                    if os.path.exists("/usr/bin/dnf"):
                        logger.debug(f"Using dnf to remove {package_name}")
                        cmd = ["sudo", "dnf", "remove", "-y", package_name] + options
                    else:
                        logger.debug(f"Using yum to remove {package_name}")
                        cmd = ["sudo", "yum", "remove", "-y", package_name] + options
                    subprocess.run(cmd, check=False)

                else:
                    logger.warning(f"Unsupported Linux distribution for package removal: {dist_id}")
                    return False

                logger.debug(f"Package {package_name} removed successfully")
                return True

            except Exception as e:
                logger.error(f"Failed to uninstall package {package_name}: {e}")
                return False

        elif system == "darwin":
            try:
                if os.path.exists("/usr/local/bin/brew"):
                    logger.debug(f"Using Homebrew to uninstall {package_name}")
                    subprocess.run(["brew", "uninstall", package_name] + options, check=False)
                    return True
                else:
                    logger.warning("Homebrew not found for package removal on macOS")
                    return False
            except Exception as e:
                logger.error(f"Failed to uninstall package {package_name} on macOS: {e}")
                return False

        else:
            logger.warning(f"Package manager uninstallation not supported on {system}")
            return False

    @staticmethod
    def uninstall_windows_from_registry(product_name):
        """
        Uninstall a Windows application using its registry uninstaller.

        Args:
            product_name: Name of the product to uninstall (used to search registry)

        Returns:
            bool: True if uninstallation was successful, False otherwise
        """
        if not winreg:
            logger.error("winreg module is not available. Cannot access Windows Registry.")
            return False

        logger.info(f"Attempting to uninstall {product_name} using registry information...")

        # Get the uninstall command from registry
        uninstall_cmd = UninstallUtils.get_windows_uninstall_command(product_name)
        if not uninstall_cmd:
            logger.warning(f"No uninstall command found for {product_name}")
            return False

        logger.debug(f"Found uninstall command: {uninstall_cmd}")

        try:
            # Many uninstall strings use MsiExec.exe, so handle that case
            if "msiexec" in uninstall_cmd.lower():
                # Make sure it runs silently
                if "/i" in uninstall_cmd:
                    # Change /i to /x for uninstall
                    uninstall_cmd = uninstall_cmd.replace("/i", "/x")
                if "/quiet" not in uninstall_cmd and "/q" not in uninstall_cmd:
                    uninstall_cmd += " /quiet"

                logger.debug(f"Running MSI uninstaller: {uninstall_cmd}")
                # MSI installers often use quotes in the command, so use shell=True
                subprocess.run(uninstall_cmd, shell=True, check=True)
            else:
                # Handle other uninstall commands
                logger.debug(f"Running uninstaller: {uninstall_cmd} /S")
                # Add /S for silent uninstall if not already present
                if "/S" not in uninstall_cmd and "/s" not in uninstall_cmd:
                    uninstall_cmd += " /S"
                subprocess.run(uninstall_cmd, shell=True, check=True)

            logger.debug(f"Successfully uninstalled {product_name}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to uninstall {product_name} on Windows: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during {product_name} uninstallation on Windows: {e}")

        return False

    @staticmethod
    def get_windows_uninstall_command(product_name):
        """Get the uninstall command from Windows registry for a product."""
        try:
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
                            with winreg.OpenKey(root, f"{subkey}\\{subkey_name}") as key:
                                display_name = winreg.QueryValueEx(key, "DisplayName")[0]
                                if product_name.lower() in display_name.lower():
                                    return winreg.QueryValueEx(key, "UninstallString")[0]
                        except Exception:
                            continue
            return None
        except Exception as e:
            logger.error(f"Error accessing registry: {e}")
            return None