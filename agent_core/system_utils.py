import os
import platform
import subprocess
import shutil
import ctypes
import sys
import logging
import time

logger = logging.getLogger('InstallationLogger')


class SystemUtility:

    @staticmethod
    def elevate_privileges():
        """
        Ensures the script is running with root/admin privileges.
        If not, it re-runs the script with the necessary privileges.
        """
        system = platform.system().lower()
        if system == "windows":
            # For Windows, check if the script is running as admin
            if not SystemUtility.is_admin():
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Requesting admin privileges on Windows...")
                try:
                    # Absolute path to the script
                    script = os.path.abspath(sys.argv[0])
                    # Prepare arguments: ensure each argument is quoted
                    args = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
                    # Command to execute: Python executable, script path, and arguments
                    command = f'"{sys.executable}" "{script}" {args}'
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug(f"Elevation command: {command}")
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {args}', None, 1)
                    sys.exit(0)
                except Exception as e:
                    logger.error(f"Failed to elevate privileges on Windows: {e}")
                    sys.exit(1)
            else:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Script is already running with admin privileges.")
        elif system in ["linux", "darwin"]:
            # For Unix-like systems (Linux/macOS), check if the script is running as root
            if os.geteuid() != 0:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Elevating script privileges with sudo...")
                try:
                    subprocess.run(['sudo', '-E', sys.executable] + sys.argv, check=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to elevate privileges with sudo: {e}")
                    sys.exit(1)
                sys.exit(0)
            else:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug("Script is already running with root privileges.")

    @staticmethod
    def is_admin():
        system = platform.system().lower()
        if system == "windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() == 1
            except Exception as e:
                logger.error(f"Error checking admin privileges on Windows: {e}")
                return False
        elif system in ["linux", "darwin"]:
            return os.geteuid() == 0
        else:
            raise NotImplementedError(f"Unsupported operating system: {system}")

    @staticmethod
    def run_command_with_retries(command, logger, retries=3, delay=5, backoff=2, success_predicate=None, quiet=False):
        """
        Executes a shell command with retries and exponential backoff.
        If quiet is True, suppress stdout and stderr.
        """
        attempt = 0
        current_delay = delay
        while attempt <= retries:
            try:
                logger.debug(f"Executing command: {' '.join(command)} (Attempt {attempt + 1})")
                if quiet:
                    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
                else:
                    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if success_predicate:
                    is_success = success_predicate(result)
                else:
                    is_success = result.returncode == 0
                if is_success:
                    logger.debug(f"Command succeeded: {' '.join(command)}")
                    return result
                else:
                    logger.debug(f"Command failed with return code {result.returncode}: {' '.join(command)}")
                    if not quiet:
                        logger.debug(f"stderr: {result.stderr.strip()}")
            except Exception as e:
                logger.error(f"Exception occurred while executing command {' '.join(command)}: {e}")
            attempt += 1
            if attempt > retries:
                break
            logger.debug(f"Retrying after {current_delay} seconds...")
            time.sleep(current_delay)
            current_delay *= backoff
        logger.error(f"All {retries} attempts failed for command: {' '.join(command)}")
        return None

    @staticmethod
    def run_command(command, check=True, shell=False, quiet=False):
        """
        Executes a shell command.
        If quiet is True, suppress stdout and stderr.
        """
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Running command: {' '.join(command)}")
        try:
            if quiet:
                subprocess.run(command, check=check, shell=shell,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                subprocess.run(command, check=check, shell=shell)
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Command completed successfully: {' '.join(command)}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e}")
            if check:
                sys.exit(1)

    @staticmethod
    def move_with_sudo(src, dest, logger_instance=None, quiet=False):
        """
        Moves a file from src to dest using sudo if necessary.
        Accepts an optional quiet flag to suppress command output.
        """
        log = logger_instance or logging.getLogger(__name__)
        try:
            if not os.path.exists(src):
                log.error(f"Source file does not exist: {src}")
                return False
            if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                dest_dir = os.path.dirname(dest)
                if not os.access(dest_dir, os.W_OK):
                    command = ['sudo', 'mv', src, dest]
                    result = SystemUtility.run_command_with_retries(command, log, quiet=quiet)
                    if result and result.returncode != 0:
                        log.error(f"Failed to move {src} to {dest} with sudo.")
                        return False
                    log.debug(f"Successfully moved {src} to {dest} with sudo.")
                    chmod_command = ['sudo', 'chmod', '644', dest]
                    chmod_result = SystemUtility.run_command_with_retries(chmod_command, log, quiet=quiet)
                    if chmod_result and chmod_result.returncode != 0:
                        log.error(f"Failed to set permissions for {dest}.")
                        return False
                    log.debug(f"Permissions set for {dest}.")
                else:
                    shutil.move(src, dest)
                    log.debug(f"Successfully moved {src} to {dest}.")
                    os.chmod(dest, 0o644)
                    log.debug(f"Permissions set for {dest}.")
            elif sys.platform.startswith('win'):
                shutil.move(src, dest)
                log.debug(f"Successfully moved {src} to {dest}.")
                os.chmod(dest, 0o644)
                log.debug(f"Permissions set for {dest}.")
            else:
                log.error(f"Unsupported platform: {sys.platform}")
                return False
            return True
        except Exception as e:
            log.error(f"Exception occurred while moving file: {e}")
            return False

    @staticmethod
    def create_directories(dirs):
        for dir in dirs:
            if not dir.exists():
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Creating directory: {dir}")
                if platform.system() == "Windows":
                    dir.mkdir(parents=True, exist_ok=True)
                else:
                    SystemUtility.run_command(["sudo", "mkdir", "-p", str(dir)])

    @staticmethod
    def get_distro():
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Getting OS distribution info...")
        if platform.system() == "Linux":
            try:
                distro = subprocess.check_output(['lsb_release', '-is']).decode().strip().lower()
                version = subprocess.check_output(['lsb_release', '-rs']).decode().strip()
            except FileNotFoundError:
                with open('/etc/os-release') as f:
                    lines = f.readlines()
                    distro = next(
                        (line.split('=')[1].strip().strip('"').lower() for line in lines if line.startswith('ID=')),
                        None)
                    version = next(
                        (line.split('=')[1].strip().strip('"') for line in lines if line.startswith('VERSION_ID=')),
                        None)
        elif platform.system() == "Darwin":
            distro = "macos"
            version = platform.mac_ver()[0]
        elif platform.system() == "Windows":
            distro = "windows"
            version = platform.version()
        else:
            distro = "unknown"
            version = "unknown"
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"Operating System: {platform.system()}")
            logger.debug(f"Distribution: {distro}")
            logger.debug(f"Version: {version}")
        return distro, version

    @staticmethod
    def has_winreg():
        try:
            import winreg
            return True
        except ImportError:
            return False

    @staticmethod
    def get_windows_uninstall_command(product_name):
        """
        Searches the Windows Registry for the uninstall command of the given product.
        """
        try:
            import winreg
        except ImportError:
            logger.error("winreg module is not available. Cannot access the Windows Registry.")
            return None
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

    @staticmethod
    def is_admin_alt():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    @staticmethod
    def request_admin_access():
        if not SystemUtility.is_admin():
            # Re-run the script with admin rights
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()
