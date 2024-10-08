import os
import platform
import subprocess
import shutil
import ctypes
import sys
import logging

logger = logging.getLogger('InstallationLogger')


class SystemUtility:
    @staticmethod
    def elevate_privileges():
        """
        Ensures the script is running with root privileges. If not, it re-runs the script with 'sudo'.
        """
        system = platform.system().lower()

        if system == "windows":
            # For Windows, check if the script is running as admin
            if not SystemUtility.is_admin():
                logger.info("Requesting admin privileges on Windows...")
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
                sys.exit(0)
        else:
            # Check if the script is already running as root (for Unix-like systems: Linux/macOS)
            if os.geteuid() != 0:
                logger.info("Elevating script privileges with sudo...")
                try:
                    # Re-run the current script with sudo using the current Python interpreter
                    subprocess.run(['sudo', '-E', sys.executable] + sys.argv, check=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to elevate privileges: {e}")
                    sys.exit(1)
                sys.exit(0)  # Exit the non-root process after relaunching with sudo

    @staticmethod
    def is_admin():
        try:
            # For Unix-like systems, check if the user is root
            return os.geteuid() == 0
        except AttributeError:
            # For Windows, check if the script is running as admin
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False

    @staticmethod
    def run_command(command, check=True, shell=False):
        try:
            logger.info(f"Running command: {' '.join(command)}")
            subprocess.run(command, check=check, shell=shell)
            logger.info(f"Command completed successfully: {' '.join(command)}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e}")
            if check:
                sys.exit(1)

    @staticmethod
    def move_with_sudo(src, dest):
        logger.info(f"Moving {src} to {dest} with sudo")
        if platform.system() == "Windows":
            shutil.move(src, dest)
        else:
            SystemUtility.run_command(["sudo", "mv", src, dest])

    @staticmethod
    def create_directories(dirs):
        for dir in dirs:
            if not dir.exists():
                logger.info(f"Creating directory: {dir}")
                if platform.system() == "Windows":
                    dir.mkdir(parents=True, exist_ok=True)
                else:
                    SystemUtility.run_command(["sudo", "mkdir", "-p", str(dir)])

    @staticmethod
    def get_distro():
        logger.info("Getting OS distribution info...")
        if platform.system() == "Linux":
            try:
                distro = subprocess.check_output(['lsb_release', '-is']).decode().strip().lower()
                version = subprocess.check_output(['lsb_release', '-rs']).decode().strip()
            except FileNotFoundError:
                with open('/etc/os-release') as f:
                    lines = f.readlines()
                    distro = next((line.split('=')[1].strip().strip('"').lower() for line in lines if line.startswith('ID=')), None)
                    version = next((line.split('=')[1].strip().strip('"') for line in lines if line.startswith('VERSION_ID=')), None)
        elif platform.system() == "Darwin":
            distro = "macos"
            version = platform.mac_ver()[0]
        elif platform.system() == "Windows":
            distro = "windows"
            version = platform.version()
        else:
            distro = "unknown"
            version = "unknown"

        logger.debug(f"Operating System: {platform.system()}")
        logger.debug(f"Distribution: {distro}")
        logger.debug(f"Version: {version}")

        return distro, version

    @staticmethod
    def has_winreg():
        """
        Checks if the winreg module is available.
        """
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
