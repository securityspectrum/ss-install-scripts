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
        Ensures the script is running with root/admin privileges.
        If not, it re-runs the script with the necessary privileges.
        """
        system = platform.system().lower()

        if system == "windows":
            # For Windows, check if the script is running as admin
            if not SystemUtility.is_admin():
                logger.info("Requesting admin privileges on Windows...")
                try:
                    # Prepare the current environment variables to be passed to the elevated process
                    env_vars = ' '.join([f'{key}="{value}"' for key, value in os.environ.items()])

                    # Re-run the script as administrator with current environment variables
                    command = f'cmd.exe /c {env_vars} && "{sys.executable}" ' + ' '.join(sys.argv)

                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", "cmd.exe", f'/C {command}', None, 1
                    )
                    sys.exit(0)  # Exit the non-admin instance of the script
                except Exception as e:
                    logger.error(f"Failed to elevate privileges on Windows: {e}")
                    sys.exit(1)
            else:
                logger.info("Script is already running with admin privileges.")
        elif system in ["linux", "darwin"]:
            # For Unix-like systems (Linux/macOS), check if the script is running as root
            if os.geteuid() != 0:
                logger.info("Elevating script privileges with sudo...")
                try:
                    # Re-run the script with sudo, preserving the environment
                    subprocess.run(['sudo', '-E', sys.executable] + sys.argv, check=True)
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to elevate privileges with sudo: {e}")
                    sys.exit(1)
                sys.exit(0)  # Exit the non-root process after relaunching with sudo
            else:
                logger.info("Script is already running with root privileges.")

    @staticmethod
    def is_admin():
        """
        Check if the script is running with administrator (Windows) or root (Linux/macOS) privileges.
        Returns:
            bool: True if running as admin/root, False otherwise.
        """
        system = platform.system().lower()

        if system == "windows":
            try:
                return ctypes.windll.shell32.IsUserAnAdmin() == 1
            except Exception as e:
                print(f"Error checking admin privileges on Windows: {e}")
                return False
        elif system in ["linux", "darwin"]:
            return os.geteuid() == 0
        else:
            raise NotImplementedError(f"Unsupported operating system: {system}")


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

    @staticmethod
    def is_admin():
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

    @staticmethod
    def request_admin_access():
        if not SystemUtility.is_admin():
            # Re-run the script with admin rights
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()