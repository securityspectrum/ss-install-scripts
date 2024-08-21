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
    def request_sudo():
        if platform.system() != "Windows":
            logger.info("Requesting sudo access...")
            try:
                subprocess.run(["sudo", "-v"], check=True)
                logger.info("Sudo access granted.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error: {e}")
                sys.exit(1)
        else:
            if not SystemUtility.is_admin():
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
                logger.info("Sudo access granted.")
                input("Press any key to exit...")
                sys.exit(1)

    @staticmethod
    def is_admin():
        try:
            return os.getuid() == 0
        except AttributeError:
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
