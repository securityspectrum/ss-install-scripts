# agent_core/os_strategy/macos_strategy.py
from agent_core.os_strategy.platform_strategy import PlatformStrategy
from pathlib import Path
import subprocess
import shutil
import logging

logger = logging.getLogger('InstallationLogger')

class MacOSStrategy(PlatformStrategy):
    def get_cert_dir(self) -> Path:
        return Path("/etc/ss-agent/ssl")

    def get_config_dir(self) -> Path:
        return Path("/etc/ss-agent/config")

    def get_fluent_bit_config_path(self) -> Path:
        return Path("/etc/fluent-bit/ss-fluent-bit.conf")

    def get_fluent_bit_ssl_path(self) -> Path:
        return Path("/etc/fluent-bit/ssl")

    def create_directory(self, path: Path):
        try:
            if not path.exists():
                subprocess.run(["sudo", "mkdir", "-p", str(path)], check=True)
                logger.debug(f"Created directory: {path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Error creating directory {path}: {e}")
            
    def create_directories(self):
        dirs = [
            self.get_fluent_bit_config_path().parent,
            self.get_cert_dir(),
            self.get_config_dir()
        ]
        for dir in dirs:
            if not dir.exists():
                try:
                    subprocess.run(["sudo", "mkdir", "-p", str(dir)], check=True)
                    logger.debug(f"Created directory: {dir}")
                except Exception as e:
                    logger.error(f"Error creating directory {dir}: {e}")

    def move_file(self, src: Path, dest: Path):
        subprocess.run(["sudo", "mv", str(src), str(dest)], check=True)

    def set_permissions(self, path: Path, permissions: str):
        subprocess.run(["sudo", "chmod", permissions, str(path)], check=True)

    def run_command(self, command: list):
        subprocess.run(command, check=True)
