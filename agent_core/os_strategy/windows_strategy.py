# agent_core/os_strategy/windows_strategy.py
import subprocess
from agent_core.os_strategy.platform_strategy import PlatformStrategy
from pathlib import Path
import shutil
import logging

logger = logging.getLogger('InstallationLogger')

class WindowsStrategy(PlatformStrategy):
    def get_cert_dir(self) -> Path:
        return Path("C:\\Program Files\\ss-agent\\ssl")

    def get_config_dir(self) -> Path:
        return Path("C:\\Program Files\\ss-agent\\config")

    def get_fluent_bit_config_path(self) -> Path:
        return Path("C:\\Program Files\\fluent-bit\\ss-fluent-bit.conf")

    def get_fluent_bit_ssl_path(self) -> Path:
        return Path("C:\\Program Files\\fluent-bit\\ssl")

    def create_directory(self, path: Path):
        try:
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created directory: {path}")
        except Exception as e:
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
                    dir.mkdir(parents=True, exist_ok=True)
                    logger.debug(f"Created directory: {dir}")
                except Exception as e:
                    logger.error(f"Error creating directory {dir}: {e}")

    def move_file(self, src: Path, dest: Path):
        shutil.move(str(src), str(dest))

    def set_permissions(self, path: Path, permissions: str):
        # Windows-specific permission setting logic
        pass

    def run_command(self, command: list):
        subprocess.run(command, shell=True, check=True)
