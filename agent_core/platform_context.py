# agent_core/platform_context.py
from pathlib import Path
from agent_core.os_strategy.platform_strategy import PlatformStrategy
from agent_core.os_strategy.linux_strategy import LinuxStrategy
from agent_core.os_strategy.windows_strategy import WindowsStrategy
from agent_core.os_strategy.macos_strategy import MacOSStrategy
import platform

class PlatformContext:
    def __init__(self):
        self._strategy = self.get_platform_strategy()

    def get_platform_strategy(self) -> PlatformStrategy:
        system = platform.system()
        if system == "Linux":
            return LinuxStrategy()
        elif system == "Windows":
            return WindowsStrategy()
        elif system == "Darwin":
            return MacOSStrategy()
        else:
            raise ValueError(f"Unsupported platform: {system}")

    def create_directory(self, path: Path):
        self._strategy.create_directory(path)

    def move_file(self, src: Path, dest: Path):
        self._strategy.move_file(src, dest)

    def set_permissions(self, path: Path, permissions: str):
        self._strategy.set_permissions(path, permissions)

    def run_command(self, command: list):
        self._strategy.run_command(command)
