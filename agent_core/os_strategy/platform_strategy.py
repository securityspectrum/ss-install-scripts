from abc import ABC, abstractmethod
from pathlib import Path

class PlatformStrategy(ABC):
    @abstractmethod
    def get_cert_dir(self) -> Path:
        pass

    @abstractmethod
    def get_config_dir(self) -> Path:
        pass

    @abstractmethod
    def get_fluent_bit_config_path(self) -> Path:
        pass

    @abstractmethod
    def get_fluent_bit_ssl_path(self) -> Path:
        pass

    @abstractmethod
    def create_directory(self, path: Path):
        pass

    @abstractmethod
    def create_directories(self):
        pass

    @abstractmethod
    def move_file(self, src: Path, dest: Path):
        pass

    @abstractmethod
    def set_permissions(self, path: Path, permissions: str):
        pass

    @abstractmethod
    def run_command(self, command: list):
        pass
