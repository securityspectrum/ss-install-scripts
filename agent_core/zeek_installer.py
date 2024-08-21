import platform
import subprocess
import distro
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ZeekInstaller:
    def __init__(self):
        self.system = platform.system().lower()
        self.distro_name = distro.id().lower()
        self.version = distro.version().split('.')[0]
        self.architecture = platform.machine()

    def install_zeek(self):
        if self.system != "linux":
            logger.error(f"Zeek installation is only supported on Linux systems. Detected system: {self.system}")
            raise NotImplementedError(f"Unsupported OS: {self.system}")

        installed_version = self.get_installed_zeek_version()

        if "debian" in self.distro_name or "ubuntu" in self.distro_name:
            self.install_zeek_debian_ubuntu(installed_version)
        elif "centos" in self.distro_name:
            if self.version == "7":
                self.install_zeek_centos7(installed_version)
            else:
                logger.error(f"Unsupported CentOS version: {self.version}")
                raise NotImplementedError(f"Unsupported CentOS version: {self.version}")
        elif "fedora" in self.distro_name or "opensuse" in self.distro_name or "raspbian" in self.distro_name:
            self.install_zeek_fedora_opensuse_raspbian(installed_version)
        else:
            logger.error(f"Unsupported Linux distribution: {self.distro_name}")
            raise NotImplementedError(f"Unsupported Linux distribution: {self.distro_name}")

    def get_installed_zeek_version(self):
        try:
            output = subprocess.check_output(["zeek", "--version"], stderr=subprocess.STDOUT).decode()
            installed_version = output.split()[2]  # Assumes "Zeek version x.x.x"
            logger.info(f"Installed Zeek version: {installed_version}")
            return installed_version
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.info("Zeek is not currently installed.")
            return None

    def check_if_update_needed(self, installed_version, new_version):
        if installed_version and installed_version == new_version:
            logger.info(f"Zeek {new_version} is already installed. Skipping installation.")
            return False
        elif installed_version and installed_version != new_version:
            logger.info(f"A different version of Zeek ({installed_version}) is installed. Updating to version {new_version}.")
            return True
        else:
            logger.info(f"Zeek {new_version} is not installed. Proceeding with installation.")
            return True

    def install_zeek_debian_ubuntu(self, installed_version):
        # Implementation for Debian/Ubuntu (same as before)
        pass

    def install_zeek_centos7(self, installed_version):
        new_version = "6.0.5"
        if not self.check_if_update_needed(installed_version, new_version):
            return

        # Import GPG key for the repository
        gpg_key_url = "https://download.opensuse.org/repositories/security:/zeek/RPM-GPG-KEY-security"
        self.run_command(f"sudo rpm --import {gpg_key_url}")

        # Install RPM package with dependencies
        package_url = "https://download.opensuse.org/repositories/security:/zeek/CentOS_7/x86_64/zeek-6.0-6.0.5-1.1.x86_64.rpm"
        self.remove_conflicting_zeek_packages()  # Remove conflicting packages
        self.download_and_install_rpm(package_url)

    def install_zeek_fedora_opensuse_raspbian(self, installed_version):
        package_map = {
            "fedora": {
                "40": "Fedora_40",
                "39": "Fedora_39",
                "38": "Fedora_38"
            },
            "opensuse": {
                "tumbleweed": "openSUSE_Tumbleweed",
                "15.6": "15.6",
                "15.5": "15.5"
            },
            "raspbian": {
                "12": "Raspbian_12",
                "11": "Raspbian_11"
            }
        }

        if self.distro_name in package_map:
            repo_name = package_map[self.distro_name].get(self.version)
            if repo_name:
                new_version = "7.0.0"
                if not self.check_if_update_needed(installed_version, new_version):
                    return

                # Import GPG key for the repository
                gpg_key_url = "https://download.opensuse.org/repositories/security:/zeek/RPM-GPG-KEY-security"
                self.run_command(f"sudo rpm --import {gpg_key_url}")

                if self.distro_name == "raspbian":
                    package_url = f"https://download.opensuse.org/repositories/security:/zeek/{repo_name}/armhf/zeek_7.0_7.0.0-0_armhf.deb"
                    self.download_and_install_deb(package_url)
                else:
                    self.remove_conflicting_zeek_packages()  # Remove conflicting packages
                    package_url = f"https://download.opensuse.org/repositories/security:/zeek/{repo_name}/{self.architecture}/zeek-7.0.0-2.1.{self.architecture}.rpm"
                    self.download_and_install_rpm(package_url)
            else:
                logger.error(f"Unsupported {self.distro_name} version: {self.version}")
                raise NotImplementedError(f"Unsupported {self.distro_name} version: {self.version}")
        else:
            logger.error(f"Unsupported distribution for Zeek installation: {self.distro_name}")
            raise NotImplementedError(f"Unsupported distribution for Zeek installation: {self.distro_name}")

    def download_and_install_deb(self, url):
        dest_path = Path("/tmp") / Path(url).name
        self.run_command(f"curl -o {dest_path} -L {url}")
        self.run_command(f"sudo dpkg -i {dest_path}")

    def download_and_install_rpm(self, url):
        dest_path = Path("/tmp") / Path(url).name
        self.run_command(f"curl -o {dest_path} -L {url}")
        try:
            self.run_command(f"sudo rpm -Uvh {dest_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"RPM installation failed: {e}")
            # Attempt to resolve dependencies automatically
            logger.info("Attempting to install missing dependencies...")
            self.run_command(f"sudo dnf install -y {dest_path}")

    def remove_conflicting_zeek_packages(self):
        logger.info("Removing conflicting Zeek packages...")
        conflicting_packages = [
            "zeek-lts-core", "zeek-lts-client", "zeekctl-lts",
            "zeek-lts-devel", "zeek-lts-spicy-devel", "zeek-lts-btest-data",
            "zeek-lts-btest", "libbroker-lts-devel", "zeek-lts-zkg", "zeek-lts"
        ]
        for pkg in conflicting_packages:
            self.run_command(f"sudo rpm -e {pkg} --nodeps || true")

    def run_command(self, command):
        try:
            subprocess.run(command, shell=True, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {command}")
            logger.error(e)
            raise
