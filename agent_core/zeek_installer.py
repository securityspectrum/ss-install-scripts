#!/usr/bin/env python3
import platform
import subprocess
import distro
import logging
from pathlib import Path
import sys
import os
import shutil

# Configure logging
from agent_core import SystemUtility

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ZeekInstaller:
    def __init__(self):
        # Fetch distribution info as a dictionary
        self.os_info = distro.info()

        # Use dictionary keys to access the OS details
        self.os_id = self.os_info.get('id', '').lower()
        self.os_like = self.os_info.get('like', '').lower()
        self.zeek_version = "7.0.1"  # Current LTS version
        self.builder_user = "builder"

        # Flag to indicate if Zeek is installed from source or package/repo
        self.source_install = False

        # Ensure the script is run as root
        self.check_root()


    def run_command(self, command, check=True, capture_output=False, shell=False, input_data=None):
        """
        Executes a system command.
        """
        logger.info(f"Executing command: {' '.join(command) if isinstance(command, list) else command}")
        try:
            result = subprocess.run(command,
                check=check,
                capture_output=capture_output,
                text=True,
                shell=shell,
                input=input_data)
            if capture_output:
                return result.stdout.strip()
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(command) if isinstance(command, list) else command}")
            logger.error(e)
            if e.stdout:
                logger.error(f"Output: {e.stdout}")
            if e.stderr:
                logger.error(f"Error Output: {e.stderr}")
            raise

    def check_root(self):
        """
        Ensures the script is run as root.
        """
        if os.geteuid() != 0:
            logger.error("This script must be run as root. Please run again with 'sudo' or as the root user.")
            # Request sudo access at the start
            SystemUtility.elevate_privileges()
        logger.info("Script is running as root.")

    def command_exists(self, command):
        """
        Checks if a command exists in the system PATH.
        """
        exists = shutil.which(command) is not None
        logger.debug(f"Command '{command}' exists: {exists}")
        return exists

    def check_zeek_installed(self):
        """
        Checks if Zeek is already installed and exits if it is.
        """
        if self.command_exists('zeek'):
            zeek_version = self.run_command(['zeek', '--version'], capture_output=True).splitlines()[0]
            logger.info(f"Zeek is already installed: {zeek_version}")
            sys.exit(0)

    def is_zeek_installed(self):
        """
        Returns True if Zeek is installed, else False.
        """
        installed = self.command_exists('zeek') or self.command_exists('zeek-config')
        logger.debug(f"Is Zeek installed: {installed}")
        return installed

    def install_utilities(self):
        """
        Installs required utilities based on the Linux distribution.
        """
        logger.info("Installing required utilities...")
        try:
            if self.os_id in ['ubuntu', 'debian'] or 'debian' in self.os_like:
                self.run_command(['apt', 'install', '-y', 'apt-transport-https', 'curl', 'gnupg', 'lsb-release'])
            elif self.os_id in ['centos', 'rhel'] or 'rhel' in self.os_like:
                self.run_command(['yum', 'install', '-y', 'epel-release', 'curl'])
            elif self.os_id == 'fedora':
                self.run_command(['dnf', 'install', '-y', 'curl', 'redhat-lsb-core'])
            elif self.os_id in ['opensuse', 'sles'] or 'suse' in self.os_like:
                self.run_command(['zypper', 'install', '-y', 'curl', 'lsb-release'])
            else:
                logger.error("Unsupported distribution for installing utilities.")
                sys.exit(1)
            logger.info("Required utilities installed successfully.")
        except Exception as e:
            logger.error("Failed to install required utilities.")
            sys.exit(1)

    def install_zeek_ubuntu(self):
        """
        Installs Zeek on Ubuntu.
        """
        logger.info("Detected Ubuntu. Proceeding with installation...")
        self.install_utilities()
        distro_version = self.run_command(['lsb_release', '-rs'], capture_output=True)
        logger.info("Configuring repository for Ubuntu...")
        try:
            # Add Zeek GPG key
            gpg_key_url = f"https://download.opensuse.org/repositories/security:zeek/xUbuntu_{distro_version}/Release.key"
            keyring_path = "/usr/share/keyrings/zeek-archive-keyring.gpg"
            # Download and store the GPG key
            gpg_output = self.run_command(['curl', '-fsSL', gpg_key_url], capture_output=True)
            self.run_command(['gpg', '--dearmor'], input_data=gpg_output, capture_output=False)
            with open(keyring_path, 'wb') as f:
                f.write(gpg_output.encode())
            # Add Zeek repository
            repo_entry = f"deb [signed-by={keyring_path}] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_{distro_version}/ /"
            self.run_command(['bash', '-c', f'echo "{repo_entry}" > /etc/apt/sources.list.d/zeek.list'])

            # Update only the Zeek repository
            self.run_command(['apt', 'update', '-o', f'Dir::Etc::sourcelist="sources.list.d/zeek.list"', '-o',
                              'Dir::Etc::sourceparts="-"', '-o', 'APT::Get::List-Cleanup="0"'])

            # Install Zeek and Zeekctl without updating other packages
            self.run_command(['apt', 'install', '-y', 'zeek', 'zeekctl'])
            logger.info("Zeek installed successfully via apt.")
        except Exception as e:
            logger.error("Package installation failed, attempting to install from source...")
            self.install_zeek_from_source()
            return
        self.configure_zeek()

    def install_zeek_debian(self):
        """
        Installs Zeek on Debian.
        """
        logger.info("Detected Debian. Proceeding with installation...")
        self.install_utilities()
        distro_version = self.run_command(['lsb_release', '-rs'], capture_output=True)
        logger.info("Configuring repository for Debian...")
        try:
            # Add Zeek GPG key
            gpg_key_url = f"https://download.opensuse.org/repositories/security:zeek/Debian_{distro_version}/Release.key"
            keyring_path = "/usr/share/keyrings/zeek-archive-keyring.gpg"

            # Download and store the GPG key
            gpg_output = self.run_command(['curl', '-fsSL', gpg_key_url], capture_output=True)
            self.run_command(['gpg', '--dearmor'], input_data=gpg_output, capture_output=False)
            with open(keyring_path, 'wb') as f:
                f.write(gpg_output.encode())

            # Add Zeek repository
            repo_entry = f"deb [signed-by={keyring_path}] http://download.opensuse.org/repositories/security:/zeek/Debian_{distro_version}/ /"
            self.run_command(['bash', '-c', f'echo "{repo_entry}" > /etc/apt/sources.list.d/zeek.list'])

            # Update only the Zeek repository
            self.run_command(['apt', 'update', '-o', f'Dir::Etc::sourcelist="sources.list.d/zeek.list"', '-o',
                              'Dir::Etc::sourceparts="-"', '-o', 'APT::Get::List-Cleanup="0"'])

            # Install Zeek and Zeekctl without updating other packages
            self.run_command(['apt', 'install', '-y', 'zeek', 'zeekctl'])
            logger.info("Zeek installed successfully via apt.")
        except Exception as e:
            logger.error("Package installation failed, attempting to install from source...")
            self.install_zeek_from_source()
            return
        self.configure_zeek()

    def install_zeek_fedora(self):
        """
        Installs Zeek on Fedora.
        """
        logger.info("Detected Fedora. Proceeding with installation...")
        self.install_utilities()
        # Update system
        self.run_command(['dnf', 'update', '-y'])
        try:
            # Try to install Zeek from default repositories
            self.run_command(['dnf', 'install', '-y', 'zeek', 'zeekctl'])
            logger.info("Zeek installed successfully via dnf.")
        except Exception as e:
            logger.info("Zeek package not found in default repositories. Adding Zeek OBS repository...")
            try:
                fedora_version = self.run_command(['rpm', '-E', '%fedora'], capture_output=True)
                gpg_key_url = f"https://download.opensuse.org/repositories/security:zeek/Fedora_{fedora_version}/repodata/repomd.xml.key"
                self.run_command(['rpm', '--import', gpg_key_url])

                # Add Zeek repository
                zeek_repo_content = f"""[zeek]
                name=Zeek repository for Fedora {fedora_version}
                baseurl=https://download.opensuse.org/repositories/security:/zeek/Fedora_{fedora_version}/
                enabled=1
                gpgcheck=1
                gpgkey=https://download.opensuse.org/repositories/security:/zeek/Fedora_{fedora_version}/repodata/repomd.xml.key
                """
                repo_file_path = "/etc/yum.repos.d/zeek.repo"
                with open(repo_file_path, 'w') as repo_file:
                    repo_file.write(zeek_repo_content)

                # Clean and refresh the Zeek repository only
                self.run_command(['dnf', 'clean', 'metadata', '--disablerepo="*"', '--enablerepo="zeek"'])
                self.run_command(['dnf', 'makecache', '--disablerepo="*"', '--enablerepo="zeek"'])

                # Install Zeek and Zeekctl from the Zeek repository only
                self.run_command(['dnf', 'install', '-y', '--disablerepo="*"', '--enablerepo="zeek"', 'zeek',
                                  'zeekctl'])

                logger.info("Zeek installed successfully via added repository.")

            except Exception as e:
                logger.error("Package installation failed, attempting to install from source...")
                self.install_zeek_from_source()
                return
        self.configure_zeek()

    def install_zeek_rhel8(self):
        """
        Installs Zeek on RHEL 8 (Stream or Vault).
        """
        logger.info("Detected RHEL 8. Proceeding with installation...")
        self.install_utilities()
        try:
            # Import Zeek GPG key for RHEL 8
            gpg_key_url = "https://download.opensuse.org/repositories/security:zeek/RHEL_8/repodata/repomd.xml.key"
            self.run_command(['rpm', '--import', gpg_key_url])
            # Add Zeek repository for RHEL 8
            zeek_repo_url = "https://download.opensuse.org/repositories/security:zeek/RHEL_8/security:zeek.repo"
            self.run_command(['curl', '-fsSL', '-o', '/etc/yum.repos.d/zeek.repo', zeek_repo_url])
            # Update system and install Zeek
            self.run_command(['yum', 'update', '-y'])
            self.run_command(['yum', 'install', '-y', 'zeek', 'zeekctl'])
            logger.info("Zeek installed successfully via yum.")
        except Exception as e:
            logger.error("Package installation failed, attempting to install from source...")
            self.install_zeek_from_source()
            return
        self.configure_zeek()

    def install_zeek_centos_rhel(self):
        """
        Determines CentOS/RHEL version and installs Zeek accordingly.
        """
        logger.info("Detected CentOS/RHEL. Proceeding with installation...")
        os_version = self.run_command(['rpm', '-E', '%rhel'], capture_output=True)
        if os_version == '8':
            self.install_zeek_rhel8()
        else:
            logger.error(f"Unsupported CentOS/RHEL version: {os_version}")
            sys.exit(1)

    def install_zeek_centos7(self):
        """
        Installs Zeek on CentOS 7.
        """
        logger.info("Detected CentOS 7. Proceeding with installation...")
        self.install_utilities()
        try:
            # Import Zeek GPG key for CentOS 7
            gpg_key_url = "https://download.opensuse.org/repositories/security:zeek/CentOS_7/repodata/repomd.xml.key"
            self.run_command(['rpm', '--import', gpg_key_url])
            # Add Zeek repository
            zeek_repo_url = "https://download.opensuse.org/repositories/security:zeek/CentOS_7/security:zeek.repo"
            self.run_command(['curl', '-fsSL', '-o', '/etc/yum.repos.d/zeek.repo', zeek_repo_url])
            # Update system and install Zeek
            self.run_command(['yum', 'update', '-y'])
            self.run_command(['yum', 'install', '-y', 'zeek', 'zeekctl'])
            logger.info("Zeek installed successfully via yum.")
        except Exception as e:
            logger.error("Package installation failed, attempting to install from source...")
            self.install_zeek_from_source()
            return
        self.configure_zeek()

    def install_zeek_centos8(self):
        """
        Installs Zeek on CentOS 8 (Stream or Vault).
        """
        logger.info("Detected CentOS 8. Proceeding with installation...")
        self.install_utilities()
        # Determine if it's CentOS 8 Stream or CentOS 8
        try:
            centos_version_info = self.run_command(['centos-release'], capture_output=True)
            if 'Stream' in centos_version_info:
                logger.info("Installing Zeek on CentOS 8 Stream...")
                # Import Zeek GPG key for CentOS 8 Stream
                gpg_key_url = "https://download.opensuse.org/repositories/security:zeek/CentOS_8_Stream/repodata/repomd.xml.key"
                self.run_command(['rpm', '--import', gpg_key_url])
                # Add Zeek repository for CentOS 8 Stream
                zeek_repo_url = "https://download.opensuse.org/repositories/security:zeek/CentOS_8_Stream/security:zeek.repo"
                self.run_command(['curl', '-fsSL', '-o', '/etc/yum.repos.d/zeek.repo', zeek_repo_url])
            else:
                logger.info("Installing Zeek on CentOS 8 (using Vault repository)...")
                # Update the repository to use CentOS Vault since CentOS 8 has reached EOL
                centos_repo_files = list(Path('/etc/yum.repos.d/').glob('CentOS-*.repo'))
                for repo_file in centos_repo_files:
                    self.run_command(['sed', '-i', 's|mirrorlist=|#mirrorlist=|g', str(repo_file)])
                    self.run_command(['sed', '-i',
                                      's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g',
                                      str(repo_file)])
                # Import Zeek GPG key for CentOS 8
                gpg_key_url = "https://download.opensuse.org/repositories/security:zeek/CentOS_8/repodata/repomd.xml.key"
                self.run_command(['rpm', '--import', gpg_key_url])
                # Add Zeek repository for CentOS 8
                zeek_repo_url = "https://download.opensuse.org/repositories/security:zeek/CentOS_8/security:zeek.repo"
                self.run_command(['curl', '-fsSL', '-o', '/etc/yum.repos.d/zeek.repo', zeek_repo_url])
            # Update system and install Zeek
            self.run_command(['yum', 'update', '-y'])
            self.run_command(['yum', 'install', '-y', 'zeek', 'zeekctl'])
            logger.info("Zeek installed successfully via yum.")
        except Exception as e:
            logger.error("Failed to detect CentOS version or install Zeek.")
            sys.exit(1)
        self.configure_zeek()

    def install_zeek_opensuse(self):
        """
        Installs Zeek on openSUSE. If repository installation fails, it falls back to installing from source.
        """
        if self.is_zeek_installed():
            logger.info("Zeek is already installed.")
            self.run_command(['zeek', '--version'])
            return

        # Detect openSUSE version and get repository URLs
        repo_urls = self.get_opensuse_repo_urls()

        # Attempt to install Zeek via repository
        try:
            self.install_zeek_from_repo(repo_urls)
        except Exception as e:
            logger.error(f"Repository installation failed: {e}")
            logger.info("Falling back to building Zeek from source.")
            self.install_zeek_from_source_opensuse()

        # Final verification
        if self.is_zeek_installed():
            logger.info("Zeek installed successfully.")
            self.run_command(['zeek', '--version'])
            self.configure_zeek()
        else:
            logger.error("Zeek installation failed.")
            sys.exit(1)

    def get_opensuse_repo_urls(self):
        """
        Returns appropriate repository URLs based on the detected openSUSE version.
        """
        os_release = self.run_command(['cat', '/etc/os-release'], capture_output=True)
        name = ""
        version_id = ""

        for line in os_release.splitlines():
            if line.startswith('NAME='):
                name = line.split('=')[1].strip('"')
            elif line.startswith('VERSION_ID='):
                version_id = line.split('=')[1].strip('"')

        if name == "openSUSE Tumbleweed":
            return {"zeek": "https://download.opensuse.org/repositories/security:zeek/openSUSE_Tumbleweed/",
                "python": "https://download.opensuse.org/repositories/devel:/languages:/python/openSUSE_Tumbleweed/"}
        elif name == "openSUSE Leap" and version_id in ["15.5", "15.6"]:
            return {"zeek": f"https://download.opensuse.org/repositories/security:zeek/{version_id}/",
                "python": f"https://download.opensuse.org/repositories/devel:/languages:/python/{version_id}/"}
        else:
            logger.error("Unsupported openSUSE version or distribution.")
            sys.exit(1)

    def install_zeek_from_repo(self, repo_urls):
        """
        Installs Zeek and necessary Python packages from the repository.
        """
        # Add Zeek and Python repositories
        logger.info("Adding the Zeek and Python repositories.")
        self.run_command(['zypper', '--non-interactive', 'addrepo', '--check', '--refresh', '--name',
                          'Zeek Security Repository', repo_urls['zeek'], 'security_zeek'])
        self.run_command(['zypper', '--non-interactive', 'addrepo', '--check', '--refresh', '--name',
                          'devel:languages:python', repo_urls['python'], 'devel_languages_python'])

        # Refresh only the newly added repositories
        self.run_command(['zypper', '--non-interactive', 'refresh', 'security_zeek', 'devel_languages_python'])

        # Install Python package and Zeek
        logger.info("Installing required packages via zypper.")
        try:
            self.run_command(['zypper', '--non-interactive', 'install', '-y', 'python3-gitpython'])
            logger.info("python3-gitpython installed successfully.")
            self.run_command(['zypper', '--non-interactive', 'install', '--no-recommends', '-y', 'zeek'])
            logger.info("Zeek installed successfully via zypper.")
        except Exception as e:
            logger.error(f"Failed to install Zeek from repository: {e}")
            raise e

    def install_zeek_from_source_opensuse(self):
        """
        Installs Zeek from source if the repository installation fails.
        """
        logger.info("Installing Zeek from source.")

        # Install build dependencies
        logger.info("Installing build dependencies...")
        self.run_command(['zypper', '--non-interactive', 'install', '-y', 'make', 'cmake', 'flex', 'bison',
                          'libpcap-devel', 'libopenssl-devel', 'python3', 'python3-devel', 'swig', 'zlib-devel', 'wget',
                          'tar', 'gzip', 'gcc10', 'gcc10-c++'])

        # Set GCC to version 10
        logger.info("Setting GCC to version 10...")
        self.run_command(['update-alternatives', '--install', '/usr/bin/gcc', 'gcc', '/usr/bin/gcc-10', '100'])
        self.run_command(['update-alternatives', '--install', '/usr/bin/g++', 'g++', '/usr/bin/g++-10', '100'])

        # Download and build Zeek from source
        zeek_version = self.zeek_version
        src_dir = Path.home() / 'src'
        src_dir.mkdir(parents=True, exist_ok=True)

        zeek_tar = src_dir / f"zeek-{zeek_version}.tar.gz"
        zeek_dir = src_dir / f"zeek-{zeek_version}"

        if not zeek_tar.is_file():
            logger.info(f"Downloading Zeek source code version {zeek_version}...")
            self.run_command(['wget', f"https://download.zeek.org/zeek-{zeek_version}.tar.gz"], cwd=src_dir)

        if not zeek_dir.is_dir():
            logger.info("Extracting Zeek source code...")
            self.run_command(['tar', '-xzf', zeek_tar], cwd=src_dir)

        build_dir = zeek_dir / 'build'
        build_dir.mkdir(parents=True, exist_ok=True)

        logger.info("Building Zeek from source...")
        self.run_command(['cmake', '..'], cwd=build_dir)
        self.run_command(['make', '-j', str(os.cpu_count())], cwd=build_dir)
        self.run_command(['make', 'install'], cwd=build_dir)

        # Add Zeek to the system PATH
        self.add_zeek_to_path()

    def add_zeek_to_path(self):
        """
        Adds Zeek to the system's PATH if it's not already there.
        """
        home_dir = Path.home()
        bashrc = home_dir / '.bashrc'
        zeek_bin = '/usr/local/zeek/bin'

        if not bashrc.exists():
            bashrc.touch()

        with bashrc.open('r') as file:
            bashrc_content = file.read()

        if zeek_bin not in bashrc_content:
            logger.info("Adding Zeek to the system PATH...")
            with bashrc.open('a') as file:
                file.write(f'\nexport PATH={zeek_bin}:$PATH\n')

            # Source the updated bashrc
            self.run_command(['bash', '-c', f'source {bashrc}'])

    def clean_build_directory(self):
        """
        Cleans the build directory if necessary.
        """
        logger.info("Cleaning build directory...")
        build_dir = Path.cwd() / 'build'
        if build_dir.is_dir():
            try:
                self.run_command(['make', 'distclean'])
            except:
                shutil.rmtree(build_dir)
            logger.info("Build directory cleaned.")
        else:
            logger.info("No build directory to clean.")

    def install_build_dependencies(self):
        """
        Installs build dependencies required for building Zeek from source.
        """
        logger.info("Installing build dependencies...")
        logger.info(f"Detected OS: {self.os_id} {self.os_info.version_id} {self.os_info.version}")
        try:
            if self.os_id in ['ubuntu', 'debian'] or 'debian' in self.os_like:
                self.run_command(['apt', 'update', '-y'])
                self.run_command(['apt', 'install', '-y', 'curl', 'wget', 'lsb-release', 'gnupg', 'build-essential',
                                  'cmake', 'gcc', 'g++', 'flex', 'bison', 'libpcap-dev', 'libssl-dev', 'python3-dev',
                                  'zlib1g-dev', 'libcaf-dev', 'swig', 'binutils-gold', 'libkrb5-dev', 'nodejs'])
            elif self.os_id in ['centos', 'rhel'] or 'rhel' in self.os_like:
                self.run_command(['yum', 'groupinstall', '-y', '"Development Tools"'])
                self.run_command(['yum', 'install', '-y', 'curl', 'wget', 'cmake', 'make', 'gcc', 'gcc-c++', 'flex',
                                  'bison', 'libpcap-devel', 'openssl-devel', 'python3-devel', 'zlib-devel'])
            elif self.os_id == 'fedora':
                self.run_command(['dnf', 'install', '-y', 'curl', 'wget', 'cmake', 'make', 'gcc', 'gcc-c++', 'flex',
                                  'bison', 'libpcap-devel', 'openssl-devel', 'python3', 'python3-devel', 'swig',
                                  'nodejs', 'nodejs-devel', 'zlib-devel'])
            elif self.os_id in ['opensuse', 'sles'] or 'suse' in self.os_like:
                self.run_command(['zypper', 'install', '-y', 'curl', 'wget', 'cmake', 'make', 'gcc', 'gcc-c++', 'flex',
                                  'bison', 'libpcap-devel', 'libopenssl-devel', 'python3-devel', 'zlib-devel'])
            else:
                logger.error("Unsupported distribution for source installation.")
                sys.exit(1)
            logger.info("Build dependencies installed successfully.")
        except Exception as e:
            logger.error("Failed to install build dependencies.")
            sys.exit(1)

    def install_zeek_from_source(self):
        """
        Installs Zeek from source.
        """
        logger.info("Installing Zeek from source...")
        if self.is_zeek_installed():
            logger.info("Skipping source installation as Zeek is already installed.")
            return
        # Set Zeek version
        zeek_version = self.zeek_version
        # Create non-root user if not exists

        # Set the flag to indicate source installation
        self.source_install = True

        try:
            self.run_command(['id', self.builder_user], capture_output=True)
            logger.info(f"User '{self.builder_user}' already exists.")
        except:
            logger.info(f"Creating user '{self.builder_user}'...")
            self.run_command(['useradd', '-m', self.builder_user])
        # Install build dependencies
        self.install_build_dependencies()
        # Ensure builder's home directory ownership
        self.run_command(['chown', '-R', f'{self.builder_user}:{self.builder_user}', f'/home/{self.builder_user}'])
        # Create build script for the builder user
        build_script_path = Path(f"/home/{self.builder_user}/build_zeek.sh")
        build_script_content = f"""#!/bin/bash
set -e
cd ~/

# Clean previous builds
rm -rf zeek-*

# Download Zeek source code
echo "Downloading Zeek source code..."
DOWNLOAD_URL="https://github.com/zeek/zeek/releases/download/v{zeek_version}/zeek-{zeek_version}.tar.gz"
curl -L -o zeek-{zeek_version}.tar.gz "$DOWNLOAD_URL"

# Verify download
if [ ! -f zeek-{zeek_version}.tar.gz ]; then
    echo "Failed to download Zeek source code."
    exit 1
fi

FILE_SIZE=$(stat -c%s "zeek-{zeek_version}.tar.gz")
if [ $FILE_SIZE -lt 100000 ]; then
    echo "Downloaded file is too small, indicating a failed download."
    echo "File contents:"
    cat zeek-{zeek_version}.tar.gz
    exit 1
fi

# Extract and build
tar -xzf zeek-{zeek_version}.tar.gz
cd zeek-{zeek_version}
./configure
make -j$(nproc)
"""
        with build_script_path.open('w') as f:
            f.write(build_script_content)
        # Set ownership and permissions
        self.run_command(['chown', f'{self.builder_user}:{self.builder_user}', str(build_script_path)])
        self.run_command(['chmod', '+x', str(build_script_path)])
        # Run the build script as the builder user
        logger.info("Running build script as 'builder' user...")
        self.run_command(['su', '-', self.builder_user, '-c', f"bash {build_script_path}"])
        # Install Zeek as root
        zeek_build_dir = Path(f"/home/{self.builder_user}/zeek-{zeek_version}/build")
        if not zeek_build_dir.is_dir():
            logger.error(f"Directory {zeek_build_dir} does not exist.")
            sys.exit(1)
        os.chdir(zeek_build_dir)
        self.run_command(['make', 'install'])
        # Clean up
        self.run_command(['rm', '-f', str(build_script_path)])
        os.chdir('-')  # Return to previous directory
        logger.info("Zeek installed successfully from source.")
        # Configure Zeek
        self.configure_zeek()

    def find_zeek_config(self):
        """
        Finds zeek-config and updates PATH if necessary.
        """
        # Adjust the search directories based on the installation method
        if self.source_install:
            # If installed from source, prioritize /usr/local
            search_directories = ['/usr/local', '/opt', '/usr']
        else:
            # If installed from package/repo, prioritize /opt/zeek
            search_directories = ['/opt/zeek', '/usr/local', '/usr']

        # Check if zeek-config is already in the PATH
        if self.command_exists('zeek-config'):
            zeek_config_path = shutil.which('zeek-config')
            logger.info(f"zeek-config found in PATH at: {zeek_config_path}")
        else:
            logger.info("zeek-config not found in PATH. Searching common directories...")
            zeek_config_path = None

            # Search through the specified directories
            for directory in search_directories:
                for root, dirs, files in os.walk(directory):
                    if 'zeek-config' in files:
                        zeek_config_path = os.path.join(root, 'zeek-config')
                        break
                if zeek_config_path:
                    break

            # If zeek-config is still not found, log an error and exit
            if not zeek_config_path:
                logger.error("Unable to find zeek-config. Please ensure Zeek is installed correctly.")
                sys.exit(1)

            # Add zeek-config directory to the PATH
            zeek_config_dir = os.path.dirname(zeek_config_path)
            os.environ['PATH'] = f"{zeek_config_dir}:{os.environ['PATH']}"
            logger.info(f"zeek-config found at {zeek_config_path} and added to PATH.")

        return zeek_config_path

    def update_node_cfg_macos(self):
        """
        Updates the interface in node.cfg for macOS.
        """
        if platform.system() != 'Darwin':
            return
        logger.info("Updating node.cfg for macOS...")
        try:
            # Extract the interface used by the default route
            route_output = self.run_command(['route', 'get', 'default'], capture_output=True)
            interface = None
            for line in route_output.splitlines():
                if 'interface:' in line:
                    interface = line.split(':')[1].strip()
                    break
            if not interface:
                logger.error("Unable to detect network interface from default route.")
                sys.exit(1)
            logger.info(f"Using network interface: {interface}")
            # Path to node.cfg
            node_cfg = "/usr/local/etc/node.cfg"
            if not Path(node_cfg).is_file():
                logger.error(f"Error: node.cfg not found at {node_cfg}")
                sys.exit(1)
            # Update the node.cfg file with the correct interface
            self.run_command(['sed', '-i', '', f's/^interface=.*/interface={interface}/', node_cfg])
            logger.info(f"Updated node.cfg with interface {interface}.")
        except Exception as e:
            logger.error("Failed to update node.cfg for macOS.")
            sys.exit(1)

    def configure_zeek(self):
        """
        Configures Zeek after installation.
        """
        logger.info("Configuring Zeek...")
        # Ensure the script is running as root
        if os.geteuid() != 0:
            logger.error("Error: This script must be run as root.")
            sys.exit(1)
        # Find zeek-config
        zeek_config_path = self.find_zeek_config()
        logger.info(f"Found zeek-config at: {zeek_config_path}")
        # Get Zeek installation prefix
        zeek_prefix = self.run_command([zeek_config_path, '--prefix'], capture_output=True)
        if not zeek_prefix:
            logger.error("Unable to determine Zeek installation prefix.")
            sys.exit(1)
        logger.info(f"Zeek installation prefix: {zeek_prefix}")
        # Detect and update the network interface
        if platform.system() == 'Darwin':
            self.update_node_cfg_macos()
        else:
            try:
                # For Linux systems, use the ip command to detect the interface
                ip_output = self.run_command(['ip', 'route'], capture_output=True)
                interface = None
                for line in ip_output.splitlines():
                    if 'default' in line:
                        parts = line.split()
                        if 'dev' in parts:
                            dev_index = parts.index('dev') + 1
                            interface = parts[dev_index]
                            break
                if not interface:
                    logger.error("Unable to detect network interface.")
                    sys.exit(1)
                logger.info(f"Using network interface: {interface}")
                # Path to node.cfg
                node_cfg = os.path.join(zeek_prefix, 'etc', 'node.cfg')
                # Ensure the Zeek etc directory exists
                Path(os.path.join(zeek_prefix, 'etc')).mkdir(parents=True, exist_ok=True)
                # Check if node.cfg exists
                if not Path(node_cfg).is_file():
                    logger.info(f"node.cfg not found at {node_cfg}. Creating node.cfg...")
                    with open(node_cfg, 'w') as f:
                        f.write(f"""[zeek]
type=standalone
host=localhost
interface={interface}
""")
                else:
                    logger.info(f"node.cfg found at {node_cfg}. Updating interface...")
                    self.run_command(['sed', '-i', f's/^interface=.*/interface={interface}/', node_cfg])
            except Exception as e:
                logger.error("Failed to configure node.cfg.")
                sys.exit(1)
        # Enable JSON logging
        local_zeek = os.path.join(zeek_prefix, 'share', 'zeek', 'site', 'local.zeek')
        if Path(local_zeek).is_file():
            with open(local_zeek, 'a') as f:
                f.write('\nredef LogAscii::use_json = T;\n')
            logger.info("Enabled JSON logging in local.zeek.")
        else:
            logger.error(f"local.zeek not found at {local_zeek}")
            sys.exit(1)
        # Create missing directories
        logger.info("Creating required directories...")
        logs_dir = os.path.join(zeek_prefix, 'logs')
        spool_dir = os.path.join(zeek_prefix, 'spool', 'zeek')
        Path(logs_dir).mkdir(parents=True, exist_ok=True)
        Path(spool_dir).mkdir(parents=True, exist_ok=True)
        # Ensure directories have proper permissions
        self.run_command(['chown', '-R', os.getlogin(), logs_dir])
        self.run_command(['chown', '-R', os.getlogin(), os.path.join(zeek_prefix, 'spool')])
        # Find zeekctl
        if self.command_exists('zeekctl'):
            zeekctl_path = shutil.which('zeekctl')
            logger.info(f"Found zeekctl at: {zeekctl_path}")
        else:
            logger.info("zeekctl not found in PATH. Searching common directories...")
            zeekctl_path = None
            for directory in ['/usr', '/usr/local', '/opt']:
                for root, dirs, files in os.walk(directory):
                    if 'zeekctl' in files:
                        zeekctl_path = os.path.join(root, 'zeekctl')
                        break
                if zeekctl_path:
                    break
            if not zeekctl_path:
                logger.error("Unable to find zeekctl. Please ensure Zeek is installed correctly.")
                sys.exit(1)
            # Add zeekctl directory to PATH
            zeekctl_dir = os.path.dirname(zeekctl_path)
            os.environ['PATH'] = f"{zeekctl_dir}:{os.environ['PATH']}"
            logger.info(f"zeekctl found at {zeekctl_path} and added to PATH.")
        # Deploy and start Zeek
        logger.info("Deploying Zeek...")
        self.run_command([zeekctl_path, 'deploy'])
        # Check Zeek status
        logger.info("Checking Zeek status...")
        self.run_command([zeekctl_path, 'status'])

    def install_utilities_macos(self):
        """
        Installs required utilities on macOS using Homebrew.
        """
        logger.info("Installing required utilities for macOS...")
        if not self.command_exists('brew'):
            logger.info("Homebrew not found. Installing Homebrew...")
            try:
                # Install Homebrew as the non-root user
                user = os.getenv('SUDO_USER') or os.getenv('USER')
                if not user:
                    logger.error("Unable to determine the non-root user for Homebrew installation.")
                    sys.exit(1)
                brew_install_cmd = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
                self.run_command(['su', '-', user, '-c', brew_install_cmd], shell=True)
            except Exception as e:
                logger.error("Failed to install Homebrew.")
                sys.exit(1)
        # Install utilities without sudo
        user = os.getenv('SUDO_USER') or os.getenv('USER')
        if not user:
            logger.error("Unable to determine the non-root user for Homebrew installation.")
            sys.exit(1)
        logger.info("Installing required utilities using Homebrew (without sudo)...")
        try:
            self.run_command(['su', '-', user, '-c',
                              'brew install cmake make gcc flex bison libpcap openssl python3 swig'], shell=True)
            logger.info("Required utilities installed successfully via Homebrew.")
        except Exception as e:
            logger.error("Failed to install required utilities via Homebrew.")
            sys.exit(1)

    def install_zeek_macos(self):
        """
        Installs Zeek on macOS.
        """
        logger.info("Detected macOS. Proceeding with installation...")
        self.install_utilities_macos()
        # Check if Zeek is available via Homebrew
        try:
            brew_info = self.run_command(['brew', 'info', 'zeek'], capture_output=True)
            if 'Not installed' in brew_info or 'could not be found' in brew_info:
                logger.info("Installing Zeek using Homebrew...")
                self.run_command(['su', '-', os.getenv('SUDO_USER') or os.getenv('USER'), '-c', 'brew install zeek'],
                                 shell=True)
                logger.info("Zeek installed successfully via Homebrew.")
                self.run_command(['zeek', '--version'])
            else:
                logger.info("Zeek is already installed via Homebrew.")
        except:
            logger.info("Zeek is not available via Homebrew. Proceeding to install from source.")
            self.install_zeek_from_source()
        self.configure_zeek()

    def detect_distro_and_install(self):
        """
        Detects the OS distribution and calls the appropriate installation function.
        """
        logger.info("Detecting operating system and proceeding with installation...")
        if platform.system() == 'Darwin':
            self.install_zeek_macos()
        elif platform.system() == 'Linux':
            if self.os_id == 'ubuntu':
                self.install_zeek_ubuntu()
            elif self.os_id in ['debian', 'raspbian']:
                self.install_zeek_debian()
            elif self.os_id == 'fedora':
                self.install_zeek_fedora()
            elif self.os_id in ['centos', 'rhel']:
                self.install_zeek_centos_rhel()
            elif self.os_id in ['opensuse', 'sles']:
                self.install_zeek_opensuse()
            else:
                logger.error(f"Unsupported Linux distribution: {self.os_id}")
                sys.exit(1)
        else:
            logger.error("Unsupported operating system.")
            sys.exit(1)

    def install(self):
        """
        Install function to run the installation.
        """
        self.check_root()
        logger.info("Checking if Zeek is already installed...")
        self.check_zeek_installed()
        self.detect_distro_and_install()


if __name__ == "__main__":
    installer = ZeekInstaller()
    installer.install()
