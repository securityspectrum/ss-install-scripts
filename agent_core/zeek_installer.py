#!/usr/bin/env python3
import platform
import subprocess
import distro
import logging
from pathlib import Path
import sys
import os
import time
import select
import pwd
import shutil
import getpass

# Configure logging
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

        # Determine the operating system
        self.os_system = platform.system()

        # Check privileges based on OS
        self.check_privileges()

    def run_command(self, command, check=True, capture_output=False, shell=False, input_data=None):
        """
        Executes a system command.
        """
        if shell and isinstance(command, list):
            # If shell=True and command is a list, join it into a string
            command = ' '.join(command)
        logger.info(f"Executing command: {' '.join(command) if isinstance(command, list) else command}")
        try:
            result = subprocess.run(command,
                                    check=check,
                                    capture_output=capture_output,
                                    text=True,
                                    shell=shell,
                                    input=input_data)
            if capture_output:
                logger.debug(f"Command output: {result.stdout.strip()}")
                return result.stdout.strip()
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(command) if isinstance(command, list) else command}")
            logger.error(f"Return code: {e.returncode}")
            if e.stdout:
                logger.error(f"Output: {e.stdout}")
            if e.stderr:
                logger.error(f"Error Output: {e.stderr}")
            raise

    def check_privileges(self):
        """
        Ensures the script is run with appropriate privileges based on the OS.
        - Root privileges are required for Linux installations.
        - No root privileges should be used for macOS installations.
        """
        if self.os_system != 'Darwin':
            # For Linux systems, enforce running as root
            if os.geteuid() != 0:
                logger.error("This script must be run as root. Please run again with 'sudo' or as the root user.")
                # Optionally, you can attempt to elevate privileges here
                # SystemUtility.elevate_privileges()
                sys.exit(1)
            logger.info("Script is running as root.")
        else:
            # For macOS, ensure the script is NOT run as root
            if os.geteuid() == 0:
                logger.error("Do not run this script as root on macOS. Please run as a regular user.")
                self.downgrade_privileges()
            logger.info("Script is running as a regular user on macOS.")

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
        else:
            logger.info("Zeek not found.")

    def downgrade_privileges(self):
        """
        Downgrades privileges from root to the specified non-root user.
        """
        sudo_user = os.getenv('SUDO_USER')
        if not sudo_user:
            logger.error('Could not determine the original non-root user. Exiting.')
            sys.exit(1)
        try:
            pw_record = pwd.getpwnam(sudo_user)
            user_uid = pw_record.pw_uid
            user_gid = pw_record.pw_gid

            os.setgid(user_gid)
            os.setuid(user_uid)
            logger.info(f"Dropped privileges to user '{sudo_user}' (UID: {user_uid}, GID: {user_gid}).")
        except KeyError:
            logger.error(f"User '{sudo_user}' does not exist.")
            sys.exit(1)
        except PermissionError:
            logger.error("Insufficient permissions to change user.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to drop privileges: {e}")
            sys.exit(1)


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
                self.run_command(['yum', 'install', '-y', 'epel-release', 'curl', 'gnupg'])
            elif self.os_id == 'fedora':
                self.run_command(['dnf', 'install', '-y', 'curl', 'redhat-lsb-core', 'gnupg'])
            elif self.os_id in ['opensuse', 'sles'] or 'suse' in self.os_like:
                self.run_command(['zypper', 'install', '-y', 'curl', 'lsb-release', 'gnupg'])
            else:
                logger.error("Unsupported distribution for installing utilities.")
                sys.exit(1)
            logger.info("Required utilities installed successfully.")
        except Exception as e:
            logger.error("Failed to install required utilities.")
            logger.error(e)
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
            self.run_command(['curl', '-fsSL', gpg_key_url], capture_output=True)
            # Store the key
            self.run_command(['curl', '-fsSL', gpg_key_url, '|', 'gpg', '--dearmor', '-o', keyring_path], shell=True)
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
            self.run_command(['curl', '-fsSL', gpg_key_url], capture_output=True)
            # Store the key
            self.run_command(['curl', '-fsSL', gpg_key_url, '|', 'gpg', '--dearmor', '-o', keyring_path], shell=True)

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
                gpg_key_url = f"https://download.opensuse.org/repositories/security:/zeek/Fedora_{fedora_version}/repodata/repomd.xml.key"
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
        logger.info(f"Detected OS: {self.os_id} {self.os_info.get('version_id', '')} {self.os_info.get('version', '')}")
        try:
            if self.os_id in ['ubuntu', 'debian'] or 'debian' in self.os_like:
                self.run_command(['apt', 'update', '-y'], check=True)
                self.run_command(['apt', 'install', '-y', 'curl', 'wget', 'lsb-release', 'gnupg', 'build-essential',
                                  'cmake', 'gcc', 'g++', 'flex', 'bison', 'libpcap-dev', 'libssl-dev', 'python3-dev',
                                  'zlib1g-dev', 'libcaf-dev', 'swig', 'binutils-gold', 'libkrb5-dev', 'nodejs'])
            elif self.os_id in ['centos', 'rhel'] or 'rhel' in self.os_like:
                self.run_command(['yum', 'groupinstall', '-y', '"Development Tools"'], check=True)
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
            logger.error(e)
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
        try:
            self.run_command(['id', self.builder_user], capture_output=True)
            logger.info(f"User '{self.builder_user}' already exists.")
        except subprocess.CalledProcessError:
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
make install
"""
        with build_script_path.open('w') as f:
            f.write(build_script_content)
        # Set ownership and permissions
        self.run_command(['chown', f'{self.builder_user}:{self.builder_user}', str(build_script_path)])
        self.run_command(['chmod', '+x', str(build_script_path)])
        # Run the build script as the builder user
        logger.info("Running build script as 'builder' user...")
        self.run_command(['su', '-', self.builder_user, '-c', f"bash {build_script_path}"])
        # Clean up
        self.run_command(['rm', '-f', str(build_script_path)])
        logger.info("Zeek installed successfully from source.")
        # Configure Zeek
        self.configure_zeek()


    def install_zeek_from_source_macos(self):
        """
        Installs Zeek from source on macOS using the existing non-root user.
        """
        logger.info("Installing Zeek from source on macOS...")

        if self.is_zeek_installed():
            logger.info("Skipping source installation as Zeek is already installed.")
            return

        # Set Zeek version
        zeek_version = self.zeek_version

        # Determine the non-root user
        
        user = os.getenv('SUDO_USER')
        if not user:
            logger.error('Could not determine the original non-root user. Exiting.')
            sys.exit(1)
        logger.info(f"Using non-root user: {user}")

        # Install build dependencies via Homebrew (if not already installed)
        logger.info("Installing build dependencies via Homebrew...")
        try:
            self.run_command(['brew', 'install', 'cmake', 'make', 'gcc', 'flex', 'bison', 'libpcap', 'openssl', 'python3', 'swig', 'zlib'], shell=False)
            logger.info("Build dependencies installed successfully via Homebrew.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install build dependencies: {e}")
            sys.exit(1)

        # Create a directory for the source code
        src_dir = Path(f"/Users/{user}/src")
        try:
            src_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Source directory created at {src_dir}.")
        except Exception as e:
            logger.error(f"Failed to create source directory at {src_dir}: {e}")
            sys.exit(1)

        # No need to change ownership on macOS
        logger.info(f"Skipping ownership change for {src_dir} on macOS.")

        # Navigate to the source directory
        os.chdir(src_dir)

        # Download the Zeek source code if not already downloaded
        zeek_tar = src_dir / f"zeek-{zeek_version}.tar.gz"
        zeek_dir = src_dir / f"zeek-{zeek_version}"

        if not zeek_tar.is_file():
            logger.info(f"Downloading Zeek source code version {zeek_version}...")
            self.run_command(['curl', '-LO', f"https://download.zeek.org/zeek-{zeek_version}.tar.gz"], cwd=src_dir)
            logger.info("Zeek source code downloaded successfully.")
        else:
            logger.info(f"Zeek source code version {zeek_version} already downloaded.")

        # Extract the source code if not already extracted
        if not zeek_dir.is_dir():
            logger.info("Extracting Zeek source code...")
            self.run_command(['tar', '-xzf', str(zeek_tar)], cwd=src_dir)
            logger.info("Zeek source code extracted successfully.")
        else:
            logger.info("Zeek source code already extracted.")

        # Build and install Zeek from source
        logger.info("Building and installing Zeek from source...")
        build_dir = zeek_dir / 'build'
        try:
            build_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Build directory created at {build_dir}.")
        except Exception as e:
            logger.error(f"Failed to create build directory at {build_dir}: {e}")
            sys.exit(1)

        # Define the build commands
        build_commands = [
            'cmake ..',
            f'make -j{os.cpu_count()}',
            'make install'
        ]

        # Execute build commands as the non-root user
        try:
            for cmd in build_commands:
                logger.info(f"Executing build command: {cmd}")
                self.run_command(['su', '-', user, '-c', f"cd {build_dir} && {cmd}"], shell=False)
            logger.info("Zeek built and installed successfully from source.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to build and install Zeek from source: {e}")
            sys.exit(1)

        # Return to the original directory
        os.chdir('/')

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

        # Determine the non-root user
        user = getpass.getuser()
        logger.info(f"Using non-root user: {user}")

        # Check if Homebrew is installed
        if not self.command_exists('brew'):
            logger.info("Homebrew not found. Installing Homebrew...")
            try:
                brew_install_cmd = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
                self.run_command(f'bash -c "{brew_install_cmd}"', shell=True)
                logger.info("Homebrew installed successfully.")
            except Exception as e:
                logger.error("Failed to install Homebrew.")
                logger.error(e)
                sys.exit(1)

    def create_source_directory(self):
        """
        Creates a source directory in the user's home directory.
        """
        user = getpass.getuser()
        user_home = Path.home()
        src_dir = user_home / 'src'

        try:
            # Create the source directory if it doesn't exist
            if not src_dir.exists():
                src_dir.mkdir(parents=True)
                logger.info(f"Source directory created at {src_dir}.")
        except Exception as e:
            logger.error(f"Failed to create source directory at {src_dir}: {e}")
            sys.exit(1)

        # For macOS, do not change ownership
        if self.os_system == 'Darwin':
            logger.info(f"Skipping ownership change for {src_dir} on macOS.")
        else:
            # For Linux, change ownership
            try:
                self.run_command(['chown', '-R', f'{user}:staff', str(src_dir)])
                logger.info(f"Ownership changed to {user}:staff for {src_dir}.")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to change ownership of {src_dir}: {e}. Proceeding without changing ownership.")

        return src_dir


    def prompt_user_for_version(self):
        """
        Prompt the user to select between the latest Zeek version (7.0.2) and the previous version (7.0.1).
        """
        print("Please choose the Zeek version to install:")
        print("1. Latest version (7.0.2)")
        print("2. Previous version (7.0.1)")
        print("Press Enter to select the default (Latest version 7.0.2)")

        # Set a timeout for the input
        user_input = None
        start_time = time.time()

        # Give the user 5 seconds to respond, otherwise default to the latest version
        while time.time() - start_time < 5:  # 5 seconds timeout
            if sys.stdin in select.select([sys.stdin], [], [], 5)[0]:  # Timeout set to 5 seconds
                user_input = input()
                break

        # If user_input is None or empty (Enter was pressed), default to the latest version
        if user_input is None or user_input.strip() == '':
            print("\nNo input or invalid input received. Proceeding with the latest version (7.0.2).")
            return "latest"
        elif user_input == '2':
            return "previous"
        else:
            print("\nInvalid input received. Proceeding with the latest version (7.0.2).")
            return "latest"

    def install_dependencies(self):
        user, _ = self.get_user_home_directory()
        brew_install_cmd = 'brew install cmake make gcc flex bison libpcap openssl python3 swig zlib'
        try:
            self.run_command(f'brew install cmake make gcc flex bison libpcap openssl python3 swig zlib', shell=True)
            logger.info("Build dependencies installed successfully via Homebrew.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install dependencies via Homebrew: {e}")
            sys.exit(1)

    def is_tap_installed(self, tap_name):
        """
        Checks if a Homebrew tap is already installed.
        """
        try:
            taps = self.run_command(['brew', 'tap'], capture_output=True, shell=False)
            return tap_name in taps.splitlines()
        except subprocess.CalledProcessError:
            return False

    def install_zeek_macos(self):
        """
        Installs Zeek on macOS, allowing the user to select between the latest version (7.0.2) or the previous version (7.0.1).
        """
        logger.info("Detected macOS. Proceeding with installation...")
        self.install_utilities_macos()

        # Determine the non-root user
        user = getpass.getuser()
        user_home = Path.home()
        logger.info(f"Using non-root user: {user}")

        # Prompt user to choose between latest or previous version of Zeek
        version_choice = self.prompt_user_for_version()

        # Handle the selected Zeek version
        if version_choice == "latest":
            zeek_version = "zeek"
            logger.info("Proceeding with the latest version (7.0.2).")
        elif version_choice == "previous":
            zeek_version = "zeek@7.0.1"
            logger.info("Proceeding with the previous version (7.0.1).")

            # Create the custom tap if it doesn't exist
            tap_name = f"{user}/older-zeek"
            if not self.is_tap_installed(tap_name):
                try:
                    self.run_command(['brew', 'tap-new', tap_name], check=True, shell=False)
                    logger.info(f"Tap '{tap_name}' created successfully.")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to create tap '{tap_name}': {e}")
                    sys.exit(1)
            else:
                logger.info(f"Tap '{tap_name}' already exists. Skipping tap creation.")

            # Download the Zeek 7.0.1 formula directly using curl
            formula_path = f"/usr/local/Homebrew/Library/Taps/{user}/homebrew-older-zeek/Formula/zeek.rb"
            try:
                logger.info("Downloading the Zeek 7.0.1 formula...")
                self.run_command(['curl', '-o', formula_path,
                                'https://raw.githubusercontent.com/Homebrew/homebrew-core/7e624e19de94dc6dccff8808f2b105480b2a9320/Formula/z/zeek.rb'],
                                check=True, shell=False)
                logger.info(f"Zeek 7.0.1 formula downloaded successfully to {formula_path}.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to download the Zeek formula: {e}. Proceeding to install from source.")
                self.create_source_directory()  # Ensure source directory exists
                self.install_zeek_from_source_macos()
                return  # Exit the method after installing from source

        # Attempt to install Zeek via Homebrew
        try:
            brew_info_cmd = ['brew', 'info', zeek_version]
            brew_info = self.run_command(brew_info_cmd, capture_output=True, shell=False)

            if 'Not installed' in brew_info or 'could not be found' in brew_info:
                logger.info(f"Installing Zeek ({zeek_version}) using Homebrew...")
                zeek_install_cmd = ['brew', 'install', f"{user}/older-zeek/zeek"]
                self.run_command(zeek_install_cmd, check=True, shell=False)
                logger.info(f"Zeek ({zeek_version}) installed successfully via Homebrew.")
                # Verify the installation
                self.run_command(['zeek', '--version'], check=True, shell=False)
            else:
                logger.info(f"Zeek ({zeek_version}) is already installed via Homebrew.")
        except subprocess.CalledProcessError as e:
            logger.info(f"Zeek is not available via Homebrew: {e}. Proceeding to install from source.")
            self.create_source_directory()  # Creating source directory before installing from source
            self.install_zeek_from_source_macos()
        except Exception as e:
            logger.info(f"An unexpected error occurred: {e}. Proceeding to install Zeek from source.")
            self.create_source_directory()  # Creating source directory before installing from source
            self.install_zeek_from_source_macos()

        # Proceed with Zeek configuration
        self.configure_zeek()


    def detect_distro_and_install(self):
        """
        Detects the OS distribution and calls the appropriate installation function.
        """
        logger.info("Detecting operating system and proceeding with installation...")
        if self.os_system == 'Darwin':
            self.install_zeek_macos()
        elif self.os_system == 'Linux':
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
        logger.info("Checking if Zeek is already installed...")
        self.check_zeek_installed()
        self.detect_distro_and_install()


if __name__ == "__main__":
    installer = ZeekInstaller()
    installer.install()
