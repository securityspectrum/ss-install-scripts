#!/usr/bin/env python3
import json
import platform
import subprocess
import distro
import logging
from pathlib import Path
import sys
import os
import time

import requests
import select
import shutil
import getpass
import time
import os
import platform
import ctypes
import re

import toml

if platform.system() == 'Windows':
    import win32security
    import win32con
    import win32api
else:
    # Imports or logic for Linux/MacOS can be added here if necessary
    pass


# Configure logging
from agent_core import SystemUtility
from agent_core.constants import SS_NETWORK_ANALYZER_REPO, SS_NETWORK_ANALYZER_SERVICE_NAME, \
    SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS, ZEEK_SERVICE_PATH_LINUX, SS_NETWORK_ANALYZER_LOG_PATH_WINDOWS, \
    SS_NETWORK_ANALYZER_CONFIG_DIR_WINDOWS, NETWORK_ANALYZER_CONFIG_FILENAME, \
    SS_NETWORK_ANALYZER_CONF_DEFAULT_FLUSH_INTERVAL, SS_NETWORK_ANALYZER_LOG_PATH_MACOS, \
    SS_NETWORK_ANALYZER_CONFIG_DIR_MACOS, SS_NETWORK_ANALYZER_CONFIG_DIR_LINUX, SS_NETWORK_ANALYZER_LOG_PATH_LINUX
from agent_core.network_analyzer_installer import SS_NETWORK_ANALYZER_ASSET_PATTERNS


logger = logging.getLogger("InstallationLogger")
quiet_install = (logger.getEffectiveLevel() > logging.DEBUG)

class ZeekInstaller:
    def __init__(self):
        """
        """

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
        self.os_system = platform.system().lower()

        if self.os_system == 'windows':
            try:
                self.win32security = win32security
                self.win32con = win32con
                self.win32api = win32api
                logger.debug("Windows-specific modules imported successfully.")
            except ImportError as e:
                logger.error("Failed to import Windows-specific modules: {}".format(e))
                sys.exit(1)

    def run_command(self, command, check=True, capture_output=False, shell=False, input_data=None, require_root=False, quiet=None):
        """
        Executes a system command with optional quiet behavior and root privileges.
        """
        # If quiet param is None, fall back to self.quiet
        if quiet is None:
            quiet = quiet_install

        if require_root and os.geteuid() != 0:
            # Prepend 'sudo' if not already root
            command = ['sudo'] + (command if isinstance(command, list) else command.split())

        # If shell=True but command is a list, join it
        if shell and isinstance(command, list):
            command = ' '.join(command)

        # Only log the full command if not quiet
        if not quiet:
            logger.debug("Executing command: %s", command if isinstance(command, str) else ' '.join(command))

        try:
            result = subprocess.run(command,
                                    check=check,
                                    capture_output=capture_output,
                                    text=True,
                                    shell=shell,
                                    input=input_data)
            # If capturing output, log it only when not quiet
            if capture_output and not quiet:
                logger.debug("Command output: %s", result.stdout.strip())
            return result.stdout.strip() if capture_output else True

        except subprocess.CalledProcessError as e:
            # Log minimal or verbose message depending on quiet
            if not quiet:
                logger.error("Command failed: %s", command if isinstance(command, str) else ' '.join(command))
                logger.error("Return code: %s", e.returncode)
                if e.stdout:
                    logger.error("Output: %s", e.stdout)
                if e.stderr:
                    logger.error("Error Output: %s", e.stderr)
            raise

    def check_privileges(self):
        """
        Ensures the script is run with appropriate privileges based on the OS.
        - Root privileges are required for Linux installations.
        - Administrative privileges are required for Windows installations.
        - No root privileges should be used for macOS installations.
        """
        if self.os_system == 'windows':
            # Check if the user has administrative privileges on Windows
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                if not is_admin:
                    logger.error("This script must be run as an administrator on Windows. Please run as an admin.")
                    sys.exit(1)
                logger.debug("Script is running with administrative privileges on Windows.")
            except Exception as e:
                logger.error(f"Failed to check admin privileges: {e}")
                sys.exit(1)

        elif self.os_system == 'darwin':
            # For macOS, ensure the script is NOT run as root
            if os.geteuid() == 0:
                logger.error("Do not run this script as root on macOS. Please run as a regular user.")
                self.downgrade_privileges()
            logger.debug("Script is running as a regular user on macOS.")

        else:
            # For Linux systems, enforce running as root
            if os.geteuid() != 0:
                logger.error("This script must be run as root. Please run again with 'sudo' or as the root user.")
                sys.exit(1)
            logger.debug("Script is running as root on Linux.")

    def command_exists(self, command):
        """
        Checks if a command exists in the system PATH without relying solely on `shutil.which`.
        Falls back to manually checking common binary directories.
        If found, adds the directory to the PATH environment variable.
        Returns the full path to the command if found, otherwise None.
        """
        try:
            # First, try using shutil.which
            command_path = shutil.which(command)
            if command_path:
                logger.debug(f"Command '{command}' found at {command_path}")
                # Add the directory to PATH if not already present
                command_dir = os.path.dirname(command_path)
                if command_dir not in os.environ.get("PATH", "").split(os.pathsep):
                    os.environ["PATH"] = command_dir + os.pathsep + os.environ["PATH"]
                    logger.debug(f"Added '{command_dir}' to PATH.")
                return command_path
        except Exception as e:
            logger.warning(f"shutil.which() failed for command '{command}': {e}")

        # Fallback: manually check common directories
        common_paths = ['/usr/bin', '/usr/local/bin', '/bin', '/usr/sbin', '/sbin', '/opt/zeek/bin']
        for path in common_paths:
            command_path = os.path.join(path, command)
            if os.access(command_path, os.X_OK):
                logger.debug(f"Command '{command}' found in {path}")
                # Add the directory to PATH if not already present
                if path not in os.environ.get("PATH", "").split(os.pathsep):
                    os.environ["PATH"] = path + os.pathsep + os.environ["PATH"]
                    logger.debug(f"Added '{path}' to PATH.")
                return command_path

        logger.debug(f"Command '{command}' not found in common paths.")
        return None

    def check_zeek_installed(self):
        """
        Checks if Zeek is already installed and exits if it is.
        """
        if self.command_exists('zeek'):
            zeek_version = self.run_command(['zeek', '--version'], capture_output=True).splitlines()[0]
            logger.debug(f"Zeek is already installed: {zeek_version}")
            return True
        else:
            logger.debug("Zeek not found.")
            return False

    def downgrade_privileges(self):
        """
        Downgrades privileges from root/administrator to the specified non-root/non-admin user.
        """
        current_platform = platform.system()
        logger.debug(f"Operating System detected: {current_platform}")

        if current_platform in ['Linux', 'Darwin']:  # Unix-like systems
            self._downgrade_privileges_unix()
        elif current_platform == 'Windows':
            self._downgrade_privileges_windows()
        else:
            logger.error(f"Unsupported operating system: {current_platform}")
            sys.exit(1)


    def _downgrade_privileges_unix(self):
        """
        Downgrades privileges on Unix-like systems using setuid and setgid.
        """
        sudo_user = os.getenv('SUDO_USER')
        if not sudo_user:
            logger.error('Could not determine the original non-root user. Exiting.')
            sys.exit(1)
        try:
            import pwd  # Import locally to avoid issues on Windows
            pw_record = pwd.getpwnam(sudo_user)
            user_uid = pw_record.pw_uid
            user_gid = pw_record.pw_gid

            os.setgid(user_gid)
            os.setuid(user_uid)
            logger.debug(f"Dropped privileges to user '{sudo_user}' (UID: {user_uid}, GID: {user_gid}).")
        except KeyError:
            logger.error(f"User '{sudo_user}' does not exist.")
            sys.exit(1)
        except PermissionError:
            logger.error("Insufficient permissions to change user.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed to drop privileges: {e}")
            sys.exit(1)

    def _downgrade_privileges_windows(self):
        """
        Downgrades privileges on Windows by impersonating a non-administrator user.
        """
        if not self.is_windows:
            return

        username = os.getenv("USERNAME")
        if not username:
            logger.error("Could not retrieve the current user. Exiting.")
            sys.exit(1)

        logger.debug(f"Attempting to downgrade privileges for user: {username}")

        try:
            # Prompt the user for the target username and password for impersonation
            target_user = input("Enter the username of the user to impersonate: ")
            target_domain = input("Enter the domain (or leave blank for local user): ")
            target_password = getpass.getpass("Enter the password for the user: ")

            # Log on the user and obtain a handle to the user's access token
            handle = self.win32security.LogonUser(
                target_user,
                target_domain or None,  # Local machine if domain is not specified
                target_password,
                self.win32con.LOGON32_LOGON_INTERACTIVE,  # Interactive logon
                self.win32con.LOGON32_PROVIDER_DEFAULT
            )

            # Impersonate the logged-on user
            self.win32security.ImpersonateLoggedOnUser(handle)
            logger.debug(f"Successfully downgraded privileges to user: {target_user}")

            # Run your installation or other operations here under the impersonated user

        except Exception as e:
            logger.error(f"Failed to downgrade privileges: {e}")
            sys.exit(1)

    def is_zeek_installed(self):
        """
        Returns True if Zeek is installed, whether from a package or source build.
        """
        logger.debug("Checking if Zeek is installed...")

        # Check if the 'zeek' or 'zeek-config' command exists and get their paths
        zeek_path = self.command_exists('zeek')
        zeek_config_path = self.command_exists('zeek-config')

        if not zeek_path and not zeek_config_path:
            logger.debug("Neither 'zeek' nor 'zeek-config' command found.")
            return False

        # Verify the version command works
        if not self.verify_zeek_version(zeek_path):
            logger.debug("Zeek version check failed.")
            return False

        logger.debug("Zeek is installed and functioning.")
        return True

    def verify_zeek_version(self, zeek_path=None):
        try:
            if zeek_path:
                logger.debug(f"Attempting to run '{zeek_path} --version'...")
                cmd = [zeek_path, '--version']
            else:
                logger.debug("Attempting to run 'zeek --version'...")
                cmd = ['zeek', '--version']

            result = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logger.debug(f"Zeek version: {result.stdout.strip()}")
            return True
        except FileNotFoundError:
            logger.error("Zeek binary not found in PATH.")
            return False
        except subprocess.CalledProcessError as e:
            logger.error(f"Zeek version command failed: {e.stderr.strip()}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error while verifying Zeek version: {e}")
            return False

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
        except Exception as e:
            logger.error("Failed to install required utilities.")
            logger.error(e)
            sys.exit(1)

    def install_zeek_ubuntu(self):
        """
        Installs Zeek on Ubuntu reliably with minimal system-wide updates.
        """
        logger.debug("Detected Ubuntu. Proceeding with Zeek installation...")
        self.install_utilities()

        # Detect Ubuntu release version
        distro_version = self.run_command(['lsb_release', '-rs'], capture_output=True).strip()
        logger.debug(f"Ubuntu version detected: {distro_version}")

        # Ensure universe repository is enabled (needed for some dependencies, such as libmaxminddb-dev)
        # logger.debug("Enabling universe repository...")
        # self.run_command(['add-apt-repository', '-y', 'universe'])

        # Update package lists after enabling universe
        logger.debug("Updating package lists after enabling universe repository...")
        self.run_command(['apt', 'update'])

        # Prepare to add Zeek repository
        gpg_key_url = f"https://download.opensuse.org/repositories/security:zeek/xUbuntu_{distro_version}/Release.key"
        keyring_path = "/usr/share/keyrings/zeek-archive-keyring.gpg"

        # Remove old keyring if exists to avoid prompt
        logger.debug("Ensuring clean state for Zeek keyring...")
        self.run_command(['rm', '-f', keyring_path])

        # Download the GPG key
        logger.debug(f"Downloading Zeek GPG key from {gpg_key_url}")
        gpg_key_data = self.run_command(['curl', '-fsSL', gpg_key_url], capture_output=True)

        # Write key to a temporary file
        with open('/tmp/Release.key', 'wb') as key_file:
            key_file.write(gpg_key_data.encode('utf-8'))

        # Dearmor and store the GPG key
        logger.debug("Storing the GPG key...")
        self.run_command(['gpg', '--batch', '--yes', '--dearmor', '-o', keyring_path, '/tmp/Release.key'])

        # Add the Zeek repository
        repo_entry = f"deb [signed-by={keyring_path}] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_{distro_version}/ /"
        logger.debug(f"Adding Zeek repository: {repo_entry}")
        self.run_command(['bash', '-c', f'echo "{repo_entry}" > /etc/apt/sources.list.d/zeek.list'])

        # Option 1: Update all package lists (safer, ensures all dependencies can be found)
        # logger.debug("Updating package lists with new Zeek repository...")
        # self.run_command(['apt', 'update'])

        # Option 2 (Older approach): Update only the Zeek repository
        # This tries to update only the repository mentioned in /etc/apt/sources.list.d/zeek.list
        # Useful if you don't want to refresh all package indices system-wide
        logger.debug("Updating only the Zeek repository lists...")
        self.run_command(['apt', 'update', '-o', 'Dir::Etc::sourcelist="sources.list.d/zeek.list"', '-o',
            'APT::Get::List-Cleanup="0"'])

        # Fix any broken dependencies if present
        logger.debug("Attempting to fix any broken dependencies before installation...")
        self.run_command(['apt', '--fix-broken', 'install', '-y'])

        # Attempt to install Zeek and Zeekctl
        logger.debug("Installing Zeek and Zeekctl...")
        try:
            self.run_command(['apt', 'install', '-y', 'zeek', 'zeekctl'])
            logger.debug("Zeek installed successfully via apt.")
        except Exception as e:
            logger.error(f"Package installation failed: {e}. Attempting to fix broken packages and retry...")

            # Fix broken packages if any
            self.run_command(['apt', '--fix-broken', 'install', '-y'])

            # Retry installation once
            try:
                self.run_command(['apt', 'install', '-y', 'zeek', 'zeekctl'])
                logger.debug("Zeek installed successfully on retry.")
            except Exception as e2:
                logger.error(f"Second attempt to install Zeek failed: {e2}. Falling back to source installation.")
                self.install_zeek_from_source()

        # Proceed with Zeek configuration
        self.configure_zeek()

    def install_zeek_debian(self):
        """
        Installs Zeek on Debian.
        """
        logger.debug("Detected Debian. Proceeding with installation...")
        self.install_utilities()

        # Clean up the distro version to avoid issues with minor version numbers
        distro_version = self.run_command(['lsb_release', '-rs'], capture_output=True).strip().split('.')[0]
        logger.debug(f"Configuring repository for Debian {distro_version}...")

        try:
            # Add Zeek GPG key
            gpg_key_url = f"https://download.opensuse.org/repositories/security:zeek/Debian_{distro_version}/Release.key"
            keyring_path = "/usr/share/keyrings/zeek-archive-keyring.gpg"

            # Download and store the GPG key
            logger.debug(f"Downloading GPG key from {gpg_key_url}...")
            gpg_key_data = self.run_command(['curl', '-fsSL', gpg_key_url], capture_output=True)

            # Store the GPG key using gpg
            logger.debug(f"Storing GPG key at {keyring_path}...")
            with open('/tmp/zeek_release.key', 'wb') as key_file:
                key_file.write(gpg_key_data.encode('utf-8'))

            self.run_command(['gpg', '--dearmor', '-o', keyring_path, '/tmp/zeek_release.key'])

            # Add Zeek repository
            repo_entry = f"deb [signed-by={keyring_path}] http://download.opensuse.org/repositories/security:/zeek/Debian_{distro_version}/ /"
            logger.debug(f"Adding Zeek repository to /etc/apt/sources.list.d/zeek.list...")
            self.run_command(['bash', '-c', f'echo "{repo_entry}" > /etc/apt/sources.list.d/zeek.list'])

            # Update only the Zeek repository
            logger.debug("Updating the Zeek repository...")
            self.run_command(['apt', 'update', '-o', f'Dir::Etc::sourcelist="sources.list.d/zeek.list"', '-o',
                              'APT::Get::List-Cleanup="0"'])

            # Install Zeek and Zeekctl without updating other packages
            logger.debug("Installing Zeek and Zeekctl...")
            self.run_command(['apt', 'install', '-y', 'zeek', 'zeekctl'])
            logger.debug("Zeek installed successfully via apt.")

        except Exception as e:
            logger.error(f"Package installation failed: {e}. Attempting to install from source...")
            self.install_zeek_from_source()
            return

        # Proceed with Zeek configuration
        self.configure_zeek()

    def install_zeek_fedora(self):
        """
        Installs Zeek on Fedora without a full system update.
        """
        logger.debug("Detected Fedora. Proceeding with installation...")
        self.install_utilities()

        try:

            makecache_cmd = ['dnf', 'makecache', '--refresh']
            install_cmd = ['dnf', 'install', '-y', 'zeek', 'zeekctl', 'zeek-core']
            # Only refresh the metadata, avoiding full system update
            if quiet_install:
                makecache_cmd.insert(1, '-q')  # => dnf -q makecache --refresh
                install_cmd.insert(1, '-q')  # => dnf -q install -y zeek ...

            logger.debug("Installing Zeek with command: " + ' '.join(install_cmd))
            self.run_command(makecache_cmd)
            self.run_command(install_cmd)

            logger.info("Zeek installed successfully on Fedora.")
        except Exception as e:
            logger.debug("Zeek package not found in default repositories. Adding Zeek OBS repository...")
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

                logger.debug("Zeek installed successfully via added repository.")

            except Exception as e:
                logger.error("Package installation failed, attempting to install from source...")
                self.install_zeek_from_source()
                return
        self.configure_zeek()

    def install_zeek_rhel8(self):
        """
        Installs Zeek on RHEL 8 (Stream or Vault).
        """
        logger.debug("Detected RHEL 8. Proceeding with installation...")
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
            logger.debug("Zeek installed successfully via yum.")
        except Exception as e:
            logger.error("Package installation failed, attempting to install from source...")
            self.install_zeek_from_source()
            return
        self.configure_zeek()

    def install_zeek_centos_rhel(self):
        """
        Determines CentOS/RHEL version and installs Zeek accordingly.
        """
        logger.debug("Detected CentOS/RHEL. Proceeding with installation...")
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
        logger.debug("Detected CentOS 8. Proceeding with installation...")
        self.install_utilities()
        # Determine if it's CentOS 8 Stream or CentOS 8
        try:
            centos_version_info = self.run_command(['centos-release'], capture_output=True)
            if 'Stream' in centos_version_info:
                logger.debug("Installing Zeek on CentOS 8 Stream...")
                # Import Zeek GPG key for CentOS 8 Stream
                gpg_key_url = "https://download.opensuse.org/repositories/security:zeek/CentOS_8_Stream/repodata/repomd.xml.key"
                self.run_command(['rpm', '--import', gpg_key_url])
                # Add Zeek repository for CentOS 8 Stream
                zeek_repo_url = "https://download.opensuse.org/repositories/security:zeek/CentOS_8_Stream/security:zeek.repo"
                self.run_command(['curl', '-fsSL', '-o', '/etc/yum.repos.d/zeek.repo', zeek_repo_url])
            else:
                logger.debug("Installing Zeek on CentOS 8 (using Vault repository)...")
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
            logger.debug("Zeek installed successfully via yum.")
        except Exception as e:
            logger.error("Failed to detect CentOS version or install Zeek.")
            sys.exit(1)
        self.configure_zeek()

    def install_zeek_opensuse(self):
        """
        Installs Zeek on openSUSE. If repository installation fails, it falls back to installing from source.
        """
        if self.is_zeek_installed():
            logger.debug("Zeek is already installed.")
            self.run_command(['zeek', '--version'])
            return

        # Detect openSUSE version and get repository URLs
        repo_urls = self.get_opensuse_repo_urls()

        # Attempt to install Zeek via repository
        try:
            self.install_zeek_from_repo_opensuse(repo_urls)
        except Exception as e:
            logger.error(f"Repository installation failed: {e}")
            logger.debug("Falling back to building Zeek from source.")
            self.install_zeek_from_source_opensuse()

        time.sleep(2)
        # Final verification
        if self.is_zeek_installed():
            logger.debug("Zeek installed successfully.")
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

    def install_zeek_from_repo_opensuse(self, repo_urls):
        """
        Installs Zeek and necessary Python packages from the repository.
        """
        # Import GPG keys for the repositories
        logger.debug("Importing GPG keys for repositories.")
        self.run_command(['rpm', '--import',
                          'https://download.opensuse.org/repositories/devel:/languages:/python/openSUSE_Tumbleweed/repodata/repomd.xml.key'])
        self.run_command(['rpm', '--import',
                          'https://download.opensuse.org/repositories/security:/zeek/openSUSE_Tumbleweed/repodata/repomd.xml.key'])

        # Add Zeek and Python repositories
        logger.debug("Adding the Zeek and Python repositories.")
        self.run_command(['zypper', '--non-interactive', 'addrepo', '--check', '--refresh', '--name',
                          'Zeek Security Repository', repo_urls['zeek'], 'security_zeek'])
        self.run_command(['zypper', '--non-interactive', 'addrepo', '--check', '--refresh', '--name',
                          'devel:languages:python', repo_urls['python'], 'devel_languages_python'])

        # Refresh the repositories with auto-import of GPG keys
        self.run_command(['zypper', '--non-interactive', '--gpg-auto-import-keys', 'refresh', 'security_zeek',
                          'devel_languages_python'])

        # Install the required packages
        logger.debug("Installing required packages via zypper.")
        try:
            # Use the correct package name here
            self.run_command(['zypper', '--non-interactive', '--gpg-auto-import-keys', 'install', '-y',
                              'python3-GitPython'])
            logger.debug("python3-GitPython installed successfully.")
            self.run_command(['zypper', '--non-interactive', '--gpg-auto-import-keys', 'install', '--no-recommends',
                              '-y', 'zeek'])
            logger.debug("Zeek installed successfully via zypper.")
        except Exception as e:
            logger.error(f"Failed to install Zeek from repository: {e}")
            raise e

    def install_zeek_from_source_opensuse(self):
        """
        Installs Zeek from source if the repository installation fails.
        """
        logger.debug("Installing Zeek from source.")

        # Install build dependencies
        logger.debug("Installing build dependencies...")
        self.run_command(['zypper', '--non-interactive', 'install', '-y', 'make', 'cmake', 'flex', 'bison',
                          'libpcap-devel', 'libopenssl-devel', 'python3', 'python3-devel', 'swig', 'zlib-devel', 'wget',
                          'tar', 'gzip', 'gcc10', 'gcc10-c++'])

        # Set GCC to version 10
        logger.debug("Setting GCC to version 10...")
        self.run_command(['update-alternatives', '--install', '/usr/bin/gcc', 'gcc', '/usr/bin/gcc-10', '100'])
        self.run_command(['update-alternatives', '--install', '/usr/bin/g++', 'g++', '/usr/bin/g++-10', '100'])

        # Download and build Zeek from source
        zeek_version = self.zeek_version
        src_dir = Path.home() / 'src'
        src_dir.mkdir(parents=True, exist_ok=True)

        zeek_tar = src_dir / f"zeek-{zeek_version}.tar.gz"
        zeek_dir = src_dir / f"zeek-{zeek_version}"

        if not zeek_tar.is_file():
            logger.debug(f"Downloading Zeek source code version {zeek_version}...")
            self.run_command(['wget', f"https://download.zeek.org/zeek-{zeek_version}.tar.gz"], cwd=src_dir)

        if not zeek_dir.is_dir():
            logger.debug("Extracting Zeek source code...")
            self.run_command(['tar', '-xzf', zeek_tar], cwd=src_dir)

        build_dir = zeek_dir / 'build'
        build_dir.mkdir(parents=True, exist_ok=True)

        logger.debug("Building Zeek from source...")
        self.run_command(['cmake', '..'], cwd=build_dir)
        self.run_command(['make', '-j', str(os.cpu_count())], cwd=build_dir)
        self.run_command(['make', 'install'], cwd=build_dir)

        # Add Zeek to the system PATH
        self.add_zeek_to_path()

    def install_ss_network_analyzer_windows(self):
        """
        Installs Zeek on Windows.
        """
        logger.debug(f"Starting {SS_NETWORK_ANALYZER_SERVICE_NAME} installation on Windows...")

        # Get the latest release URL
        try:
            logger.debug(f"Fetching latest {SS_NETWORK_ANALYZER_SERVICE_NAME} release information...")
            release_info = self.get_latest_release_info(SS_NETWORK_ANALYZER_REPO)
        except Exception as e:
            logger.error(f"Failed to fetch latest {SS_NETWORK_ANALYZER_SERVICE_NAME} release info: {e}")
            sys.exit(1)

        # Categorize assets
        categorized_assets = self.categorize_assets(release_info['assets'])
        selected_assets = self.select_asset(categorized_assets)

        if not selected_assets:
            logger.error(f"No suitable {SS_NETWORK_ANALYZER_SERVICE_NAME} Windows asset found for installation.")
            sys.exit(1)

        asset_name, download_url = selected_assets[0]  # Get the first matching asset

        operating_system = platform.system().lower()
        # Define download and install paths
        if operating_system == "windows":
            tmp_path = Path(r"C:\Temp") / asset_name
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            final_path = Path(SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS)
            final_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure the directory exists
        else:
            logger.error(f"install_ss_network_analyzer_windows called on unsupported OS: {platform.system()}")
            sys.exit(1)

        logger.info(f"Downloading {asset_name} from {download_url}...")
        self.download_binary(download_url, tmp_path)

        logger.info(f"Installing {asset_name}...")
        self.run_installation_command(tmp_path, final_path)

        logger.info(f"{SS_NETWORK_ANALYZER_SERVICE_NAME} installation on Windows complete.")

    def download_binary(self, download_url, dest_path):
        """
        Downloads the binary from the specified URL to the destination path.
        """
        try:
            response = requests.get(download_url, stream=True)
            response.raise_for_status()
            with open(dest_path, 'wb') as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
            logger.debug(f"Downloaded binary to {dest_path}.")
        except Exception as e:
            logger.error(f"Failed to download binary: {e}")
            raise

    def get_latest_release_info(self, repo):
        """
        Fetches the latest release information from GitHub for the specified repository.
        """
        api_url = f"https://api.github.com/repos/{repo}/releases"
        response = requests.get(api_url)
        response.raise_for_status()
        releases = response.json()
        latest_release = releases[0]  # Assuming the first one is the latest
        return latest_release

    def categorize_assets(self, assets):
        """
        Categorizes the assets based on the predefined asset patterns.
        """
        categorized = {key: [] for key in SS_NETWORK_ANALYZER_ASSET_PATTERNS}
        for asset in assets:
            asset_name = asset["name"]
            download_url = asset["browser_download_url"]
            for key, pattern in SS_NETWORK_ANALYZER_ASSET_PATTERNS.items():
                if pattern in asset_name:
                    categorized[key].append((asset_name, download_url))
        return categorized

    def select_asset(self, categorized_assets):
        """
        Selects the appropriate asset for the current operating system.
        """
        system = platform.system().lower()
        logger.info(f"Detected system: {system}")
        if system == "linux":
            return categorized_assets.get("linux")
        elif system == "darwin":
            return categorized_assets.get("darwin")
        elif system == "windows":
            return categorized_assets.get("windows")
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

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
            logger.debug("Adding Zeek to the system PATH...")
            with bashrc.open('a') as file:
                file.write(f'\nexport PATH={zeek_bin}:$PATH\n')

            # Source the updated bashrc
            self.run_command(['bash', '-c', f'source {bashrc}'])

    def clean_build_directory(self):
        """
        Cleans the build directory if necessary.
        """
        logger.debug("Cleaning build directory...")
        build_dir = Path.cwd() / 'build'
        if build_dir.is_dir():
            try:
                self.run_command(['make', 'distclean'])
            except:
                shutil.rmtree(build_dir)
            logger.debug("Build directory cleaned.")
        else:
            logger.debug("No build directory to clean.")

    def install_build_dependencies(self):
        """
        Installs build dependencies required for building Zeek from source.
        """
        logger.debug("Installing build dependencies...")
        logger.debug(f"Detected OS: {self.os_id} {self.os_info.get('version_id', '')} {self.os_info.get('version', '')}")
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
            logger.debug("Build dependencies installed successfully.")
        except Exception as e:
            logger.error("Failed to install build dependencies.")
            logger.error(e)
            sys.exit(1)

    def install_zeek_from_source(self):
        """
        Installs Zeek from source.
        """
        logger.debug("Installing Zeek from source...")
        if self.is_zeek_installed():
            logger.debug("Skipping source installation as Zeek is already installed.")
            return
        # Set Zeek version
        zeek_version = self.zeek_version
        # Create non-root user if not exists
        try:
            self.run_command(['id', self.builder_user], capture_output=True)
            logger.debug(f"User '{self.builder_user}' already exists.")
        except subprocess.CalledProcessError:
            logger.debug(f"Creating user '{self.builder_user}'...")
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
        logger.debug("Running build script as 'builder' user...")
        self.run_command(['su', '-', self.builder_user, '-c', f"bash {build_script_path}"])
        # Clean up
        self.run_command(['rm', '-f', str(build_script_path)])
        logger.debug("Zeek installed successfully from source.")
        # Configure Zeek
        self.configure_zeek()


    def install_zeek_from_source_macos(self):
        """
        Installs Zeek from source on macOS using the existing non-root user.
        """
        logger.debug("Installing Zeek from source on macOS...")

        if self.is_zeek_installed():
            logger.debug("Skipping source installation as Zeek is already installed.")
            return

        # Set Zeek version
        zeek_version = self.zeek_version

        # Determine the non-root user

        user = os.getenv('SUDO_USER')
        if not user:
            logger.error('Could not determine the original non-root user. Exiting.')
            sys.exit(1)
        logger.debug(f"Using non-root user: {user}")

        # Install build dependencies via Homebrew (if not already installed)
        logger.debug("Installing build dependencies via Homebrew...")
        try:
            self.run_command(['brew', 'install', 'cmake', 'make', 'gcc', 'flex', 'bison', 'libpcap', 'openssl', 'python3', 'swig', 'zlib'], shell=False)
            logger.debug("Build dependencies installed successfully via Homebrew.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to install build dependencies: {e}")
            sys.exit(1)

        # Create a directory for the source code
        src_dir = Path(f"/Users/{user}/src")
        try:
            src_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Source directory created at {src_dir}.")
        except Exception as e:
            logger.error(f"Failed to create source directory at {src_dir}: {e}")
            sys.exit(1)

        # No need to change ownership on macOS
        logger.debug(f"Skipping ownership change for {src_dir} on macOS.")

        # Navigate to the source directory
        os.chdir(src_dir)

        # Download the Zeek source code if not already downloaded
        zeek_tar = src_dir / f"zeek-{zeek_version}.tar.gz"
        zeek_dir = src_dir / f"zeek-{zeek_version}"

        if not zeek_tar.is_file():
            logger.debug(f"Downloading Zeek source code version {zeek_version}...")
            self.run_command(['curl', '-LO', f"https://download.zeek.org/zeek-{zeek_version}.tar.gz"], cwd=src_dir)
            logger.debug("Zeek source code downloaded successfully.")
        else:
            logger.debug(f"Zeek source code version {zeek_version} already downloaded.")

        # Extract the source code if not already extracted
        if not zeek_dir.is_dir():
            logger.debug("Extracting Zeek source code...")
            self.run_command(['tar', '-xzf', str(zeek_tar)], cwd=src_dir)
            logger.debug("Zeek source code extracted successfully.")
        else:
            logger.debug("Zeek source code already extracted.")

        # Build and install Zeek from source
        logger.debug("Building and installing Zeek from source...")
        build_dir = zeek_dir / 'build'
        try:
            build_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Build directory created at {build_dir}.")
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
                logger.debug(f"Executing build command: {cmd}")
                self.run_command(['su', '-', user, '-c', f"cd {build_dir} && {cmd}"], shell=False)
            logger.debug("Zeek built and installed successfully from source.")
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
            search_directories = ['/opt/zeek', '/usr/local', '/usr', '/usr/bin/', '/usr/sbin/']

        # Check if zeek-config is already in the PATH
        if self.command_exists('zeek-config'):
            zeek_config_path = shutil.which('zeek-config')
            logger.debug(f"zeek-config found in PATH at: {zeek_config_path}")
        else:
            logger.debug("zeek-config not found in PATH. Searching common directories...")
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
            logger.debug(f"zeek-config found at {zeek_config_path} and added to PATH.")

        return zeek_config_path

    def find_zeek_installation(self):
        """
        Finds the Zeek installation path on macOS using Homebrew or default locations.
        Returns the installation directory or None if not found.
        """
        if platform.system() == 'Darwin':
            try:
                brew_output = subprocess.run(['brew', '--prefix', 'zeek'], capture_output=True, text=True)
                zeek_prefix = brew_output.stdout.strip()
                if zeek_prefix:
                    logger.debug(f"Detected Zeek installed via Homebrew at: {zeek_prefix}")
                    return Path(zeek_prefix)
            except subprocess.CalledProcessError:
                logger.error("Failed to detect Zeek installation using Homebrew.")
                return None
        else:
            # For non-macOS systems, use standard paths
            default_zeek_paths = [
                Path('/usr/local/bin/zeek'),
                Path('/opt/zeek/bin/zeek'),
                Path('/usr/bin/zeek')
            ]
            for path in default_zeek_paths:
                if path.exists():
                    return path.parent
        return None

    # def find_zeekctl(self, zeek_install_dir):
    #     """
    #     Finds the zeekctl executable in the Zeek installation directory.
    #     """
    #     zeekctl_path = zeek_install_dir / "bin/zeekctl"
    #     if zeekctl_path.exists():
    #         return zeekctl_path
    #     else:
    #         logger.error(f"zeekctl not found in {zeek_install_dir}.")
    #         return None

    def find_zeekctl(self, zeek_install_dir):
        """
        Attempts to locate the zeekctl executable in common installation paths.
        """

        logger.debug("find_zeekctl: searching for zeekctl...")
        logger.debug(f"Zeek installation directory: {zeek_install_dir}")
        possible_paths = [
            Path('/usr/bin/zeekctl'),
            Path('/opt/zeek/bin/zeekctl'),
            Path('/usr/local/bin/zeekctl'),  # Common on macOS
            Path(zeek_install_dir) / 'bin/zeekctl'
        ]
        zeekctl_path = next((path for path in possible_paths if path.exists()), None)
        if zeekctl_path:
            return zeekctl_path
        else:
            return shutil.which('zeekctl')

    def configure_log_directory(self, zeek_install_dir):
        """
        Ensures the log directory for Zeek exists and creates it if necessary.
        """
        logdir = zeek_install_dir / "logs"
        if not logdir.exists():
            try:
                logdir.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created log directory: {logdir}")
            except Exception as e:
                logger.error(f"Failed to create log directory: {logdir} - {e}")
                sys.exit(1)
        return logdir

    def update_node_cfg_macos(self):
        """
        Updates the interface in node.cfg for macOS.
        """
        if platform.system() != 'Darwin':
            return
        logger.debug("Updating node.cfg for macOS...")
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
            logger.debug(f"Using network interface: {interface}")
            # Path to node.cfg
            node_cfg = "/usr/local/etc/node.cfg"
            if not Path(node_cfg).is_file():
                logger.error(f"Error: node.cfg not found at {node_cfg}")
                sys.exit(1)
            # Update the node.cfg file with the correct interface
            self.run_command(['sed', '-i', '', f's/^interface=.*/interface={interface}/', node_cfg])
            logger.debug(f"Updated node.cfg with interface {interface}.")
        except Exception as e:
            logger.error("Failed to update node.cfg for macOS.")
            sys.exit(1)

    def update_zeekctl_cfg(self, zeek_install_dir):
        """
        Updates the LogDir and other relevant settings in the zeekctl.cfg file.
        """
        zeekctl_cfg_path = zeek_install_dir / "etc/zeekctl.cfg"
        logdir = zeek_install_dir / "logs"

        if zeekctl_cfg_path.exists():
            try:
                with open(zeekctl_cfg_path, 'r') as f:
                    config_lines = f.readlines()
                with open(zeekctl_cfg_path, 'w') as f:
                    for line in config_lines:
                        if line.startswith("LogDir"):
                            f.write(f"LogDir = {logdir}\n")
                        else:
                            f.write(line)
                logger.debug(f"Updated LogDir to {logdir} in {zeekctl_cfg_path}")
            except Exception as e:
                logger.error(f"Failed to update zeekctl.cfg: {e}")
                sys.exit(1)
        else:
            logger.warning(f"zeekctl.cfg not found at {zeekctl_cfg_path}")
            # It should continue to work

        # Ensure the logdir exists
        if not logdir.exists():
            try:
                logdir.mkdir(parents=True, exist_ok=True)
                logger.debug(f"Created log directory: {logdir}")
            except Exception as e:
                logger.error(f"Failed to create log directory: {logdir} - {e}")
                sys.exit(1)

    def configure_zeek(self):
        """
        Configures Zeek after installation, handling both Linux and macOS, and detects the correct network interface.
        """
        logger.debug("Configuring Zeek...")

        # Find the Zeek installation path
        zeek_install_dir = self.find_zeek_installation()
        if not zeek_install_dir:
            logger.error("Zeek installation directory not found.")
            sys.exit(1)

        # Update zeekctl.cfg with correct LogDir
        self.update_zeekctl_cfg(zeek_install_dir)
        # Known file paths for node.cfg and local.zeek across Linux and macOS
        node_cfg_paths = [Path('/etc/zeek/node.cfg'), Path('/opt/zeek/etc/node.cfg'), Path('/usr/local/etc/node.cfg')]
        local_zeek_paths = [Path('/usr/share/zeek/site/local.zeek'), Path('/opt/zeek/share/zeek/site/local.zeek'),
            Path('/usr/local/share/zeek/site/local.zeek')]

        # Find node.cfg and local.zeek paths
        node_cfg = next((p for p in node_cfg_paths if p.exists()), None)
        local_zeek = next((p for p in local_zeek_paths if p.exists()), None)

        if not node_cfg or not local_zeek:
            logger.error("Zeek configuration files not found in known locations.")
            sys.exit(1)

        logger.debug(f"Using node.cfg at: {node_cfg}")
        logger.debug(f"Using local.zeek at: {local_zeek}")

        # Detect network interface based on the platform
        try:
            if platform.system().lower() == 'darwin':
                # macOS uses 'route' to detect the default network interface
                route_output = self.run_command(['route', 'get', 'default'], capture_output=True)
                interface = None
                for line in route_output.splitlines():
                    if 'interface:' in line:
                        interface = line.split(':')[1].strip()
                        break
            else:
                # Linux uses 'ip route' to detect the default network interface
                ip_output = self.run_command(['ip', 'route'], capture_output=True)
                interface = next((line.split()[line.split().index('dev') + 1] for line in ip_output.splitlines() if
                                  'default' in line), None)

            if not interface:
                logger.error("Unable to detect network interface.")
                sys.exit(1)
            logger.debug(f"Using network interface: {interface}")
        except Exception as e:
            logger.error(f"Failed to detect network interface: {e}")
            sys.exit(1)

        # Update node.cfg with the detected network interface
        try:
            with open(node_cfg, 'w') as file:
                file.write(f"""[zeek]
    type=standalone
    host=localhost
    interface={interface}
    """)
            logger.debug(f"node.cfg updated at {node_cfg}")
        except Exception as e:
            logger.error(f"Failed to write to node.cfg: {e}")
            sys.exit(1)

        # Enable JSON logging in local.zeek
        try:
            with open(local_zeek, 'a') as file:
                file.write('\nredef LogAscii::use_json = T;\n')
            logger.debug(f"Enabled JSON logging in {local_zeek}")
        except Exception as e:
            logger.error(f"Failed to update local.zeek: {e}")
            sys.exit(1)

        # Find zeekctl
        zeekctl_path = self.find_zeekctl(zeek_install_dir)
        if not zeekctl_path:
            logger.error("zeekctl not found. Please ensure Zeek is installed correctly.")
            sys.exit(1)

        logger.debug(f"Using zeekctl at: {zeekctl_path}")

        if platform.system().lower() == 'darwin':
            logs_dir = os.path.join(zeek_install_dir, 'logs')
            spool_dir = os.path.join(zeek_install_dir, 'spool', 'zeek')
            Path(logs_dir).mkdir(parents=True, exist_ok=True)
            Path(spool_dir).mkdir(parents=True, exist_ok=True)
            # Ensure directories have proper permissions
            self.run_command(['chown', '-R', f'{os.getlogin()}:staff', logs_dir], require_root=True)
            self.run_command(['chown', '-R', f'{os.getlogin()}:staff', os.path.join(zeek_install_dir, 'spool')], require_root=True)

        # Deploy and start Zeek using zeekctl
        self.deploy_zeek(zeekctl_path)

    def deploy_zeek(self, zeekctl_path):
        """
        Deploys Zeek using zeekctl and handles any errors.
        """
        logger.debug("Deploying Zeek...")

        try:
            # Capture the output of the zeekctl deploy command
            result = self.run_command([str(zeekctl_path), 'deploy'], capture_output=True, check=True, require_root=True)

            # Log the output
            logger.debug("Zeek deploy output:\n" + result)
            print("Zeek deploy output:\n" + result)

            # Check the status after deployment
            logger.debug("Checking Zeek status...")
            status_output = self.run_command([str(zeekctl_path), 'status'],
                                             capture_output=True,
                                             check=True,
                                             require_root=False)
            logger.debug("Zeek status output:\n" + status_output)
            print("Zeek status output:\n" + status_output)

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to deploy Zeek: {e}. Command '{e.cmd}' returned non-zero exit status {e.returncode}.")

            # Capture and print diagnostic information with zeekctl diag
            logger.debug("Running zeekctl diag to gather diagnostic information...")
            try:
                diag_output = self.run_command([str(zeekctl_path), 'diag'], capture_output=True, require_root=True)
                logger.error(f"Zeek diagnostic output:\n{diag_output}")
                print(f"Zeek diagnostic output:\n{diag_output}")
            except subprocess.CalledProcessError as diag_error:
                logger.error(f"Failed to run zeekctl diag: {diag_error}")

            sys.exit(1)

    def install_utilities_macos(self):
        """
        Installs required utilities on macOS using Homebrew.
        """
        logger.debug("Installing required utilities for macOS...")

        # Determine the non-root user
        user = getpass.getuser()
        logger.debug(f"Using non-root user: {user}")

        # Check if Homebrew is installed
        if not self.command_exists('brew'):
            logger.debug("Homebrew not found. Installing Homebrew...")
            try:
                brew_install_cmd = '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
                self.run_command(f'bash -c "{brew_install_cmd}"', shell=True)
                logger.debug("Homebrew installed successfully.")
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
                logger.debug(f"Source directory created at {src_dir}.")
        except Exception as e:
            logger.error(f"Failed to create source directory at {src_dir}: {e}")
            sys.exit(1)

        # For macOS, do not change ownership
        if self.os_system == 'darwin':
            logger.debug(f"Skipping ownership change for {src_dir} on macOS.")
        else:
            # For Linux, change ownership
            try:
                self.run_command(['chown', '-R', f'{user}:staff', str(src_dir)])
                logger.debug(f"Ownership changed to {user}:staff for {src_dir}.")
            except subprocess.CalledProcessError as e:
                logger.warning(f"Failed to change ownership of {src_dir}: {e}. Proceeding without changing ownership.")

        return src_dir

    def install_dependencies(self):
        brew_install_cmd = f'brew install cmake make gcc flex bison libpcap openssl python3 swig zlib'
        try:
            self.run_command(brew_install_cmd, shell=True)
            logger.debug("Build dependencies installed successfully via Homebrew.")
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
        Installs Zeek on macOS, automatically selecting the appropriate version based on the macOS version.
        """
        logger.debug("Detected macOS. Proceeding with installation...")
        self.install_utilities_macos()

        # Determine the non-root user
        user = getpass.getuser()
        user_home = Path.home()
        logger.debug(f"Using non-root user: {user}")

        # Automatically choose Zeek version based on macOS version
        macos_version = platform.mac_ver()[0]
        major_version = int(macos_version.split('.')[0])

        if major_version == 11:  # macOS Big Sur
            zeek_version = "zeek@5.2.2"
            zeek_name = f"{user}/older-zeek/zeek"
            logger.debug("Detected macOS Big Sur. Proceeding with Zeek version 5.2.2.")

            # Create the custom tap if it doesn't exist
            tap_name = f"{user}/older-zeek"
            if not self.is_tap_installed(tap_name):
                try:
                    self.run_command(['brew', 'tap-new', tap_name], check=True, shell=False)
                    logger.debug(f"Tap '{tap_name}' created successfully.")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to create tap '{tap_name}': {e}")
                    sys.exit(1)
            else:
                logger.debug(f"Tap '{tap_name}' already exists. Skipping tap creation.")

            # Download the Zeek 5.2.2 formula directly using curl
            formula_path = f"/usr/local/Homebrew/Library/Taps/{user}/homebrew-older-zeek/Formula/zeek.rb"
            try:
                logger.debug("Downloading the Zeek 5.2.2 formula...")
                self.run_command(['curl', '-o', formula_path,
                                  'https://raw.githubusercontent.com/Homebrew/homebrew-core/666405fbc6af1f06a7ee70d0912a85129258847f/Formula/z/zeek.rb'],
                                 check=True,
                                 shell=False)
                logger.debug(f"Zeek 5.2.2 formula downloaded successfully to {formula_path}.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to download the Zeek formula: {e}. Proceeding to install from source.")
                self.create_source_directory()  # Ensure source directory exists
                self.install_zeek_from_source_macos()
                return

        elif major_version == 12:  # macOS Monterey
            zeek_version = "zeek@7.0.1"
            zeek_name = f"{user}/older-zeek/zeek"
            logger.debug("Detected macOS Monterey. Proceeding with Zeek version 7.0.1.")

            # Create the custom tap if it doesn't exist
            tap_name = f"{user}/older-zeek"
            if not self.is_tap_installed(tap_name):
                try:
                    self.run_command(['brew', 'tap-new', tap_name], check=True, shell=False)
                    logger.debug(f"Tap '{tap_name}' created successfully.")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to create tap '{tap_name}': {e}")
                    sys.exit(1)
            else:
                logger.debug(f"Tap '{tap_name}' already exists. Skipping tap creation.")

            # Download the Zeek 7.0.1 formula directly using curl
            formula_path = f"/usr/local/Homebrew/Library/Taps/{user}/homebrew-older-zeek/Formula/zeek.rb"
            try:
                logger.debug("Downloading the Zeek 7.0.1 formula...")
                self.run_command(['curl', '-o', formula_path,
                                  'https://raw.githubusercontent.com/Homebrew/homebrew-core/7e624e19de94dc6dccff8808f2b105480b2a9320/Formula/z/zeek.rb'],
                                 check=True,
                                 shell=False)
                logger.debug(f"Zeek 7.0.1 formula downloaded successfully to {formula_path}.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to download the Zeek formula: {e}. Proceeding to install from source.")
                self.create_source_directory()  # Ensure source directory exists
                self.install_zeek_from_source_macos()
                return

        elif major_version >= 13:  # macOS Ventura or newer
            zeek_version = "zeek"
            zeek_name = "zeek"
            logger.debug(
                "Detected macOS version newer than Monterey. Proceeding with the latest version of Zeek (latest).")

        else:  # macOS versions older than Big Sur
            logger.debug("Detected macOS version older than Big Sur. Proceeding to install Zeek from source.")
            self.create_source_directory()  # Ensure source directory exists
            self.install_zeek_from_source_macos()
            return

        # Attempt to install Zeek via Homebrew
        try:
            brew_info_cmd = ['brew', 'info', 'zeek']
            brew_info = self.run_command(brew_info_cmd, capture_output=True, shell=False)

            if 'Not installed' in brew_info or 'could not be found' in brew_info or 'No available formula' in brew_info:
                logger.info(f"Installing Zeek ({zeek_version}) using Homebrew...")
                zeek_install_cmd = ['brew', 'install', zeek_name]
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
            logger.debug(f"An unexpected error occurred: {e}. Proceeding to install Zeek from source.")
            self.create_source_directory()  # Creating source directory before installing from source
            self.install_zeek_from_source_macos()

        # Proceed with Zeek configuration
        self.configure_zeek()

    def detect_distro_and_install(self):
        """
        Detects the OS distribution and calls the appropriate installation function.
        """
        logger.debug("Detecting operating system and proceeding with installation...")
        if self.os_system == 'darwin':
            self.install_zeek_macos()
        elif self.os_system == 'linux':
            if self.os_id == 'ubuntu':
                self.install_zeek_ubuntu()
            elif self.os_id in ['debian', 'raspbian']:
                self.install_zeek_debian()
            elif self.os_id == 'fedora':
                self.install_zeek_fedora()
            elif self.os_id in ['centos', 'rhel']:
                self.install_zeek_centos_rhel()
            elif 'suse' in self.os_like:  # General check for all SUSE-based distros
                self.install_zeek_opensuse()
            else:
                logger.error(f"Unsupported Linux distribution: {self.os_id}")
                sys.exit(1)
        elif self.os_system == 'windows':
            self.install_ss_network_analyzer_windows()
            self.configure_network_interface_ss_network_analyzer_windows()
        else:
            logger.error("Unsupported operating system.")
            sys.exit(1)

    def install(self):
        """
        Install function to run the installation.
        """

        # Check privileges based on OS
        self.check_privileges()

        logger.info("Checking if Zeek is already installed...")
        if self.check_zeek_installed():
            self.configure_zeek()
        self.detect_distro_and_install()

    def uninstall(self):
        """
        Orchestrates the uninstallation of Zeek based on the detected OS and distribution.
        """
        logger.info("Starting Zeek uninstallation process...")

        if self.os_system == "darwin":
            self.uninstall_zeek_macos()
        elif self.os_system == "linux":
            self.stop_and_remove_zeek_service_linux()
            self.uninstall_zeek_linux()
        elif self.os_system == "windows":
            self.stop_and_remove_zeek_service_windows()
            self.uninstall_zeek_windows()
        else:
            logger.error(f"Unsupported OS for Zeek uninstallation: {self.os_system}")
            sys.exit(1)

    def uninstall_zeek_macos(self):
        """
        Uninstall Zeek on macOS using Homebrew. If Homebrew fails, attempt manual removal.
        """
        logger.debug("Starting Zeek uninstallation process on macOS.")

        try:
            # Step 1: Uninstall Zeek via Homebrew
            self.uninstall_zeek_via_brew()

            # If uninstallation via Homebrew succeeds, exit successfully
            logger.info("Zeek uninstallation via Homebrew completed successfully.")
            return

        except RuntimeError as e:
            logger.error(f"{e}")
            logger.info("Attempting manual removal of Zeek...")
            try:
                # Step 2: Manual removal
                self.handle_manual_removal_macos(e)
            except RuntimeError as manual_e:
                logger.error(f"{manual_e}")
                raise RuntimeError("Zeek uninstallation failed. Manual intervention may be required.") from manual_e

    def uninstall_zeek_via_brew(self):
        """
        Attempt to uninstall Zeek using Homebrew.
        """
        logger.debug("Attempting to uninstall Zeek via Homebrew...")
        try:
            result = subprocess.run(
                ["brew", "uninstall", "zeek"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            logger.info("Zeek has been successfully uninstalled via Homebrew.")
            logger.debug(f"Homebrew output: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            logger.error("Failed to uninstall Zeek via Homebrew.")
            logger.debug(f"Homebrew stderr: {e.stderr.strip()}")
            # Check if the error is due to Zeek not being installed
            if "No such keg" in e.stderr:
                logger.info("Zeek is not installed via Homebrew. No further action required.")
                raise RuntimeError("Zeek is not installed via Homebrew.") from e
            else:
                # Raise exception for other errors to attempt manual removal
                raise RuntimeError(e.stderr.strip()) from e

    def handle_manual_removal_macos(self, brew_error):
        """
        Handle manual removal of Zeek if Homebrew uninstallation fails.

        :param brew_error: The RuntimeError raised from brew uninstallation.
        """
        error_message = brew_error.args[0]
        logger.debug(f"Handling manual removal with error message: {error_message}")

        # Attempt to get the installation prefix using brew
        zeek_prefix = self._get_brew_prefix()
        if zeek_prefix:
            zeek_path = Path(zeek_prefix).resolve()
            logger.info(f"Manual removal of Zeek directory is required: {zeek_path}")
            logger.debug(f"Attempting to remove Zeek directory manually: {zeek_path}")

            # Check if the path exists before attempting validation
            if zeek_path.exists():
                # Validate the path to ensure safety
                if self._is_valid_zeek_path_macos(zeek_path):
                    logger.debug(f"Validated Zeek directory path: {zeek_path}")

                    # Attempt to remove the directory using sudo rm -rf
                    removal_success = self._remove_directory_with_sudo(zeek_path)
                    if removal_success:
                        logger.info("Zeek directory has been successfully removed manually.")
                        return
                    else:
                        # If removal failed, instruct the user to remove it manually
                        logger.warning(
                            f"Failed to remove Zeek directory: {zeek_path}. "
                            "You may need to remove it manually with elevated permissions."
                        )
                        logger.debug(f"Manual removal command: sudo rm -rf {zeek_path}")
                        raise RuntimeError(
                            f"Manual removal of Zeek directory failed. "
                            f"Please run: sudo rm -rf {zeek_path}"
                        )
                else:
                    logger.error(
                        f"The extracted path does not appear to be a valid Zeek installation directory: {zeek_path}"
                    )
                    raise RuntimeError(
                        "Uninstallation failed due to invalid manual removal path. "
                        "Please verify the Zeek installation directory."
                    )
            else:
                logger.info(f"Zeek directory does not exist: {zeek_path}. No manual removal needed.")
                return
        else:
            # If brew_prefix is not found, assume Zeek is not installed via Homebrew
            logger.info("No Zeek installation found via Homebrew. No manual removal needed.")
            return


    def _get_brew_prefix(self):
        """
        Get the installation prefix of Zeek via brew.

        :return: The prefix path as a string, or None if not found.
        """
        try:
            result = subprocess.run(
                ["brew", "--prefix", "zeek"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            zeek_prefix = result.stdout.strip()
            if zeek_prefix:
                logger.debug(f"Zeek is installed via Homebrew at: {zeek_prefix}")
                return zeek_prefix
        except subprocess.CalledProcessError as e:
            logger.debug(f"brew --prefix zeek failed: {e.stderr.strip()}")
        return None

    def _is_valid_zeek_path_macos(self, path):
        """
        Validate that the path is the expected Zeek installation directory.

        :param path: Path object representing the directory to validate.
        :return: True if valid, False otherwise.
        """
        # Define the expected base directory (Homebrew Cellar)
        expected_base = Path("/usr/local/Cellar/zeek")
        is_valid = expected_base in path.parents and path.exists()
        logger.debug(f"Validating Zeek path: {path} - Valid: {is_valid}")
        return is_valid

    def _remove_directory_with_sudo(self, path):
        """
        Attempt to remove the specified directory using 'sudo rm -rf'.

        :param path: Path object representing the directory to remove.
        :return: True if removal was successful, False otherwise.
        """
        try:
            logger.debug(f"Attempting to remove directory with sudo: {path}")
            # Construct the sudo rm -rf command
            remove_command = ["sudo", "rm", "-rf", str(path)]
            logger.debug(f"Running command: {' '.join(remove_command)}")
            subprocess.run(remove_command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            logger.debug(f"Directory {path} removed successfully with sudo.")
            return True
        except subprocess.CalledProcessError as rm_error:
            logger.error(f"Failed to remove Zeek directory with sudo: {rm_error.stderr.strip()}")
            return False
        except Exception as ex:
            logger.error(f"Unexpected error while removing directory with sudo: {ex}")
            return False

    def get_macos_package_id(self):
        """
        Retrieves the Zeek package identifier using pkgutil.
        Assumes the package ID contains 'zeek'.
        """
        try:
            result = subprocess.run(
                ["pkgutil", "--pkgs"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            packages = result.stdout.splitlines()
            for pkg in packages:
                if "zeek" in pkg.lower():
                    logger.debug(f"Identified Zeek package ID: {pkg}")
                    return pkg
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to list packages with pkgutil: {e.stderr.strip()}")
        return None

    def stop_and_remove_zeek_service_linux(self):
        """
        Stops and removes the Zeek service on Linux.
        This function checks if the Zeek service exists, stops it if running, removes the service file, and reloads systemd.
        """
        zeek_service_path = ZEEK_SERVICE_PATH_LINUX

        if Path(zeek_service_path).exists():
            logger.debug(f"Zeek service found at {zeek_service_path}. Proceeding to stop and remove it.")
            try:
                # Stop the service if it's running
                logger.debug("Stopping Zeek service...")
                result_stop = subprocess.run(["sudo", "systemctl", "stop", "zeek"],
                                             check=False,
                                             text=True,
                                             stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE)
                if result_stop.returncode == 0:
                    logger.debug("Zeek service stopped successfully.")
                else:
                    logger.warning(f"Zeek service may not have been running, or failed to stop: {result_stop.stderr}")

                # Disable the service
                logger.debug("Disabling Zeek service...")
                result_disable = subprocess.run(["sudo", "systemctl", "disable", "zeek"],
                                                check=False,
                                                text=True,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.PIPE)
                if result_disable.returncode == 0:
                    logger.debug("Zeek service disabled successfully.")
                else:
                    logger.warning(f"Failed to disable Zeek service: {result_disable.stderr}")

                # Remove the service file directly with sudo
                logger.debug(f"Removing Zeek service file at {zeek_service_path} with sudo...")
                result_remove = subprocess.run(["sudo", "rm", "-f", zeek_service_path],
                                               check=False,
                                               text=True,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
                if result_remove.returncode == 0:
                    logger.debug("Zeek service file removed successfully.")
                else:
                    logger.error(f"Failed to remove Zeek service file: {result_remove.stderr}")
                    raise

                # Reload systemd to reflect the changes
                logger.debug("Reloading systemd daemon to apply changes...")
                result_reload = subprocess.run(["sudo", "systemctl", "daemon-reload"],
                                               check=True,
                                               text=True,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE)
                if result_reload.returncode == 0:
                    logger.debug("Systemd daemon reloaded successfully.")
                else:
                    logger.warning(f"Failed to reload systemd daemon: {result_reload.stderr}")

                logger.info("Zeek service has been successfully stopped and removed.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to stop and remove Zeek service: {e.stderr}")
                raise
        else:
            logger.debug(f"Zeek service not found at {zeek_service_path}. Skipping stop and removal.")

    def uninstall_zeek_linux(self):
        """
        Uninstall Zeek on Linux based on the distribution's package manager.
        """
        if self.os_id == 'ubuntu' or self.os_id in ['debian', 'raspbian']:
            self.uninstall_with_apt("zeek")
        elif self.os_id == 'fedora':
            self.uninstall_with_dnf_yum("zeek", "dnf")
        elif self.os_id in ['centos', 'rhel']:
            self.uninstall_with_dnf_yum("zeek", "yum")
        elif 'suse' in self.os_like:  # General check for SUSE-based distributions
            self.uninstall_with_zypper("zeek")
        else:
            logger.error(f"Unsupported Linux distribution: {self.os_id}")
            sys.exit(1)

    def uninstall_with_apt(self, package_name):
        """
        Uninstall Zeek using apt on Debian-based systems.
        """
        logger.debug(f"Using apt to uninstall {package_name}...")
        try:
            result_remove = subprocess.run(["sudo", "apt-get", "remove", "--purge", "-y", package_name], check=True)
            result_autoremove = subprocess.run(["sudo", "apt-get", "autoremove", "-y"], check=True)

            if result_remove.returncode == 0 and result_autoremove.returncode == 0:
                logger.debug(f"{package_name} has been successfully uninstalled using apt.")
            else:
                logger.debug(f"{package_name} was not fully removed using apt. Some components may remain.")
        except subprocess.CalledProcessError as e:
            logger.error(f"apt failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_dnf_yum(self, package_name, package_manager):
        """
        Uninstall Zeek using dnf or yum on Fedora-based systems.
        """
        logger.debug(f"Using {package_manager} to uninstall {package_name}...")
        try:
            result = subprocess.run(["sudo", package_manager, "remove", "-y", package_name], check=True)

            if result.returncode == 0:
                logger.debug(f"{package_name} has been successfully uninstalled using {package_manager}.")
            else:
                logger.debug(f"{package_name} was not fully removed using {package_manager}. Some components may remain.")
        except subprocess.CalledProcessError as e:
            logger.error(f"{package_manager} failed to uninstall {package_name}: {e}")
            raise

    def uninstall_with_zypper(self, package_name):
        """
        Uninstall Zeek using zypper on SUSE-based distributions.
        """
        logger.debug(f"Using zypper to uninstall {package_name}...")
        try:
            result = subprocess.run(["sudo", "zypper", "rm", "-y", package_name], check=True)

            if result.returncode == 0:
                logger.debug(f"{package_name} has been successfully uninstalled using zypper.")
            else:
                logger.debug(f"{package_name} was not fully removed using zypper. Some components may remain.")
        except subprocess.CalledProcessError as e:
            logger.error(f"zypper failed to uninstall {package_name}: {e}")
            raise

    def uninstall_zeek_windows(self):
        """
        Uninstalls Zeek on Windows by removing the Zeek executable and updating PATH.
        """
        logger.info(f"Starting {SS_NETWORK_ANALYZER_SERVICE_NAME} uninstallation on Windows...")
        zeek_executable_path = Path(SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS)  # Adjust this path accordingly
        try:
            if zeek_executable_path.exists():
                logger.debug(f"Removing {SS_NETWORK_ANALYZER_SERVICE_NAME} executable at {zeek_executable_path}...")
                zeek_executable_path.unlink()
                logger.debug(f"{SS_NETWORK_ANALYZER_SERVICE_NAME} executable removed.")
            else:
                logger.debug(f"{SS_NETWORK_ANALYZER_SERVICE_NAME} executable not found; skipping removal.")

            # Remove Zeek bin directory from PATH
            zeek_bin_dir = zeek_executable_path.parent
            self.remove_zeek_from_windows_path(zeek_bin_dir)

            logger.info("Zeek has been successfully uninstalled from Windows.")
        except Exception as e:
            logger.error(f"Failed to uninstall Zeek on Windows: {e}")
            raise

    def remove_zeek_from_windows_path(self, zeek_bin_dir):
        """
        Removes the Zeek binary directory from the Windows PATH environment variable.
        """
        try:
            logger.debug(f"Removing {SS_NETWORK_ANALYZER_SERVICE_NAME} from Windows PATH...")
            # Get current PATH from the system
            current_path = os.environ.get('PATH', '')
            zeek_bin_dir_str = str(zeek_bin_dir)
            if zeek_bin_dir_str in current_path:
                # Remove Zeek bin directory from PATH
                new_path = current_path.replace(f"{zeek_bin_dir_str};", "").replace(f";{zeek_bin_dir_str}", "")
                os.environ['PATH'] = new_path

                # Update the system PATH permanently using setx
                result_setx = subprocess.run(['setx', 'PATH', new_path], check=True)
                if result_setx.returncode == 0:
                    logger.debug(f"Removed {zeek_bin_dir_str} from PATH.")
                else:
                    logger.debug(f"Failed to remove {zeek_bin_dir_str} from PATH using setx.")
            else:
                logger.debug(f"{SS_NETWORK_ANALYZER_SERVICE_NAME} binary directory is not in PATH.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to remove {SS_NETWORK_ANALYZER_SERVICE_NAME} from PATH: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error while removing {SS_NETWORK_ANALYZER_SERVICE_NAME} from PATH: {e}")
            raise

    def stop_and_remove_zeek_service_windows(self):
        """
        Stops and removes the Zeek service on Windows.
        """
        os_system = platform.system().lower()
        if os_system != 'windows':
            logger.warning("The stop_and_remove_zeek_service method is intended for Windows platforms.")
            return

        try:
            # Check if the service exists
            logger.debug(f"Checking if the '{SS_NETWORK_ANALYZER_SERVICE_NAME}' service exists...")
            result = subprocess.run(['sc.exe', 'query', SS_NETWORK_ANALYZER_SERVICE_NAME], capture_output=True, text=True)
            service_exists = f"SERVICE_NAME: {SS_NETWORK_ANALYZER_SERVICE_NAME}" in result.stdout

            if service_exists:
                # Stop the service if it's running
                logger.debug(f"Attempting to stop the '{SS_NETWORK_ANALYZER_SERVICE_NAME}' service...")
                stop_result = subprocess.run(['sc.exe', 'stop', SS_NETWORK_ANALYZER_SERVICE_NAME], capture_output=True, text=True)
                if "FAILED" in stop_result.stdout or "FAILED" in stop_result.stderr:
                    logger.warning(f"Failed to stop service '{SS_NETWORK_ANALYZER_SERVICE_NAME}'. It might not be running.")
                    logger.debug(f"stop_result stdout: {stop_result.stdout.strip()}")
                    logger.debug(f"stop_result stderr: {stop_result.stderr.strip()}")
                else:
                    logger.info(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' stopped successfully.")
                    # Wait for the service to stop completely
                    time.sleep(2)

                # Delete the service
                logger.debug(f"Deleting service '{SS_NETWORK_ANALYZER_SERVICE_NAME}'...")
                delete_result = subprocess.run(['sc.exe', 'delete', SS_NETWORK_ANALYZER_SERVICE_NAME],
                                               check=True,
                                               capture_output=True,
                                               text=True)
                if "SUCCESS" in delete_result.stdout:
                    logger.info(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' deleted successfully.")
                else:
                    logger.warning(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' deletion output: {delete_result.stdout.strip()}")
            else:
                logger.info(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' does not exist. No need to stop or delete.")

        except subprocess.CalledProcessError as e:
            logger.error(f"Command '{' '.join(e.cmd)}' failed with exit status {e.returncode}")
            logger.error(f"stdout: {e.stdout.strip()}")
            logger.error(f"stderr: {e.stderr.strip() if e.stderr else 'No error output'}")
            raise

        except Exception as ex:
            logger.error(f"An unexpected error occurred while stopping and deleting the service: {ex}")
            raise

    def run_installation_command(self, dest_path, final_path):
        """
        Moves the downloaded binary to the final installation path and updates PATH.
        """
        try:
            logger.info(f"Moving {dest_path} to {final_path}...")

            if platform.system() in ["Linux", "Darwin"]:
                # Use sudo to move the file to a protected directory
                subprocess.run(["sudo", "cp", str(dest_path), str(final_path)], check=True)
                os.remove(str(dest_path))  # Remove the original file if the copy was successful

                # Set the necessary permissions and capabilities
                subprocess.run(["sudo", "chmod", "755", str(final_path)], check=True)

                if platform.system() == "Linux":
                    subprocess.run(["sudo", "setcap", "cap_net_raw,cap_net_admin=eip", str(final_path)], check=True)
                    logger.info(f"Set network capture capabilities on {final_path}.")

            elif platform.system() == "Windows":
                shutil.move(str(dest_path), str(final_path))

            logger.info(f"{final_path} has been installed successfully.")
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to move the file to {final_path}: {e}")
            raise
        except Exception as e:
            logger.error(f"Failed to move the file to {final_path}: {e}")
            raise

        # Verify installation by running the version command of the installed binary
        try:
            logger.info(f"Running '{final_path} --version' to verify installation...")
            result = subprocess.run([str(final_path), "--version"], check=True, capture_output=True, text=True)
            logger.info(f"Installed binary version: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            logger.error(f"Running {final_path} failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during installation verification: {e}")
            raise

    def configure_and_start_windows(self):
        """
        Configures and starts the Zeek service based on the operating system.
        Only executes on Windows platforms.
        """
        os_system = platform.system().lower()
        if os_system == 'windows':
            SystemUtility.request_admin_access()  # Assumes a method to elevate privileges if not already admin

            # Verify that the Zeek executable exists
            if not Path(SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS).exists():
                logger.error(f"Zeek executable not found at: {SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS}. Please verify the installation path.")
                raise FileNotFoundError(f"Zeek executable not found at {SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS}")

            try:
                # Check if the service exists
                logger.debug(f"Checking if the '{SS_NETWORK_ANALYZER_SERVICE_NAME}' service exists...")
                result = subprocess.run(['sc.exe', 'query', SS_NETWORK_ANALYZER_SERVICE_NAME], capture_output=True, text=True)
                service_exists = f'SERVICE_NAME: {SS_NETWORK_ANALYZER_SERVICE_NAME}' in result.stdout

                # Create the service if it doesn't exist
                if not service_exists:
                    logger.debug(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' not found. Creating the service...")
                    create_command = [
                        'sc.exe', 'create', SS_NETWORK_ANALYZER_SERVICE_NAME,
                        'binPath=', f'"{SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS}" start= auto',
                        'start=', 'auto'
                    ]
                    subprocess.run(create_command, check=True)
                    logger.info(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' created successfully.")

                # Configure the service
                logger.debug(f"Configuring service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' to use LocalSystem and auto-start on boot...")
                config_command = ['sc.exe', 'config', SS_NETWORK_ANALYZER_SERVICE_NAME, 'obj=', 'LocalSystem', 'start=', 'auto']
                subprocess.run(config_command, check=True, capture_output=True, text=True)
                logger.info(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' configured successfully.")

                # Check the service status before starting
                logger.debug(f"Checking the status of service '{SS_NETWORK_ANALYZER_SERVICE_NAME}'...")
                query_result = subprocess.run(['sc.exe', 'query', SS_NETWORK_ANALYZER_SERVICE_NAME], capture_output=True, text=True)

                if "RUNNING" in query_result.stdout:
                    logger.info(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' is already running. No need to start.")
                else:
                    # Start the service if not running
                    logger.debug(f"Starting service '{SS_NETWORK_ANALYZER_SERVICE_NAME}'...")
                    start_result = subprocess.run(['sc.exe', 'start', SS_NETWORK_ANALYZER_SERVICE_NAME], check=True, capture_output=True, text=True)
                    logger.info(f"Service '{SS_NETWORK_ANALYZER_SERVICE_NAME}' started successfully.")

            except subprocess.CalledProcessError as e:
                logger.error(f"Command '{' '.join(e.cmd)}' failed with exit status {e.returncode}")
                logger.error(f"stdout: {e.stdout.strip()}")
                logger.error(f"stderr: {e.stderr.strip() if e.stderr else 'No error output'}")
                raise

            except Exception as ex:
                logger.error(f"An unexpected error occurred: {ex}")
                raise

    def get_default_interface(self):
        system = platform.system().lower()
        interface = None

        if system == 'darwin':
            # macOS uses 'route' to detect the default network interface
            route_output = self.run_command(['route', 'get', 'default'], capture_output=True)
            for line in route_output.splitlines():
                if 'interface:' in line:
                    interface = line.split(':')[1].strip()
                    break

        elif system == 'linux':
            # Linux uses 'ip route' to detect the default network interface
            ip_output = self.run_command(['ip', 'route'], capture_output=True)
            for line in ip_output.splitlines():
                if 'default' in line:
                    parts = line.split()
                    if 'dev' in parts:
                        dev_index = parts.index('dev') + 1
                        if dev_index < len(parts):
                            interface = parts[dev_index]
                            break

        elif system == 'windows':
            # Step 1: Use PowerShell to get the default network interface's InterfaceAlias and InterfaceIndex in JSON
            ps_command = (
                "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                "Sort-Object -Property RouteMetric | "
                "Select-Object -First 1 | "
                "Select-Object InterfaceAlias, InterfaceIndex | "
                "ConvertTo-Json"
            )
            route_output = self.run_command(['powershell', '-Command', ps_command], capture_output=True)

            try:
                route_data = json.loads(route_output)
                interface_alias = route_data.get('InterfaceAlias')
                interface_index = route_data.get('InterfaceIndex')

                if interface_alias and interface_index:
                    logger.debug("Detected InterfaceAlias: %s, InterfaceIndex: %s", interface_alias, interface_index)
                    # Step 2: Retrieve the GUID for the InterfaceIndex using InterfaceGuid
                    ps_guid_command = (
                        f"Get-NetAdapter -InterfaceIndex {interface_index} | Select-Object -ExpandProperty InterfaceGuid | ConvertTo-Json"
                    )
                    guid_output = self.run_command(['powershell', '-Command', ps_guid_command], capture_output=True).strip()
                    interface_guid = json.loads(guid_output) if guid_output else None

                    if interface_guid:
                        # Format the NPF device name with double backslashes
                        device_name = f"\\Device\\NPF_{interface_guid.upper()}"
                        interface = device_name
                        logger.debug("Formatted NPF Device Name: %s", device_name)
                    else:
                        logger.warning("Failed to retrieve InterfaceGuid via PowerShell. Attempting fallback method.")
                        interface = self.fallback_windows_interface(interface_index)
                else:
                    logger.warning("PowerShell command did not return InterfaceAlias and InterfaceIndex. Attempting fallback method.")
                    interface = self.fallback_windows_interface()

            except json.JSONDecodeError as e:
                logger.error("Failed to parse PowerShell JSON output: %s", e)
                logger.debug("Raw PowerShell Output:\n%s", route_output)
                interface = self.fallback_windows_interface()

        else:
            logger.error("Unsupported operating system: %s", platform.system())
            sys.exit(1)

        if not interface:
            logger.error("Unable to detect network interface.")
            sys.exit(1)
        logger.debug("Using network interface: %s", interface)
        return interface

    def fallback_windows_interface(self, interface_index=None):
        """
        Fallback method to determine the default network interface by parsing 'route print' and using WMI.
        Returns the \\Device\\NPF_{GUID} if possible.
        """
        # Get the routing table
        route_output = self.run_command(['route', 'print'], capture_output=True)
        interface_ip = None
        in_ipv4_section = False

        for line in route_output.splitlines():
            line = line.strip()
            if line.startswith('IPv4 Route Table'):
                in_ipv4_section = True
                continue
            if in_ipv4_section:
                if line.startswith('Active Routes:') or line.startswith('Persistent Routes:'):
                    continue
                if line.startswith('Network Destination'):
                    # Header line, skip
                    continue
                if not line:
                    # End of IPv4 routes
                    break
                parts = line.split()
                if len(parts) >= 5 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                    # The interface is usually the fourth column (index 3)
                    interface_ip = parts[3]
                    break

        if not interface_ip:
            logger.error("Unable to find default route in 'route print' output.")
            return None

        # Map the interface IP to the interface's GUID using WMI with JSON output
        ps_guid_command = (
            f"Get-WmiObject Win32_NetworkAdapter | Where-Object {{ $_.IPAddress -contains '{interface_ip}' }} | Select-Object -ExpandProperty GUID | ConvertTo-Json"
        )
        guid_output = self.run_command(['powershell', '-Command', ps_guid_command], capture_output=True).strip()
        try:
            interface_guid = json.loads(guid_output) if guid_output else None
            if interface_guid:
                device_name = f"\\Device\\NPF_{interface_guid.upper()}"
                logger.debug("Formatted NPF Device Name from fallback: %s", device_name)
                return device_name
            else:
                logger.error("Failed to retrieve GUID via fallback method.")
                return None
        except json.JSONDecodeError as e:
            logger.error("Failed to parse fallback PowerShell JSON output: %s", e)
            logger.debug("Raw Fallback PowerShell Output:\n%s", guid_output)
            return None

    def configure_network_interface_ss_network_analyzer_windows(self):
        """
        Configures the selected network interface, log_dir, and flush_interval in the network-analyzer.conf file.
        If any of these keys are not set, it detects or assigns default values accordingly.
        """
        # Determine the current platform
        current_platform = platform.system().lower()

        # Define paths based on the platform
        if current_platform == 'windows':
            log_dir_default = SS_NETWORK_ANALYZER_LOG_PATH_WINDOWS
            config_dir = SS_NETWORK_ANALYZER_CONFIG_DIR_WINDOWS
        elif current_platform == 'linux':
            log_dir_default = SS_NETWORK_ANALYZER_LOG_PATH_LINUX
            config_dir = SS_NETWORK_ANALYZER_CONFIG_DIR_LINUX
        elif current_platform == 'darwin':
            log_dir_default = SS_NETWORK_ANALYZER_LOG_PATH_MACOS
            config_dir = SS_NETWORK_ANALYZER_CONFIG_DIR_MACOS
        else:
            logger.error("Unsupported operating system: %s", platform.system())
            sys.exit(1)

        # Define the configuration file path
        config_filename = NETWORK_ANALYZER_CONFIG_FILENAME
        config_path = os.path.join(config_dir, config_filename)

        # Ensure the configuration directory exists
        try:
            os.makedirs(config_dir, exist_ok=True)
            logger.debug("Ensured that the config directory exists: %s", config_dir)
        except Exception as e:
            logger.error("Failed to create config directory '%s': %s", config_dir, e)
            sys.exit(1)

        # Load existing config or initialize a new one
        config = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = toml.load(f)
                logger.debug("Loaded existing config file: %s", config_path)
            except toml.TomlDecodeError as e:
                logger.error("Failed to parse config file '%s': %s", config_path, e)
                sys.exit(1)
            except Exception as e:
                logger.error("Error reading config file '%s': %s", config_path, e)
                sys.exit(1)
        else:
            logger.debug("Config file does not exist. A new one will be created at: %s", config_path)

        # Flags to track if any updates are made
        config_updated = False

        # Check and set 'selected_interface' if not set
        if 'selected_interface' not in config or not config['selected_interface']:
            logger.info("'selected_interface' not set in config. Detecting default network interface...")
            # Detect the default network interface
            default_interface = self.get_default_interface()

            # Update the config with the detected interface
            config['selected_interface'] = default_interface
            logger.debug("Set 'selected_interface' to: %s", default_interface)
            config_updated = True
        else:
            logger.info("'selected_interface' is already set to: %s", config['selected_interface'])

        # Check and set 'log_dir' if not set
        if 'log_dir' not in config or not config['log_dir']:
            logger.info("'log_dir' not set in config. Setting to default path...")
            config['log_dir'] = log_dir_default
            logger.debug("Set 'log_dir' to: %s", config['log_dir'])
            config_updated = True
        else:
            logger.info("'log_dir' is already set to: %s", config['log_dir'])

        # Check and set 'flush_interval' if not set
        if 'flush_interval' not in config or not config['flush_interval']:
            logger.info("'flush_interval' not set in config. Setting to default value...")
            config['flush_interval'] = SS_NETWORK_ANALYZER_CONF_DEFAULT_FLUSH_INTERVAL
            logger.debug("Set 'flush_interval' to: %s", config['flush_interval'])
            config_updated = True
        else:
            logger.info("'flush_interval' is already set to: %s", config['flush_interval'])

        # Write the updated config back to the file if any updates were made
        if config_updated:
            try:
                with open(config_path, 'w') as f:
                    toml.dump(config, f)
                logger.info("Updated configuration in config file: %s", config_path)
            except Exception as e:
                logger.error("Failed to write to config file '%s': %s", config_path, e)
                sys.exit(1)
        else:
            logger.info("No updates made to the config file: %s", config_path)


if __name__ == "__main__":
    installer = ZeekInstaller()
    installer.install()
