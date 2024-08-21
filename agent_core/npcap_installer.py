import os
import subprocess
import sys
from pathlib import Path
import requests
import logging

from agent_core.constants import NPCAP_PATH

logger = logging.getLogger(__name__)

class NpcapInstaller:
    def __init__(self, download_url, installer_name="npcap-setup.exe"):
        self.download_url = download_url
        self.installer_path = Path(Path.home(), "Downloads", installer_name)  # Download to the user's Downloads directory

    def check_npcap_installed(self):
        """Check if Npcap is installed by looking for common installation directories or files."""
        npcap_dir = Path(NPCAP_PATH)
        # Define the key files that should exist
        expected_files = [
            npcap_dir / "npcap.cat",
            npcap_dir / "npcap.inf",
            npcap_dir / "npcap.sys",
            npcap_dir / "Uninstall.exe"
        ]

        # Check if the directory exists and contains the expected files
        if npcap_dir.exists() and all(f.exists() for f in expected_files):
            return True
        else:
            return False

    def download_npcap_installer(self):
        """Download the Npcap installer to the user's Downloads directory."""
        if self.installer_path.exists():
            logger.info(f"Npcap installer already exists at {self.installer_path}.")
            return
        logger.info(f"Downloading Npcap installer from {self.download_url} to {self.installer_path}")
        try:
            response = requests.get(self.download_url, stream=True)
            response.raise_for_status()

            with open(self.installer_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info(f"Npcap installer downloaded successfully to {self.installer_path}")
        except Exception as e:
            logger.error(f"Failed to download Npcap installer: {e}")
            sys.exit(1)

    def prompt_manual_installation(self):
        """Prompt the user to manually install Npcap."""
        print("\nNpcap is required but not installed.")
        print(f"The installer has been downloaded to {self.installer_path}.")
        print("Please follow the instructions below to install Npcap:")
        print("1. Locate and double-click the installer file.")
        print("2. Follow the installation prompts to complete the installation.")
        print("3. Ensure that you check any necessary options during installation.")
        print("4. After installation, return to this prompt and press Enter to continue.")
        os.startfile(str(self.installer_path))  # Automatically open the installer
        input("Press Enter after you have completed the Npcap installation...")

    def install_npcap(self):
        """Main method to handle the installation process."""
        if not self.check_npcap_installed():
            logger.info("Npcap not detected. Beginning installation process.")
            self.download_npcap_installer()
            self.prompt_manual_installation()
            if self.check_npcap_installed():
                logger.info("Npcap installation confirmed.")
            else:
                logger.error("Npcap installation failed or was not completed.")
                sys.exit(1)
        else:
            logger.info("Npcap is already installed.")
