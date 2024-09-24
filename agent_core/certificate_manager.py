import tempfile
from subprocess import CalledProcessError

import requests
import zipfile
import shutil
from pathlib import Path
import platform
import logging
from agent_core.system_utils import SystemUtility

logger = logging.getLogger('InstallationLogger')

class CertificateManager:
    def __init__(self, api_url, cert_dir, organization_slug):
        self.api_url = api_url
        self.cert_dir = Path(cert_dir)
        self.organization_slug = organization_slug

    def download_and_extract_certificates(self, jwt_token):
        logger.info("Downloading and extracting certificates...")
        headers = {"Authorization": f"Bearer {jwt_token}"}

        cert_list_url = f"{self.api_url}/kafka/agent-certs/"
        logger.debug(f"Fetching certificate list from {cert_list_url}")
        response = requests.get(cert_list_url, headers=headers, verify=False)
        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Content Length: {len(response.content)} bytes")

        response.raise_for_status()
        logger.debug(f"Successfully fetched certificate list from {cert_list_url}")

        cert_body = response.json()
        logger.debug(f"Certificate List Response JSON: {cert_body}")
        cert_uuid = cert_body['certificates'][0]['uuid']
        if not cert_uuid:
            logger.error("No certificates found.")
            return

        cert_url = f"{cert_list_url}{cert_uuid}/"
        logger.debug(f"Downloading certificate ZIP file from URL: {cert_url}")
        response = requests.get(cert_url, headers=headers, verify=False)
        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Content Length: {len(response.content)} bytes")

        response.raise_for_status()
        logger.debug(f"Successfully downloaded certificate ZIP file from URL: {cert_url}")

        zip_path = Path("agent-service-certificates.zip")
        with zip_path.open("wb") as f:
            f.write(response.content)
        logger.info(f"Downloaded certificates ZIP file to {zip_path}")

        self.extract_certificates(zip_path)

    def extract_certificates(self, zip_path):
        logger.debug("Extracting certificate ZIP file to a temporary directory...")
        temp_cert_dir = Path(tempfile.mkdtemp())
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(temp_cert_dir)
        logger.info(f"Extracted certificates to temporary directory: {temp_cert_dir}")

        self.move_certificates(temp_cert_dir)

        for path in self.cert_dir.rglob("*"):
            try:
                logger.info(f"Setting permissions for {path}")
                if platform.system() == "Windows":
                    # Set permissions and enable inheritance for Windows
                    self.set_windows_permissions(path)
                else:
                    # Set permissions for Linux/macOS
                    self.set_unix_permissions(path)
                logger.info(f"Set permissions for {path}")
            except Exception as e:
                logger.error(f"Error setting permissions for {path}: {e}")

        self.cleanup_temp_files(zip_path, temp_cert_dir)

    def set_windows_permissions(self, path):
        try:
            # Enable inheritance for the directory and its contents
            SystemUtility.run_command(["icacls", str(path), "/inheritance:e"], check=True)

            # Set file permissions to readable by the owner only
            if path.is_file():
                SystemUtility.run_command(["icacls", str(path), "/grant:r", "everyone:F"], check=True)
            else:
                # Set directory permissions
                SystemUtility.run_command(["icacls", str(path), "/grant:r", "everyone:F"], check=True)

            logger.info(f"Successfully set permissions for {path}")
        except Exception as e:
            logger.error(f"Failed to set permissions for {path}: {e}")
            raise

    def set_unix_permissions(self, path):
        try:
            # Set file or directory permissions for Unix-like systems
            if path.is_file():
                SystemUtility.run_command(["chmod", "600", str(path)], check=True)
            else:
                SystemUtility.run_command(["chmod", "700", str(path)], check=True)
        except Exception as e:
            logger.error(f"Failed to set permissions for {path}: {e}")
            raise

    def move_certificates(self, temp_cert_dir):
        try:
            # Create the directory with sudo
            if platform.system() != "Windows":
                SystemUtility.run_command(["sudo", "mkdir", "-p", str(self.cert_dir)])
            else:
                self.cert_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Error creating directory {self.cert_dir}: {e}")

        for item in temp_cert_dir.iterdir():
            try:
                dest_path = self.cert_dir / item.name
                logger.info(f"Moving {item} to {dest_path} with sudo")
                SystemUtility.move_with_sudo(str(item), str(dest_path))
                logger.info(f"Moved {item} to {dest_path}")
            except Exception as e:
                logger.error(f"Error moving {item} to {dest_path}: {e}")

    def cleanup_temp_files(self, zip_path: Path, temp_cert_dir: Path):
        try:
            # Remove the temporary certificate directory
            if temp_cert_dir.exists() and temp_cert_dir.is_dir():
                shutil.rmtree(temp_cert_dir)
                logger.info(f"Temporary directory {temp_cert_dir} has been removed.")
            else:
                logger.warning(f"Temporary directory {temp_cert_dir} does not exist or is not a directory.")

            # Optionally, remove the ZIP file if it should not be kept
            if zip_path.exists() and zip_path.is_file():
                zip_path.unlink()
                logger.info(f"ZIP file {zip_path} has been removed.")
            else:
                logger.warning(f"ZIP file {zip_path} does not exist or is not a file.")

        except Exception as e:
            logger.error(f"Error cleaning up temporary files: {e}")
            raise