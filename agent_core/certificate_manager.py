import tempfile
import requests
import zipfile
import shutil
from pathlib import Path
import platform
import logging
from agent_core.system_utils import SystemUtility

logger = logging.getLogger("InstallationLogger")
quiet_install = (logger.getEffectiveLevel() > logging.DEBUG)


class CertificateManager:
    def __init__(self, api_url, cert_dir, organization_slug):
        self.api_url = api_url
        self.cert_dir = Path(cert_dir)
        self.organization_slug = organization_slug

    def download_and_extract_certificates(self, jwt_token):
        # INFO: Log key details about the download source and destination.
        cert_list_url = f"{self.api_url}/kafka/agent-certs/"
        logger.info(f"Downloading security certificates from: {cert_list_url}")
        logger.info(f"Certificates will be installed at: {self.cert_dir}")

        # DEBUG: More detailed info for troubleshooting.
        logger.debug(f"API URL: {self.api_url} | Certificate directory: {self.cert_dir}")
        headers = {"Authorization": f"Bearer {jwt_token}"}
        logger.debug(f"Fetching certificate list from: {cert_list_url}")

        try:
            # Step 1: Get the certificate list to find the certificate UUID
            response = requests.get(cert_list_url, headers=headers, verify=False)
            response.raise_for_status()
            cert_body = response.json()
            cert_uuid = cert_body['certificates'][0]['uuid']

            if not cert_uuid:
                logger.error("No valid certificates found")
                raise RuntimeError("No certificates available for download")

            # Step 2: Download the certificate ZIP with the UUID
            cert_url = f"{cert_list_url}{cert_uuid}/"
            logger.debug(f"Downloading certificate from: {cert_url}")
            response = requests.get(cert_url, headers=headers, verify=False)
            response.raise_for_status()

            # Step 3: Save ZIP file
            zip_path = Path("agent-service-certificates.zip")
            with zip_path.open("wb") as f:
                f.write(response.content)
            logger.debug(f"Saved ZIP file to: {zip_path.resolve()}")

            # Step 4: Extract certificates
            logger.debug("Extracting certificates...")
            temp_cert_dir = Path(tempfile.mkdtemp())
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_cert_dir)
            logger.debug(f"Certificates extracted to temporary directory: {temp_cert_dir}")

            # Step 5: Move certificates into the final destination
            self.move_certificates(temp_cert_dir)
            logger.debug(f"Certificates moved to final directory: {self.cert_dir}")

            # Step 6: Set appropriate permissions
            for path in self.cert_dir.rglob("*"):
                if platform.system() == "Windows":
                    self.set_windows_permissions(path)
                else:
                    self.set_unix_permissions(path)

            # Step 7: Clean up temporary files
            self.cleanup_temp_files(zip_path, temp_cert_dir)
            logger.info(f"Security certificates installed successfully in: {self.cert_dir}")

        except requests.exceptions.HTTPError as http_err:
            error_msg = self._get_http_error_message(http_err, response.status_code)
            logger.error(f"HTTP error: {error_msg}")
            raise RuntimeError(f"Certificate download failed: {error_msg}")
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as conn_err:
            logger.error(f"Connection error: {conn_err}")
            raise RuntimeError(
                "Failed to connect to the server. Check your network connection and that the service is running.")
        except (KeyError, ValueError, IndexError) as parse_err:
            logger.error(f"Error parsing certificate data: {parse_err}")
            raise RuntimeError("Invalid certificate data received from server")
        except zipfile.BadZipFile:
            logger.error("The downloaded file is not a valid ZIP archive")
            raise RuntimeError("Certificate archive is corrupted or invalid")
        except Exception as e:
            logger.error(f"Unexpected error during certificate processing: {e}")
            raise RuntimeError(f"Certificate installation failed: {str(e)}")

    def _get_http_error_message(self, error, status_code):
        """Helper to provide clear error messages based on HTTP status codes"""
        if status_code == 401:
            return "Authentication failed. Check that your JWT token is valid and not expired."
        elif status_code == 403:
            return "Access forbidden. You don't have permission to download certificates."
        elif status_code == 404:
            return "Certificate endpoint not found. Verify the API URL is correct."
        else:
            return f"HTTP error {status_code}: {str(error)}"

    def set_windows_permissions(self, path):
        try:
            SystemUtility.run_command(["icacls", str(path), "/inheritance:e"],
                                      check=True, quiet=quiet_install)
            SystemUtility.run_command(["icacls", str(path), "/grant:r", "everyone:F"],
                                      check=True, quiet=quiet_install)
            logger.debug(f"Successfully set permissions for {path}")
        except Exception as e:
            logger.error(f"Failed to set permissions for {path}: {e}")
            raise

    def set_unix_permissions(self, path):
        try:
            if path.is_file():
                SystemUtility.run_command(["chmod", "600", str(path)],
                                          check=True, quiet=quiet_install)
            else:
                SystemUtility.run_command(["chmod", "700", str(path)],
                                          check=True, quiet=quiet_install)
        except Exception as e:
            logger.error(f"Failed to set permissions for {path}: {e}")
            raise

    def move_certificates(self, temp_cert_dir):
        try:
            if platform.system() != "Windows":
                logger.debug(f"Creating directory {self.cert_dir} with sudo")
                SystemUtility.run_command(["sudo", "mkdir", "-p", str(self.cert_dir)],
                                          quiet=quiet_install)
            else:
                logger.debug(f"Creating directory {self.cert_dir} on Windows")
                self.cert_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Error creating directory {self.cert_dir}: {e}")
            raise

        for item in temp_cert_dir.iterdir():
            try:
                dest_path = self.cert_dir / item.name
                if platform.system() != "Windows":
                    logger.debug(f"Moving {item} to {dest_path} with sudo")
                    SystemUtility.move_with_sudo(str(item), str(dest_path))
                else:
                    logger.debug(f"Moving {item} to {dest_path} without sudo")
                    shutil.move(str(item), str(dest_path))
                logger.debug(f"Moved {item} to {dest_path}")
            except Exception as e:
                logger.error(f"Error moving {item} to {dest_path}: {e}")
                raise

    def cleanup_temp_files(self, zip_path: Path, temp_cert_dir: Path):
        try:
            if temp_cert_dir.exists() and temp_cert_dir.is_dir():
                shutil.rmtree(temp_cert_dir)
                logger.debug(f"Temporary directory {temp_cert_dir} has been removed.")
            else:
                logger.warning(f"Temporary directory {temp_cert_dir} does not exist or is not a directory.")
            if zip_path.exists() and zip_path.is_file():
                zip_path.unlink()
                logger.debug(f"ZIP file {zip_path} has been removed.")
            else:
                logger.warning(f"ZIP file {zip_path} does not exist or is not a file.")
        except Exception as e:
            logger.error(f"Error cleaning up temporary files: {e}")
            raise
