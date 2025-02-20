import tempfile
from subprocess import CalledProcessError

import requests
import zipfile
import shutil
from pathlib import Path
import platform
import logging

from agent_core.configure_logging import configure_logging
from agent_core.system_utils import SystemUtility

logger = logging.getLogger(__name__)

class CertificateManager:
    def __init__(self, api_url, cert_dir, organization_slug):
        self.api_url = api_url
        self.cert_dir = Path(cert_dir)
        self.organization_slug = organization_slug


    def download_and_extract_certificates(self, jwt_token):
        logger.info("Starting the process to download and extract certificates.")
        headers = {"Authorization": f"Bearer {jwt_token}"}

        logger.debug(f"Creating certificate directory: {self.cert_dir}")
        logger.debug("Using Authorization header for API requests.")

        cert_list_url = f"{self.api_url}/kafka/agent-certs/"
        logger.debug(f"Fetching certificate list from {cert_list_url}")


        try:
            response = requests.get(cert_list_url, headers=headers, verify=False)
            logger.debug(f"Received response with status code: {response.status_code} - content lenght ({len(response.content)}) bytes")
            response.raise_for_status()
        except requests.exceptions.SSLError as ssl_err:
            logger.error("SSL verification failed. Please check your SSL certificates.")
            raise RuntimeError("SSL verification failed. Please check your SSL certificates.") from ssl_err
        except requests.exceptions.HTTPError as http_err:
            if response.status_code == 401:
                logger.error("Authentication failed: Unauthorized access.")
                logger.error("Please verify that your JWT token is correct and has not expired.")
                raise RuntimeError("Failed to authenticate with the server. Ensure your JWT token is correct.") from http_err
            elif response.status_code == 403:
                logger.error("Access forbidden: You do not have the necessary permissions.")
                logger.error("Contact your administrator to obtain the required permissions.")
                raise RuntimeError("Access forbidden. Contact your administrator for necessary permissions.") from http_err
            elif response.status_code == 404:
                logger.error("Resource not found: The certificate endpoint does not exist.")
                logger.error("Ensure that the API URL is correct and the server is configured properly.")
                raise RuntimeError("Certificate endpoint not found. Verify the API URL and server configuration.") from http_err
            else:
                logger.error(f"HTTP error occurred: {http_err}")
                logger.error("Please check the server logs for more details or contact support.")
                raise RuntimeError("An HTTP error occurred while fetching certificates.") from http_err
        except requests.exceptions.ConnectionError:
            logger.error("Connection error: Unable to reach the server at localhost.")
            logger.error("Please ensure that the API service is running and accessible.")
            raise RuntimeError("Failed to connect to the server. Ensure the API service is running and accessible.") from None
        except requests.exceptions.Timeout:
            logger.error("Request timed out: The server took too long to respond.")
            logger.error("Try again later or contact support if the issue persists.")
            raise RuntimeError("The request timed out. Try again later.") from None
        except requests.exceptions.RequestException as e:
            logger.error(f"An unexpected error occurred: {e}")
            raise RuntimeError("An unexpected error occurred while fetching certificates.") from e

        logger.info("Successfully fetched the certificate list from the server.")

        try:
            cert_body = response.json()
            logger.debug(f"Certificate List Response JSON: {cert_body}")
            cert_uuid = cert_body['certificates'][0]['uuid']
            if not cert_uuid:
                logger.error("No certificates found in the response.")
                raise RuntimeError("No certificates available for download.")
        except (ValueError, KeyError, IndexError) as e:
            logger.error(f"Error parsing certificate data: {e}")
            raise RuntimeError("Invalid certificate data received from the server.") from e

        cert_url = f"{cert_list_url}{cert_uuid}/"
        logger.debug(f"Downloading certificate ZIP file from URL: {cert_url}")

        try:
            response = requests.get(cert_url, headers=headers, verify=False)
            logger.debug(f"Received response with status code: {response.status_code}")
            logger.debug(f"Response content length: {len(response.content)} bytes")
            response.raise_for_status()
        except requests.exceptions.SSLError as ssl_err:
            logger.error("SSL verification failed while downloading certificates.")
            raise RuntimeError("SSL verification failed during certificate download. Check your SSL certificates.") from ssl_err
        except requests.exceptions.HTTPError as http_err:
            if response.status_code == 401:
                logger.error("Authentication failed while downloading the certificate ZIP.")
                logger.error("Please verify that your JWT token is correct and has not expired.")
                raise RuntimeError("Failed to authenticate while downloading certificates. Check your JWT token.") from http_err
            elif response.status_code == 403:
                logger.error("Access forbidden: Cannot download the certificate ZIP.")
                logger.error("Ensure you have the necessary permissions to download certificates.")
                raise RuntimeError("Access forbidden. Ensure you have the necessary permissions to download certificates.") from http_err
            elif response.status_code == 404:
                logger.error("Certificate ZIP not found at the specified URL.")
                logger.error("Verify the certificate UUID and API endpoint.")
                raise RuntimeError("Certificate ZIP not found. Verify the certificate UUID and API endpoint.") from http_err
            else:
                logger.error(f"HTTP error occurred while downloading certificates: {http_err}")
                logger.error("Please check the server logs for more details or contact support.")
                raise RuntimeError("An HTTP error occurred while downloading certificates.") from http_err
        except requests.exceptions.ConnectionError:
            logger.error("Connection error: Unable to reach the server at localhost while downloading certificates.")
            logger.error("Please ensure that the API service is running and accessible.")
            raise RuntimeError("Failed to connect to the server for certificate download.") from None
        except requests.exceptions.Timeout:
            logger.error("Request timed out while downloading the certificate ZIP.")
            logger.error("Try again later or contact support if the issue persists.")
            raise RuntimeError("The certificate download request timed out. Try again later.") from None
        except requests.exceptions.RequestException as e:
            logger.error(f"An unexpected error occurred while downloading certificates: {e}")
            raise RuntimeError("An unexpected error occurred while downloading certificates.") from e

        logger.info("Successfully downloaded the certificate ZIP file from the server.")

        zip_path = Path("agent-service-certificates.zip")
        try:
            with zip_path.open("wb") as f:
                f.write(response.content)
            logger.info(f"Downloaded certificates ZIP file to {zip_path}")
        except IOError as e:
            logger.error(f"Failed to write ZIP file to disk: {e}")
            raise RuntimeError("Failed to save the certificate ZIP file.") from e
        except Exception as e:
            logger.error(f"An unexpected error occurred while saving the ZIP file: {e}")
            raise RuntimeError("Failed to save certificates due to an unexpected error.") from e

        self.extract_certificates(zip_path)

    def extract_certificates(self, zip_path):
        logger.info("Extracting certificate ZIP file to a temporary directory...")
        try:
            temp_cert_dir = Path(tempfile.mkdtemp())
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_cert_dir)
            logger.info(f"Extracted certificates to temporary directory: {temp_cert_dir}")
        except zipfile.BadZipFile as e:
            logger.error(f"The ZIP file is corrupted or not a valid ZIP archive: {e}")
            raise RuntimeError("Failed to extract certificates. The ZIP file is invalid.") from e
        except Exception as e:
            logger.error(f"An unexpected error occurred during extraction: {e}")
            raise RuntimeError("Failed to extract certificates due to an unexpected error.") from e

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
                logger.info(f"Permissions set successfully for {path}")
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
            # Create the directory with sudo for Unix-like systems
            if platform.system() != "Windows":
                logger.info(f"Creating directory {self.cert_dir} with sudo")
                SystemUtility.run_command(["sudo", "mkdir", "-p", str(self.cert_dir)])
            else:
                logger.info(f"Creating directory {self.cert_dir} on Windows")
                self.cert_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Error creating directory {self.cert_dir}: {e}")
            raise

        for item in temp_cert_dir.iterdir():
            try:
                dest_path = self.cert_dir / item.name
                if platform.system() != "Windows":
                    logger.info(f"Moving {item} to {dest_path} with sudo")
                    SystemUtility.move_with_sudo(str(item), str(dest_path))
                else:
                    logger.info(f"Moving {item} to {dest_path} without sudo")
                    shutil.move(str(item), str(dest_path))
                logger.info(f"Moved {item} to {dest_path}")
            except Exception as e:
                logger.error(f"Error moving {item} to {dest_path}: {e}")
                raise

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