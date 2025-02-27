import logging
import os
import platform
import shutil
import tempfile
import zipfile
from pathlib import Path
from string import Template

import requests

from agent_core.constants import (
    FLUENT_BIT_CONFIG_DIR_LINUX, FLUENT_BIT_SSL_DIR_LINUX, FLUENT_BIT_CONFIG_FILENAME,
    FLUENT_BIT_CONFIG_DIR_MACOS, FLUENT_BIT_SSL_DIR_MACOS, CONFIG_DIR_PATH, FLUENT_BIT_CONF_TEMPLATE,
    FLUENT_BIT_PARSER_CONFIG_FILENAME, FLUENT_BIT_PARSER_TEMPLATE, CACERT_FILENAME, ZEEK_LOG_PATH_LINUX,
    ZEEK_LOG_PATH_MACOS, ZEEK_LOG_PATH_WINDOWS, FLUENT_BIT_SSL_DIR_WINDOWS, SS_NETWORK_ANALYZER_LOG_PATH_WINDOWS,
    FLUENT_BIT_DIR_WINDOWS, SS_NETWORK_ANALYZER_LOG_FILES_MATCH
)
from agent_core.platform_context import PlatformContext
from agent_core.secrets_manager import ContextName

logger = logging.getLogger("InstallationLogger")
quiet_install = (logger.getEffectiveLevel() > logging.DEBUG)


class FluentBitConfigurator:
    def __init__(self, api_url_domain, config_dir, ssl_dir, organization_slug):
        self.api_url_domain = api_url_domain
        self.platform_context = PlatformContext()
        self.config_dir = Path(config_dir)
        self.ssl_dir = Path(ssl_dir)
        self.organization_slug = organization_slug

        # Determine paths based on the OS during initialization
        system = platform.system().lower()
        if system == "linux":
            self.zeek_log_path = ZEEK_LOG_PATH_LINUX
            self.ssl_ca_location = Path(FLUENT_BIT_SSL_DIR_LINUX) / organization_slug / "cacert.crt"
            self.fluent_bit_config_path = Path(FLUENT_BIT_CONFIG_DIR_LINUX) / FLUENT_BIT_CONFIG_FILENAME
            self.fluent_bit_ssl_path = Path(FLUENT_BIT_SSL_DIR_LINUX) / organization_slug
        elif system == "darwin":
            self.zeek_log_path = ZEEK_LOG_PATH_MACOS
            self.ssl_ca_location = Path(FLUENT_BIT_SSL_DIR_MACOS) / organization_slug / "cacert.crt"
            self.fluent_bit_config_path = Path(FLUENT_BIT_CONFIG_DIR_MACOS) / FLUENT_BIT_CONFIG_FILENAME
            self.fluent_bit_ssl_path = Path(FLUENT_BIT_SSL_DIR_MACOS) / organization_slug
        elif system == "windows":
            self.zeek_log_path = SS_NETWORK_ANALYZER_LOG_PATH_WINDOWS + SS_NETWORK_ANALYZER_LOG_FILES_MATCH
            self.ssl_ca_location = Path(FLUENT_BIT_SSL_DIR_WINDOWS) / organization_slug / "cacert.crt"
            self.fluent_bit_config_path = Path(FLUENT_BIT_DIR_WINDOWS) / FLUENT_BIT_CONFIG_FILENAME
            self.fluent_bit_ssl_path = Path(FLUENT_BIT_SSL_DIR_WINDOWS) / organization_slug
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    @staticmethod
    def fetch_fluent_bit_config(api_url, jwt_token):
        logger.debug("Fetching Fluent Bit configuration...")
        headers = {"Authorization": f"Bearer {jwt_token}"}
        config_endpoint = f"{api_url}/configurations/agents"
        response = requests.get(config_endpoint, headers=headers, verify=False)
        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Content Length: {len(response.content)} bytes")
        response.raise_for_status()
        logger.debug(f"Successfully fetched Fluent Bit configuration from {config_endpoint}")
        return response.json()

    def configure_fluent_bit(self, api_url, context):
        logger.info("Configuring Fluent Bit logging service...")
        hostname = platform.node()

        # Fetch configuration data
        try:
            config_data = self.fetch_fluent_bit_config(api_url, context[ContextName.JWT_TOKEN])
            logger.debug("Fluent Bit configuration data fetched successfully.")
            logger.info(f"Configuration data retrieved from: {api_url}/configurations/agents")
        except Exception as e:
            logger.error(f"Error fetching Fluent Bit configuration: {e}")
            return

        # Validate configuration data structure
        required_keys = {"certificates": list, "kafka": dict, "key_server": dict, "backend_server": dict}
        for key, expected_type in required_keys.items():
            if key not in config_data:
                logger.error(f"Missing required key in config_data: '{key}'")
                return
            if not isinstance(config_data[key], expected_type):
                logger.error(f"Incorrect type for key '{key}': Expected {expected_type.__name__}, got {type(config_data[key]).__name__}")
                return

        if not config_data["certificates"]:
            logger.error("The 'certificates' list in config_data is empty.")
            return

        certificate = config_data["certificates"][0]
        for cert_key in ["principal", "sasl_password"]:
            if cert_key not in certificate:
                logger.error(f"Missing required key in certificate: '{cert_key}'")
                return

        for kafka_key in ["brokers", "topics"]:
            if kafka_key not in config_data["kafka"]:
                logger.error(f"Missing required key in Kafka config: '{kafka_key}'")
                return

        for ks_key in ["host", "port", "path"]:
            if ks_key not in config_data["key_server"]:
                logger.error(f"Missing required key in key_server config: '{ks_key}'")
                return

        if "path" not in config_data["backend_server"]:
            logger.error("Missing required key in backend_server config: 'path'")
            return

        # Generate Fluent Bit configuration using a template
        logger.info("Generating Fluent Bit configuration from template...")
        fluent_bit_template_file = Path(CONFIG_DIR_PATH) / FLUENT_BIT_CONF_TEMPLATE
        try:
            with open(fluent_bit_template_file) as f:
                template_content = f.read()
            template = Template(template_content)
            logger.debug(f"Loaded Fluent Bit template file: {fluent_bit_template_file}")
        except Exception as e:
            logger.error(f"Error loading Fluent Bit template file: {e}")
            return

        try:
            substitution_dict = {
                "client_id": context[ContextName.ORG_SLUG],
                "hostname": hostname,
                "organization_key": context[ContextName.ORG_KEY],
                "api_access_key": context[ContextName.API_ACCESS_KEY],
                "api_secret_key": context[ContextName.API_SECRET_KEY],
                "sasl_username": certificate["principal"],
                "sasl_password": certificate["sasl_password"],
                "kafka_brokers": config_data["kafka"]["brokers"],
                "kafka_topics": config_data["kafka"]["topics"],
                "key_server_host": config_data["key_server"]["host"],
                "key_server_port": config_data["key_server"]["port"],
                "key_server_path": config_data["key_server"]["path"],
                "backend_server_path": config_data["backend_server"]["path"],
                "master_key": context[ContextName.MASTER_KEY],
                "zeek_log_path": self.zeek_log_path,
                "ssl_ca_location": self.ssl_ca_location
            }
        except KeyError as e:
            logger.error(f"Missing required context key: {e}")
            return

        try:
            config = template.substitute(substitution_dict)
            logger.debug("Fluent Bit configuration generated via template substitution.")
        except Exception as e:
            logger.error(f"Error in template substitution: {e}")
            return

        # Write configuration to a temporary file and move it to final location
        try:
            temp_config_fd, temp_config_path = tempfile.mkstemp(suffix=".conf")
            with os.fdopen(temp_config_fd, 'w') as f:
                f.write(config)
            logger.debug(f"Created temporary Fluent Bit config file: {temp_config_path}")
        except Exception as e:
            logger.error(f"Error creating Fluent Bit config file: {e}")
            return

        try:
            self.platform_context.create_directory(self.fluent_bit_config_path.parent)
            self.platform_context.move_file(Path(temp_config_path), self.fluent_bit_config_path)
            logger.info(f"Fluent Bit configuration stored at: {self.fluent_bit_config_path}")
        except Exception as e:
            logger.error(f"Error moving Fluent Bit config file to {self.fluent_bit_config_path}: {e}")
            return

        # Download certificates and create parser config
        try:
            self.download_and_extract_fluent_bit_certificates(api_url, context, config_data, self.fluent_bit_ssl_path)
            self.create_fluent_bit_parser_config(self.fluent_bit_config_path.with_name(FLUENT_BIT_PARSER_CONFIG_FILENAME))
        except Exception as e:
            logger.error(f"Error during post-configuration steps: {e}")
            return

        logger.info("Fluent Bit configuration successfully generated and applied.")

    def download_and_extract_fluent_bit_certificates(self, api_url, context, config_data, certs_path: Path):
        temp_certs_path = Path(tempfile.mkdtemp())
        try:
            self.platform_context.create_directory(certs_path)
        except Exception as e:
            logger.error(f"Error creating Fluent Bit certificates directory {certs_path}: {e}")
            return

        certificate_uuid = config_data["certificates"][0]["certificate_uuid"]
        cert_url = f"{api_url}/kafka/pki-certs/{certificate_uuid}/"
        logger.info(f"Downloading Fluent Bit certificates from: {cert_url}")
        logger.debug(f"Certificate UUID: {certificate_uuid}")

        response = requests.get(
            cert_url,
            headers={"Authorization": f"Bearer {context[ContextName.JWT_TOKEN]}"},
            stream=True,
            verify=False
        )
        logger.debug(f"Download response status code: {response.status_code}")
        content_size = int(response.headers.get('content-length', 0))
        logger.debug(f"Download size: {content_size/1024/1024:.2f} MB")
        response.raise_for_status()

        zip_path = temp_certs_path / f"fluent-bit-certificates-{context[ContextName.ORG_SLUG]}.zip"
        try:
            with zip_path.open("wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.debug(f"Saved certificate ZIP to: {zip_path}")
        except Exception as e:
            logger.error(f"Error saving Fluent Bit certificates ZIP file: {e}")
            return

        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                file_list = zip_ref.namelist()
                logger.debug(f"ZIP file contains {len(file_list)} files.")
                zip_ref.extractall(temp_certs_path)
            logger.debug(f"Extracted certificates to temporary directory: {temp_certs_path}")
        except zipfile.BadZipFile:
            logger.debug("Bad ZIP file encountered, attempting extraction with shutil.unpack_archive.")
            shutil.unpack_archive(str(zip_path), str(temp_certs_path))
            logger.debug("Extraction via shutil.unpack_archive successful.")
        except Exception as e:
            logger.error(f"Error extracting Fluent Bit certificates ZIP file: {e}")
            return

        cacert_path = temp_certs_path / CACERT_FILENAME
        if not cacert_path.exists():
            logger.error(f"Error: {CACERT_FILENAME} not found in the ZIP file.")
            return

        for item in temp_certs_path.iterdir():
            try:
                dest_path = certs_path / item.name
                if dest_path.exists():
                    logger.debug(f"Overwriting existing file: {dest_path}")
                self.platform_context.move_file(item, dest_path)
                logger.debug(f"Moved {item} to {dest_path}")
            except Exception as e:
                logger.error(f"Error moving {item} to {dest_path}: {e}")

        try:
            shutil.rmtree(temp_certs_path)
            logger.debug("Cleaned up temporary Fluent Bit certificate files.")
        except Exception as e:
            logger.error(f"Error cleaning up temporary Fluent Bit certificate files: {e}")

        logger.info(f"Fluent Bit certificates installed at: {certs_path}")

    def create_fluent_bit_parser_config(self, parser_config_path):
        logger.info("Generating Fluent Bit parser configuration...")
        parser_template_file = Path(CONFIG_DIR_PATH) / FLUENT_BIT_PARSER_TEMPLATE
        try:
            with open(parser_template_file) as f:
                parser_template = Template(f.read())
            parser_config = parser_template.substitute()
            temp_parser_config_fd, temp_parser_config_path = tempfile.mkstemp(suffix=".conf")
            with os.fdopen(temp_parser_config_fd, 'w') as f:
                f.write(parser_config)
            self.platform_context.create_directory(parser_config_path.parent)
            self.platform_context.move_file(Path(temp_parser_config_path), parser_config_path)
            logger.info(f"Fluent Bit parser configuration stored at: {parser_config_path}")
        except Exception as e:
            logger.error(f"Error creating or moving Fluent Bit parser config file: {e}")

    def remove_configurations(self):
        logger.info("Uninstalling Fluent Bit configurations and certificates...")
        paths_to_remove = [
            self.fluent_bit_config_path,  # Fluent Bit main configuration file
            self.fluent_bit_ssl_path,      # SSL directory containing certificates
            self.zeek_log_path,            # Zeek log path if applicable
        ]

        for path in paths_to_remove:
            if path.is_dir():
                try:
                    shutil.rmtree(path)
                    logger.debug(f"Removed directory: {path}")
                except Exception as e:
                    logger.error(f"Failed to remove directory {path}: {e}")
            elif path.is_file():
                try:
                    path.unlink()
                    logger.debug(f"Removed file: {path}")
                except Exception as e:
                    logger.error(f"Failed to remove file {path}: {e}")

        unique_dirs = {path.parent for path in paths_to_remove}
        for dir_path in unique_dirs:
            if dir_path.is_dir() and not any(dir_path.iterdir()):
                try:
                    dir_path.rmdir()
                    logger.debug(f"Removed empty directory: {dir_path}")
                except Exception as e:
                    logger.error(f"Failed to remove empty directory {dir_path}: {e}")

        logger.info("Uninstallation of Fluent Bit configurations completed.")
