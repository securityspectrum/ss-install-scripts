import os
from pathlib import Path
import platform
import tempfile
import shutil
import zipfile
import requests
import logging
from string import Template

from agent_core.constants import SS_NETWORK_ANALYZER_LOG_PATH_LINUX, SS_NETWORK_ANALYZER_LOG_PATH_MACOS, \
    FLUENT_BIT_CONFIG_DIR_LINUX, FLUENT_BIT_SSL_DIR_LINUX, FLUENT_BIT_CONFIG_FILENAME, FLUENT_BIT_CONFIG_DIR_MACOS, \
    FLUENT_BIT_SSL_DIR_MACOS, SS_NETWORK_ANALYZER_LOG_PATH_WINDOWS, FLUENT_BIT_CONFIG_DIR_WINDOWS, \
    FLUENT_BIT_SSL_DIR_WINDOWS, CONFIG_DIR_PATH, FLUENT_BIT_CONF_TEMPLATE, FLUENT_BIT_PARSER_CONFIG_FILENAME, \
    FLUENT_BIT_PARSER_TEMPLATE, CACERT_FILENAME, ZEEK_LOG_PATH_LINUX, ZEEK_LOG_PATH_MACOS
from agent_core.platform_context import PlatformContext

logger = logging.getLogger(__name__)

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
            # Zeek is not supported on windows
            raise NotImplementedError(f"Unsupported OS: {system}")
            # self.ssl_ca_location = Path(FLUENT_BIT_SSL_DIR_WINDOWS) / organization_slug / "cacert.crt"
            # self.fluent_bit_config_path = Path(FLUENT_BIT_CONFIG_DIR_WINDOWS) / FLUENT_BIT_CONFIG_FILENAME
            # self.fluent_bit_ssl_path = Path(FLUENT_BIT_SSL_DIR_WINDOWS) / organization_slug
        else:
            raise NotImplementedError(f"Unsupported OS: {system}")

    @staticmethod
    def fetch_fluent_bit_config(api_url, jwt_token):
        logger.debug(f"Fetching Fluent Bit configuration...")
        headers = {"Authorization": f"Bearer {jwt_token}"}
        response = requests.get(f"{api_url}/configurations/agents", headers=headers, verify=False)
        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Content Length: {len(response.content)} bytes")
        response.raise_for_status()
        logger.debug(f"Successfully fetched Fluent Bit configuration from {api_url}/configurations/agents")
        return response.json()

    def configure_fluent_bit(self, api_url, secrets, organization_slug):
        logger.debug(f"Configuring Fluent Bit...")
        hostname = platform.node()
        try:
            config_data = self.fetch_fluent_bit_config(api_url, secrets["jwt_token"])
            logger.debug(f"Config data fetched: {config_data}")
        except Exception as e:
            logger.error(f"Error fetching Fluent Bit configuration: {e}")
            return

        logger.info(f"Generating Fluent Bit configuration...")
        fluent_bit_template_file = Path(CONFIG_DIR_PATH) / FLUENT_BIT_CONF_TEMPLATE
        try:
            with open(fluent_bit_template_file) as f:
                template = Template(f.read())
            logger.debug(f"Fluent Bit template file loaded: {fluent_bit_template_file}")
        except Exception as e:
            logger.error(f"Error loading Fluent Bit template file: {e}")
            return

        try:
            config = template.substitute(
                client_id=organization_slug,
                hostname=hostname,
                organization_key=secrets["organization_key"],
                api_access_key=secrets["api_access_key"],
                api_secret_key=secrets["api_secret_key"],
                sasl_username=config_data["certificates"][0]["principal"],
                sasl_password=config_data["certificates"][0]["sasl_password"],
                kafka_brokers=config_data["kafka"]["brokers"],
                kafka_topics=config_data["kafka"]["topics"],
                key_server_host=config_data["key_server"]["host"],
                key_server_port=config_data["key_server"]["port"],
                key_server_path=config_data["key_server"]["path"],
                backend_server_path=config_data["backend_server"]["path"],
                master_key=secrets["master_key"],
                zeek_log_path=self.zeek_log_path,
                ssl_ca_location=self.ssl_ca_location
            )
            logger.debug(f"Generated Fluent Bit config: {config}")
        except KeyError as e:
            logger.error(f"Key error in template substitution: {e}")
            return
        except Exception as e:
            logger.error(f"Error in template substitution: {e}")
            return

        temp_config_fd, temp_config_path = tempfile.mkstemp(suffix=".conf")
        try:
            with os.fdopen(temp_config_fd, 'w') as f:
                f.write(config)
            logger.debug(f"Created Fluent Bit config file: {temp_config_path}")
        except Exception as e:
            logger.error(f"Error creating Fluent Bit config file: {e}")
            return

        try:
            self.platform_context.create_directory(self.fluent_bit_config_path.parent)
            self.platform_context.move_file(Path(temp_config_path), self.fluent_bit_config_path)
            logger.debug(f"Moved Fluent Bit config file to {self.fluent_bit_config_path}")
        except Exception as e:
            logger.error(f"Error moving Fluent Bit config file to {self.fluent_bit_config_path}: {e}")

        self.download_and_extract_fluent_bit_certificates(api_url, secrets, organization_slug, config_data, self.fluent_bit_ssl_path)
        self.create_fluent_bit_parser_config(self.fluent_bit_config_path.with_name(FLUENT_BIT_PARSER_CONFIG_FILENAME))


    def download_and_extract_fluent_bit_certificates(self, api_url, secrets, organization_slug, config_data, certs_path: Path):
        temp_certs_path = Path(tempfile.mkdtemp())
        try:
            self.platform_context.create_directory(certs_path)
            logger.debug(f"Created Fluent Bit certs directory: {certs_path}")
        except Exception as e:
            logger.error(f"Error creating Fluent Bit certs directory: {certs_path}: {e}")

        certificate_uuid = config_data["certificates"][0]["certificate_uuid"]
        cert_url = f"{api_url}/kafka/pki-certs/{certificate_uuid}/"
        logger.debug(f"Downloading Fluent Bit certificates ZIP file from URL: {cert_url}")
        response = requests.get(cert_url, headers={"Authorization": f"Bearer {secrets['jwt_token']}"}, stream=True, verify=False)
        logger.debug(f"Response Status Code: {response.status_code}")
        logger.debug(f"Response Content Length: {len(response.content)} bytes")

        response.raise_for_status()
        logger.debug(f"Successfully downloaded Fluent Bit certificates ZIP file from URL: {cert_url}")

        zip_path = temp_certs_path / f"fluent-bit-certificates-{organization_slug}.zip"
        try:
            with zip_path.open("wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.debug(f"Downloaded Fluent Bit certificates ZIP file to {zip_path}")
        except Exception as e:
            logger.error(f"Error downloading Fluent Bit certificates ZIP file: {e}")
            return

        logger.debug(f"Extracting Fluent Bit certificates ZIP file: {zip_path}")
        try:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                zip_ref.extractall(temp_certs_path)
            logger.debug(f"Extracted Fluent Bit certificates to {temp_certs_path}")
        except zipfile.BadZipFile:
            logger.debug("Bad zip file encountered, attempting to handle multipart.")
            shutil.unpack_archive(str(zip_path), str(temp_certs_path))
            logger.debug(f"Extracted Fluent Bit certificates to {temp_certs_path}")
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
            logger.debug("Cleaned up temporary Fluent Bit certificate files")
        except Exception as e:
            logger.error(f"Error cleaning up temporary Fluent Bit certificate files: {e}")

        logger.debug("Fluent Bit configuration generated.")

    def create_fluent_bit_parser_config(self, parser_config_path):
        logger.debug("Creating Fluent Bit parser configuration...")
        parser_template_file = Path(CONFIG_DIR_PATH) / FLUENT_BIT_PARSER_TEMPLATE

        with open(parser_template_file) as f:
            parser_template = Template(f.read())

        parser_config = parser_template.substitute()

        temp_parser_config_fd, temp_parser_config_path = tempfile.mkstemp(suffix=".conf")
        try:
            with os.fdopen(temp_parser_config_fd, 'w') as f:
                f.write(parser_config)
            logger.debug(f"Created Fluent Bit parser config file: {temp_parser_config_path}")
        except Exception as e:
            logger.error(f"Error creating Fluent Bit parser config file: {e}")
            return

        try:
            self.platform_context.create_directory(parser_config_path.parent)
            self.platform_context.move_file(Path(temp_parser_config_path), parser_config_path)
            logger.debug(f"Moved Fluent Bit parser config file to {parser_config_path}")
        except Exception as e:
            logger.error(f"Error moving Fluent Bit parser config file to {parser_config_path}: {e}")