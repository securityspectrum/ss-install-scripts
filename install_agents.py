#!/usr/bin/env python3
import argparse
import platform
import logging
from logging.handlers import RotatingFileHandler
import sys

from agent_core.fluent_bit_installer import FluentBitInstaller
from agent_core.npcap_installer import NpcapInstaller
from agent_core.ss_agent_installer import SSAgentInstaller
from agent_core.system_utils import SystemUtility
from agent_core.secrets_manager import SecretsManager
from agent_core.ss_agent_configurator import SSAgentConfigurator
from agent_core.fluent_bit_configurator import FluentBitConfigurator
from agent_core.constants import *
from agent_core.certificate_manager import CertificateManager
from agent_core.zeek_installer import ZeekInstaller
from agent_core.osquery import OsqueryInstaller


def configure_logging(log_dir_path, log_level):
    # Ensure log directory exists
    log_dir = Path(log_dir_path)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / 'installation.log'

    # Get the root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)  # Set the log level based on the argument

    # Create console handler and file handler
    console_handler = logging.StreamHandler()
    file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=2)

    # Set log format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add handlers to the root logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


def get_platform_specific_paths():
    os_name = platform.system().lower()

    if os_name == "windows":
        fluent_bit_config_dir = FLUENT_BIT_CONFIG_DIR_WINDOWS
        ss_agent_config_dir = SS_AGENT_CONFIG_DIR_WINDOWS
        ss_agent_ssl_dir = SS_AGENT_SSL_DIR_WINDOWS
        # Unfortunately, Zeek does not support Windows
        raise NotImplementedError(f"Unsupported OS: {os_name}")
    elif os_name == "linux":
        fluent_bit_config_dir = FLUENT_BIT_CONFIG_DIR_LINUX
        ss_agent_config_dir = SS_AGENT_CONFIG_DIR_LINUX
        ss_agent_ssl_dir = SS_AGENT_SSL_DIR_LINUX
        zeek_log_path = ZEEK_LOG_PATH_LINUX
    elif os_name == "darwin":
        fluent_bit_config_dir = FLUENT_BIT_CONFIG_DIR_MACOS
        ss_agent_config_dir = SS_AGENT_CONFIG_DIR_MACOS
        ss_agent_ssl_dir = SS_AGENT_SSL_DIR_MACOS
        zeek_log_path = ZEEK_LOG_PATH_MACOS
    else:
        raise ValueError(f"Unsupported operating system: {os_name}")

    return fluent_bit_config_dir, ss_agent_config_dir, ss_agent_ssl_dir, zeek_log_path


def install(args):
    # Set up logging configuration globally
    log_level = getattr(logging, args.log_level.upper(), logging.DEBUG)

    # Configure logging with the provided log level
    logger = configure_logging(LOG_DIR_PATH, log_level)

    try:
        supported_os = ["linux", "darwin", "windows"]
        current_os = platform.system().lower()
        architecture = platform.machine()

        if current_os not in supported_os:
            logger.error(f"Unsupported operating system: {current_os} ({architecture})")
            sys.exit(1)

        logger.info(f"Beginning of ss-install-script execution process.")
        logger.info(f"ss-install-script version: {INSTALL_SCRIPT_VERSION}")
        logger.info(f"operating system: {current_os} ({architecture})")

        # Request sudo access at the start
        SystemUtility.elevate_privileges()

        # Before starting installation, check if services are already installed & running

        # SS Agent Installation
        ss_agent_installer = SSAgentInstaller()
        ss_agent_installer.stop_all_services_ss_agent()
        ss_agent_installer.stop_ss_agent()


        # Load or prompt for secrets
        secrets_manager = SecretsManager()
        secrets = secrets_manager.load_secrets_from_var_envs()
        organization_slug = secrets_manager.get_organization_slug()

        api_url = f"{API_URL_DOMAIN}{API_VERSION_PATH}/r/{organization_slug}"

        # Get platform-specific paths
        fluent_bit_config_dir, ss_agent_config_dir, ss_agent_ssl_dir, ss_network_analyzer_log_path = get_platform_specific_paths()

        # Certificate Manager
        cert_manager = CertificateManager(api_url, ss_agent_ssl_dir, organization_slug)
        cert_manager.download_and_extract_certificates(secrets["jwt_token"])
        logger.info("Certificate downloaded and extracted completed.")

        # Npcap Installation (only for Windows)
        if current_os == "windows":
            npcap_url = NPCAP_URL_WINDOWS
            installer = NpcapInstaller(download_url=npcap_url)

            installer.install_npcap()

        # Fluent Bit Configurator
        fluent_bit_configurator = FluentBitConfigurator(API_URL_DOMAIN, fluent_bit_config_dir, ss_agent_ssl_dir, organization_slug)
        fluent_bit_configurator.configure_fluent_bit(api_url, secrets, organization_slug)

        # Fluent Bit Installation
        fluent_bit_installer = FluentBitInstaller()
        fluent_bit_installer.install()

        # SS Agent Configurator
        ss_agent_configurator = SSAgentConfigurator(API_URL_DOMAIN, ss_agent_config_dir, ss_agent_ssl_dir)
        ss_agent_configurator.configure_ss_agent(secrets, Path(CONFIG_DIR_PATH) / SS_AGENT_TEMPLATE)

        ss_agent_installer.install()

        # Zeek Installer
        zeek_installer = ZeekInstaller()
        zeek_installer.install()

        # osquery Installation
        logger.info("Starting osquery setup...")
        osquery_installer = OsqueryInstaller()
        osquery_installer.install(extract_dir=OSQUERY_EXTRACT_DIR)
        logger.info("osquery setup completed successfully.")

        logger.info("Installation complete.")
    except Exception as e:
        logger.error("An error occurred during the installation process.", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='Install Zeek on openSUSE.')
    parser.add_argument('--log-level', default='DEBUG', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level')
    args = parser.parse_args()

    # Pass the logger to the main function
    install(args)
