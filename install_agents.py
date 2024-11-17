#!/usr/bin/env python3
import argparse
import platform
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys

from agent_core.fluent_bit_installer import FluentBitInstaller
from agent_core.npcap_installer import NpcapInstaller
from agent_core.ss_agent_installer import SSAgentInstaller
from agent_core.system_utils import SystemUtility
from agent_core.secrets_manager import SecretsManager, ContextName
from agent_core.ss_agent_configurator import SSAgentConfigurator
from agent_core.fluent_bit_configurator import FluentBitConfigurator
from agent_core.constants import *
from agent_core.certificate_manager import CertificateManager
from agent_core.zeek_installer import ZeekInstaller
from agent_core.osquery import OsqueryInstaller


def configure_logging(log_dir_path, log_level):
    log_dir = Path(log_dir_path)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / 'installation.log'

    # Get or create the root logger
    logger = logging.getLogger()

    # Set the overall log level
    logger.setLevel(log_level)

    # Define handlers
    console_handler = logging.StreamHandler()
    file_handler = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=2)

    # Set log level for handlers
    console_handler.setLevel(log_level)
    file_handler.setLevel(log_level)

    # Create formatters and add them to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger


def get_platform_specific_paths():
    os_name = platform.system().lower()

    if os_name == "windows":
        return FLUENT_BIT_DIR_WINDOWS, SS_AGENT_CONFIG_DIR_WINDOWS, SS_AGENT_SSL_DIR_WINDOWS, ZEEK_LOG_PATH_WINDOWS
    elif os_name == "linux":
        return FLUENT_BIT_CONFIG_DIR_LINUX, SS_AGENT_CONFIG_DIR_LINUX, SS_AGENT_SSL_DIR_LINUX, ZEEK_LOG_PATH_LINUX
    elif os_name == "darwin":
        return FLUENT_BIT_CONFIG_DIR_MACOS, SS_AGENT_CONFIG_DIR_MACOS, SS_AGENT_SSL_DIR_MACOS, ZEEK_LOG_PATH_MACOS
    else:
        raise ValueError(f"Unsupported operating system: {os_name}")


def install(args):
    log_level = getattr(logging, args.log_level.upper(), logging.DEBUG)
    logger = configure_logging(LOG_DIR_PATH, log_level)

    # Test logger to ensure it works
    logger.debug("Logger initialized at DEBUG level.")
    logger.info("Logger initialized at INFO level.")
    logger.warning("Logger initialized at WARNING level.")
    logger.error("Logger initialized at ERROR level.")
    logger.critical("Logger initialized at CRITICAL level.")

    try:
        supported_os = ["linux", "darwin", "windows"]
        current_os = platform.system().lower()
        architecture = platform.machine()

        if current_os not in supported_os:
            logger.error(f"Unsupported operating system: {current_os} ({architecture})")
            sys.exit(1)

        logger.info(f"Beginning of ss-install-script execution process.")
        logger.debug(f"ss-install-script version: {INSTALL_SCRIPT_VERSION}")
        logger.debug(f"Operating system: {current_os} ({architecture})")

        SystemUtility.elevate_privileges()

        ss_agent_installer = SSAgentInstaller()
        ss_agent_installer.stop_all_services_ss_agent()
        ss_agent_installer.stop_ss_agent()

        secrets_manager = SecretsManager()
        context = secrets_manager.load_secrets_from_var_envs()
        organization_slug = secrets_manager.get_organization_slug()

        api_url = f"{API_URL_DOMAIN}{API_VERSION_PATH}/r/{organization_slug}"

        fluent_bit_config_dir, ss_agent_config_dir, ss_agent_ssl_dir, zeek_log_path = get_platform_specific_paths()

        cert_manager = CertificateManager(api_url, ss_agent_ssl_dir, organization_slug)
        cert_manager.download_and_extract_certificates(context[ContextName.JWT_TOKEN])
        logger.debug("Certificate downloaded and extracted successfully.")

        if current_os == "windows":
            npcap_url = NPCAP_URL_WINDOWS
            npcap_installer = NpcapInstaller(download_url=npcap_url)
            npcap_installer.install_npcap()

        fluent_bit_installer = FluentBitInstaller()
        fluent_bit_installer.install()
        fluent_bit_installer.enable_and_start()

        fluent_bit_configurator = FluentBitConfigurator(API_URL_DOMAIN, fluent_bit_config_dir, ss_agent_ssl_dir, organization_slug)
        fluent_bit_configurator.configure_fluent_bit(api_url, context)

        ss_agent_configurator = SSAgentConfigurator(API_URL_DOMAIN, ss_agent_config_dir, ss_agent_ssl_dir)
        ss_agent_configurator.configure_ss_agent(context, Path(CONFIG_DIR_PATH) / SS_AGENT_TEMPLATE)

        ss_agent_installer.install()

        zeek_installer = ZeekInstaller()
        zeek_installer.install()
        zeek_installer.configure_and_start_windows()

        logger.info("Starting osquery setup...")
        osquery_installer = OsqueryInstaller()
        osquery_installer.install(extract_dir=OSQUERY_EXTRACT_DIR)
        osquery_installer.configure_and_start()
        logger.info("osquery setup completed successfully.")

        final_executable_path = ss_agent_installer.determine_executable_installation_path()
        ss_agent_installer.enable_and_start(final_executable_path)
        ss_agent_installer.start_all_services_ss_agent()

        logger.info("Installation complete.")
    except Exception as e:
        logger.error("An error occurred during the installation process.", exc_info=True)
        sys.exit(1)


def uninstall(args):
    log_level = getattr(logging, args.log_level.upper(), logging.DEBUG)
    logger = configure_logging(LOG_DIR_PATH, log_level)

    confirm_uninstallation()
    logger.info("Starting ss-agent uninstallation process...")

    ss_agent_installer = SSAgentInstaller()
    ss_agent_installer.stop_all_services_ss_agent()
    ss_agent_installer.stop_and_delete_windows_service()
    ss_agent_installer.stop_ss_agent()

    fluent_bit_installer = FluentBitInstaller()
    fluent_bit_installer.uninstall()

    osquery_installer = OsqueryInstaller()
    osquery_installer.uninstall()

    zeek_installer = ZeekInstaller()
    zeek_installer.uninstall()

    ss_agent_installer.uninstall()


def confirm_uninstallation():
    confirmation = input("Are you sure you want to uninstall SS Agent? [y/N]: ").strip().lower()
    if confirmation != 'y':
        logging.info("Uninstallation aborted by the user.")
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Install or uninstall SS Agent')
    parser.add_argument('--uninstall', action='store_true', help='Uninstall SS Agent')
    parser.add_argument('--install', action='store_true', help='Install SS Agent')
    parser.add_argument('--log-level', default='DEBUG', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level')
    args = parser.parse_args()

    if args.install:
        install(args)
    elif args.uninstall:
        uninstall(args)
    else:
        parser.print_help()
