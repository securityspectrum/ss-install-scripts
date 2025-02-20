#!/usr/bin/env python3

import argparse
import platform
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# ------------------------
# Example imports (you'd adjust according to your actual code structure):
from agent_core.configure_logging import configure_logging
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


###############################################################################
# Main Installation Routines
###############################################################################
def install(args, logger):
    """
    Perform installation steps.
    """
    try:

        quiet_install = (args.log_level.upper() != "DEBUG")

        supported_os = ["linux", "darwin", "windows"]
        current_os = platform.system().lower()
        architecture = platform.machine()

        if current_os not in supported_os:
            logger.error(f"Unsupported operating system: {current_os} ({architecture})")
            sys.exit(1)

        logger.info("Beginning of ss-install-script execution process.")
        logger.debug(f"ss-install-script version: {INSTALL_SCRIPT_VERSION}")
        logger.debug(f"Operating system: {current_os} ({architecture})")

        SystemUtility.elevate_privileges()

        # Example usage of your classes:
        ss_agent_installer = SSAgentInstaller()
        ss_agent_installer.stop_all_services_ss_agent()
        ss_agent_installer.stop_ss_agent()

        secrets_manager = SecretsManager()
        context = secrets_manager.load_secrets_from_var_envs()
        organization_slug = secrets_manager.get_organization_slug()

        api_url = f"{API_URL_DOMAIN}{API_VERSION_PATH}/r/{organization_slug}"

        (fluent_bit_config_dir, ss_agent_config_dir, ss_agent_ssl_dir, zeek_log_path) = get_platform_specific_paths()

        cert_manager = CertificateManager(api_url, ss_agent_ssl_dir, organization_slug)
        cert_manager.download_and_extract_certificates(context[ContextName.JWT_TOKEN])
        logger.debug("Certificate downloaded and extracted successfully.")

        if current_os == "windows":
            npcap_installer = NpcapInstaller(download_url=NPCAP_URL_WINDOWS)
            npcap_installer.install_npcap()

        fluent_bit_installer = FluentBitInstaller(logger=logger, quiet_install=quiet_install)
        fluent_bit_installer.install()
        fluent_bit_installer.enable_and_start()

        fluent_bit_configurator = FluentBitConfigurator(API_URL_DOMAIN,
                                                        fluent_bit_config_dir,
                                                        ss_agent_ssl_dir,
                                                        organization_slug)
        fluent_bit_configurator.configure_fluent_bit(api_url, context)

        ss_agent_configurator = SSAgentConfigurator(API_URL_DOMAIN, ss_agent_config_dir, ss_agent_ssl_dir)
        ss_agent_configurator.configure_ss_agent(context, Path(CONFIG_DIR_PATH) / SS_AGENT_TEMPLATE)

        ss_agent_installer.install()

        zeek_installer = ZeekInstaller(logger=logger, quiet_install=quiet_install)
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
        logger.error("Installation failed: %s", e, exc_info=logger.isEnabledFor(logging.DEBUG))
        sys.exit(1)


def uninstall(args, logger):
    """
    Perform uninstallation steps.
    """
    try:

        quiet_install = (args.log_level.upper() != "DEBUG")

        confirm_uninstallation(logger)
        logger.info("Starting ss-agent uninstallation process...")

        ss_agent_installer = SSAgentInstaller()
        ss_agent_installer.stop_all_services_ss_agent()
        ss_agent_installer.stop_and_delete_windows_service()
        ss_agent_installer.stop_ss_agent()

        fluent_bit_installer = FluentBitInstaller(logger=logger, quiet_install=quiet_install)
        fluent_bit_installer.uninstall()

        osquery_installer = OsqueryInstaller()
        osquery_installer.uninstall()

        zeek_installer = ZeekInstaller(logger=logger, quiet_install=quiet_install)
        zeek_installer.uninstall()

        ss_agent_installer.uninstall()

        logger.info("Uninstallation complete.")
    except Exception as e:
        logger.error("Uninstallation failed: %s", e, exc_info=logger.isEnabledFor(logging.DEBUG))
        sys.exit(1)


def confirm_uninstallation(logger):
    """
    Confirm with the user before uninstalling.
    """
    confirmation = input("Are you sure you want to uninstall SS Agent? [y/N]: ").strip().lower()
    if confirmation != 'y':
        logger.info("Uninstallation aborted by the user.")
        sys.exit(0)


def get_platform_specific_paths():
    os_name = platform.system().lower()
    if os_name == "windows":
        return (FLUENT_BIT_DIR_WINDOWS, SS_AGENT_CONFIG_DIR_WINDOWS, SS_AGENT_SSL_DIR_WINDOWS, ZEEK_LOG_PATH_WINDOWS)
    elif os_name == "linux":
        return (FLUENT_BIT_CONFIG_DIR_LINUX, SS_AGENT_CONFIG_DIR_LINUX, SS_AGENT_SSL_DIR_LINUX, ZEEK_LOG_PATH_LINUX)
    elif os_name == "darwin":
        return (FLUENT_BIT_CONFIG_DIR_MACOS, SS_AGENT_CONFIG_DIR_MACOS, SS_AGENT_SSL_DIR_MACOS, ZEEK_LOG_PATH_MACOS)
    else:
        raise ValueError(f"Unsupported operating system: {os_name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Install or uninstall SS Agent')
    parser.add_argument('--install', action='store_true', help='Install SS Agent')
    parser.add_argument('--uninstall', action='store_true', help='Uninstall SS Agent')
    parser.add_argument('--log-level',
                        default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the console logging level')
    args = parser.parse_args()

    # Configure logging once here:
    LOG_DIR_PATH = "logs"  # or wherever you want
    logger = configure_logging(log_dir_path=LOG_DIR_PATH, console_level=args.log_level)

    if args.install:
        install(args, logger)
    elif args.uninstall:
        uninstall(args, logger)
    else:
        logger.info("No action specified. Use --install or --uninstall.")
