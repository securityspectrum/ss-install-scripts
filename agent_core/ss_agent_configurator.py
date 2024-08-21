# agent_core/ss_agent_configurator.py
import os
import tempfile  # Use tempfile for creating temporary files
from pathlib import Path
import logging
from string import Template
from agent_core.platform_context import PlatformContext
from agent_core.system_utils import SystemUtility
from agent_core.constants import API_URL_DOMAIN, API_VERSION_PATH, SS_AGENT_TEMPLATE

logger = logging.getLogger('InstallationLogger')

class SSAgentConfigurator:
    def __init__(self, api_url_domain, config_dir, cert_dir):
        self.api_url_domain = api_url_domain
        # Ensure config_dir and cert_dir are Path objects
        self.config_dir = Path(config_dir)
        self.cert_dir = Path(cert_dir)
        self.platform_context = PlatformContext()

    def configure_ss_agent(self, secrets, template_path: Path):
        logger.debug(f"Configuring ss-agent using template: {template_path}")
        try:
            with open(template_path) as f:
                template = Template(f.read())
            logger.debug(f"Loaded ss-agent template from {template_path}")
        except Exception as e:
            logger.error(f"Error loading ss-agent template: {e}")
            return

        config = template.substitute(
            api_url=f"{self.api_url_domain}{API_VERSION_PATH}",
            organization_key=secrets["organization_key"],
            api_access_key=secrets["api_access_key"],
            api_secret_key=secrets["api_secret_key"],
            cert_file=str(self.cert_dir / "client.crt"),
            key_file=str(self.cert_dir / "client.key"),
            ca_file=str(self.cert_dir / "cacert.crt")
        )

        logger.debug(f"Generated ss-agent configuration: {config}")

        try:
            temp_config_fd, temp_config_path = tempfile.mkstemp(suffix=".json")
            with os.fdopen(temp_config_fd, 'w') as f:
                f.write(config)
            logger.debug(f"Created temporary config file: {temp_config_path}")
        except Exception as e:
            logger.error(f"Error creating temporary config file: {e}")
            return

        final_config_path = self.config_dir / "config.json"
        try:
            self.platform_context.create_directory(self.config_dir)
            SystemUtility.move_with_sudo(temp_config_path, str(final_config_path))
            logger.debug(f"Moved config file to {final_config_path}")
        except Exception as e:
            logger.error(f"Error moving config file to {final_config_path}: {e}")
