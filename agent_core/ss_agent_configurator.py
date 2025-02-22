# agent_core/ss_agent_configurator.py
import os
import tempfile  # Use tempfile for creating temporary files
from pathlib import Path
import logging
from string import Template
from agent_core.platform_context import PlatformContext
from agent_core.secrets_manager import ContextName
from agent_core.system_utils import SystemUtility
from agent_core.constants import API_URL_DOMAIN, API_VERSION_PATH, SS_AGENT_TEMPLATE

logger = logging.getLogger("InstallationLogger")
quiet_install = (logger.getEffectiveLevel() > logging.DEBUG)


class SSAgentConfigurator:
    def __init__(self, api_url_domain, config_dir, cert_dir):
        self.api_url_domain = api_url_domain
        # Ensure config_dir and cert_dir are Path objects
        self.config_dir = Path(config_dir)
        self.cert_dir = Path(cert_dir)
        self.platform_context = PlatformContext()

    def configure_ss_agent(self, context: dict, template_path: Path):
        """
        Configures the ss-agent by generating a config.json from a template.
        """
        logger.info(f"Configuring ss-agent using template: {template_path}")
        try:
            with open(template_path) as f:
                template = Template(f.read())
            logger.debug(f"Loaded ss-agent template from {template_path}")
        except Exception as e:
            logger.error(f"Error loading ss-agent template: {e}")
            return

        # Use as_posix() to ensure paths are JSON-compatible
        config = template.substitute(api_url=f"{self.api_url_domain}/api/v1",
                                     organization_key=context.get(ContextName.ORG_KEY, ""),
                                     api_access_key=context.get(ContextName.API_ACCESS_KEY, ""),
                                     api_secret_key=context.get(ContextName.API_SECRET_KEY, ""),
                                     cert_file=(self.cert_dir / "client.crt").as_posix(),
                                     key_file=(self.cert_dir / "client.key").as_posix(),
                                     ca_file=(self.cert_dir / "cacert.crt").as_posix())

        logger.debug(f"Generated ss-agent configuration: {config}")

        # Validate JSON
        try:
            import json
            json.loads(config)
            logger.debug("JSON configuration is valid.")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON configuration: {e}")
            return

        try:
            # Create a temporary file to store the config
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
            # Convert Path objects to strings before passing to the move_with_sudo function
            SystemUtility.move_with_sudo(str(Path(temp_config_path)), str(final_config_path))
            logger.debug(f"Moved config file to {final_config_path}")
        except Exception as e:
            logger.error(f"Error moving config file to {final_config_path}: {e}")
            return

        logger.info(f"ss-agent configured successfully at {final_config_path}")
