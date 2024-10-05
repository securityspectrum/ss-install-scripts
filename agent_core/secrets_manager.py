import json
import os

import jwt
from pathlib import Path
import logging

logger = logging.getLogger('InstallationLogger')

class SecretsManager:
    def __init__(self, user_config_file):
        self.user_config_file = user_config_file
        self.organization_slug = ""

    def prompt_for_secrets(self):
        # Load secrets from environment variables if available, otherwise raise an error
        org_key = os.getenv("ORG_KEY")
        api_access_key = os.getenv("API_ACCESS_KEY")
        api_secret_key = os.getenv("API_SECRET_KEY")
        jwt_token = os.getenv("JWT_TOKEN")
        master_key = os.getenv("MASTER_KEY")

        if not all([org_key, api_access_key, api_secret_key, jwt_token, master_key]):
            raise EnvironmentError("One or more required environment variables are missing for secrets.")

        secrets = {
            "organization_key": org_key,
            "api_access_key": api_access_key,
            "api_secret_key": api_secret_key,
            "jwt_token": jwt_token,
            "master_key": master_key
        }

        try:
            with self.user_config_file.open("w") as f:
                json.dump(secrets, f)
            logger.debug(f"User secrets saved to {self.user_config_file}")
        except Exception as e:
            logger.error(f"Failed to save secrets to {self.user_config_file}: {e}")
            raise

        return secrets

    def load_secrets(self):
        if self.user_config_file.exists():
            logger.debug(f"Loading secrets from {self.user_config_file}")
            try:
                with self.user_config_file.open() as f:
                    secrets = json.load(f)
            except json.JSONDecodeError as e:
                logger.error(f"JSON decoding error: {e}")
                secrets = self.prompt_for_secrets()
            except Exception as e:
                logger.error(f"Failed to load secrets from {self.user_config_file}: {e}")
                raise
        else:
            logger.debug(f"{self.user_config_file} not found, prompting for secrets")
            secrets = self.prompt_for_secrets()

        self.organization_slug = self.decode_jwt(secrets["jwt_token"])
        return secrets

    @staticmethod
    def decode_jwt(jwt_token):
        try:
            decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
            return decoded_token["organization"]
        except jwt.DecodeError as e:
            logger.error(f"Failed to decode JWT: {e}")
            raise
        except KeyError:
            logger.error("JWT does not contain 'organization' key")
            raise

    def get_organization_slug(self):
        return self.organization_slug
