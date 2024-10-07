import json
import os

import jwt
from pathlib import Path
import logging

logger = logging.getLogger('InstallationLogger')


class SecretsManager:
    def __init__(self):
        self.organization_slug = None

    def load_secrets_from_var_envs(self):
        # Load secrets from environment variables if available, otherwise raise an error
        org_key = os.getenv("ORG_KEY")
        api_access_key = os.getenv("API_ACCESS_KEY")
        api_secret_key = os.getenv("API_SECRET_KEY")
        jwt_token = os.getenv("JWT_TOKEN")
        master_key = os.getenv("MASTER_KEY")

        if not all([org_key, api_access_key, api_secret_key, jwt_token, master_key]):
            raise EnvironmentError("One or more required environment variables are missing for secrets.")

        self.organization_slug = self.decode_jwt(jwt_token)

        secrets = {
            "organization_key": org_key,
            "api_access_key": api_access_key,
            "api_secret_key": api_secret_key,
            "jwt_token": jwt_token,
            "master_key": master_key
        }

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
