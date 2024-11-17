import json
import os
from enum import Enum

import jwt
from pathlib import Path
import logging

logger = logging.getLogger('InstallationLogger')


class ContextName(Enum):
    ORG_SLUG = "org_slug"
    ORG_KEY = "organization_key"
    API_ACCESS_KEY = "api_access_key"
    API_SECRET_KEY = "api_secret_key"
    JWT_TOKEN = "jwt_token"
    MASTER_KEY = "master_key"


class SecretsManager:
    def __init__(self):
        self.organization_slug = None

    def load_secrets_from_var_envs(self):
        # Load secrets from environment variables if available, otherwise raise an error
        org_slug = os.getenv("ORG_SLUG")
        org_key = os.getenv("ORG_KEY")
        api_access_key = os.getenv("API_ACCESS_KEY")
        api_secret_key = os.getenv("API_SECRET_KEY")
        jwt_token = os.getenv("JWT_TOKEN")
        master_key = os.getenv("MASTER_KEY")

        if not all([org_key, api_access_key, api_secret_key, jwt_token, master_key]):
            raise EnvironmentError("One or more required environment variables are missing for secrets.")

        self.jwt_token = self.decode_jwt(jwt_token)

        self.context = {
            ContextName.ORG_SLUG: org_slug,
            ContextName.ORG_KEY: org_key,
            ContextName.API_ACCESS_KEY: api_access_key,
            ContextName.API_SECRET_KEY: api_secret_key,
            ContextName.JWT_TOKEN: jwt_token,
            ContextName.MASTER_KEY: master_key
        }

        return self.context

    @staticmethod
    def decode_jwt(jwt_token):
        try:
            decoded_token = jwt.decode(jwt_token, options={"verify_signature": False})
            return decoded_token
        except jwt.DecodeError as e:
            logger.error(f"Failed to decode JWT: {e}")
            raise
        except KeyError:
            logger.error("JWT does not contain 'organization' key")
            raise

    def get_organization_slug(self):
        return self.context.get(ContextName.ORG_SLUG)
