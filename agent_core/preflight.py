"""Validate bootstrap inputs before stopping services or installing packages."""
import io
import logging
import platform
import re
import subprocess
import zipfile

import requests

from agent_core.secrets_manager import ContextName

logger = logging.getLogger("InstallationLogger")


def check_installation(api_url, context, keep_existing_sensors=False):
    slug = context[ContextName.ORG_SLUG]
    if not slug or not re.fullmatch(r"[a-zA-Z0-9_-]+", slug):
        raise ValueError("ORG_SLUG must be the organization slug from the setup wizard")
    if keep_existing_sensors:
        if platform.system() != "Linux":
            raise ValueError("--keep-existing-sensors requires Linux")
        for service in ("zeek", "osqueryd"):
            result = subprocess.run(["systemctl", "is-active", "--quiet", service])
            if result.returncode:
                raise RuntimeError(f"{service} must already be active to use --keep-existing-sensors")

    # Match the installer's development TLS behavior. Never follow redirects
    # with the organization credentials to another host.
    with requests.Session() as session:
        session.headers["Authorization"] = "Bearer " + context[ContextName.JWT_TOKEN]

        def fetch(path, headers=None):
            response = session.get(api_url + path, headers=headers, verify=False, timeout=20, allow_redirects=False)
            if response.status_code != 200:
                raise RuntimeError(f"Preflight {path}: HTTP {response.status_code}; check the local gateway and setup credentials")
            return response

        config = fetch("/configurations/agents").json()
        if config.get("organization_key") != context[ContextName.ORG_KEY]:
            raise ValueError("ORG_KEY does not match this organization's configuration")
        for section, keys in (("kafka", ("brokers", "topics")),
                              ("key_server", ("host", "port", "path")),
                              ("backend_server", ("host", "port", "path"))):
            if not all(config.get(section, {}).get(key) for key in keys):
                raise ValueError(f"Incomplete {section} configuration for {slug}")
        certificates = config.get("certificates", [])
        if not certificates or not all(certificates[0].get(key) for key in ("certificate_uuid", "principal", "sasl_password")):
            raise ValueError("Create a Kafka certificate in the setup wizard first")
        agents = fetch("/kafka/agent-certs/").json().get("certificates", [])
        if not agents or not agents[0].get("uuid"):
            raise ValueError("Create an agent certificate in the setup wizard first")
        for path, expected in (
            (f"/kafka/agent-certs/{agents[0]['uuid']}/", {"cacert.crt", "client.crt", "client.key"}),
            (f"/kafka/pki-certs/{certificates[0]['certificate_uuid']}/", {"cacert.crt"}),
        ):
            with zipfile.ZipFile(io.BytesIO(fetch(path).content)) as archive:
                if not expected.issubset(archive.namelist()) or archive.testzip() is not None:
                    raise ValueError("The certificate archive is incomplete or damaged")
        # The collector uses API keys and does not follow Django's slash redirects.
        # Exercise exactly the paths returned by the configuration endpoint.
        agent_headers = {
            "Authorization": None,
            "X-ORGANIZATION-KEY": context[ContextName.ORG_KEY],
            "X-API-ACCESS-KEY": context[ContextName.API_ACCESS_KEY],
            "X-API-SECRET-KEY": context[ContextName.API_SECRET_KEY],
        }
        for name in ("backend_server", "key_server"):
            public_path = config[name]["path"].replace("${client_id}", slug)
            prefix = "/api/v1/r/" + slug
            if not public_path.startswith(prefix + "/"):
                raise ValueError(f"Unexpected {name} path for {slug}")
            payload = fetch(public_path[len(prefix):], headers=agent_headers).json()
            if not isinstance(payload.get("entries"), list):
                raise ValueError(f"Invalid {name} response: expected entries")
            if name == "key_server" and not payload["entries"]:
                raise ValueError("Activate an encryption key in the local setup wizard first")
        logger.info("Organization configuration, certificates, and collector API requests passed preflight: %s", api_url)
