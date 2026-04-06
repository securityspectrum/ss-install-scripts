# agent_core/__init__.py
# Lazy imports — only load modules when accessed, so consumers that only
# need specific installers don't hit missing-dependency errors.

def __getattr__(name):
    if name == "SystemUtility":
        from .system_utils import SystemUtility
        return SystemUtility
    if name == "SecretsManager":
        from .secrets_manager import SecretsManager
        return SecretsManager
    if name == "CertificateManager":
        from .certificate_manager import CertificateManager
        return CertificateManager
    if name == "SSAgentConfigurator":
        from .ss_agent_configurator import SSAgentConfigurator
        return SSAgentConfigurator
    if name == "FluentBitConfigurator":
        from .fluent_bit_configurator import FluentBitConfigurator
        return FluentBitConfigurator
    if name == "GitHubReleases":
        from .github_releases import GitHubReleases
        return GitHubReleases
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
