from pathlib import Path

# Install script version
INSTALL_SCRIPT_VERSION = "1.0.0"

# Base API URL
API_URL_DOMAIN = "https://localhost"

# API version path
API_VERSION_PATH = "/api/v1"

# Directory paths
LOG_DIR_PATH = "logs"
RUNTIME_DIR_PATH = "runtime"
CONFIG_DIR_PATH = "config"

# Executable paths
SS_AGENT_EXECUTABLE_PATH_LINUX = "/usr/local/bin/ss-agent"
SS_AGENT_EXECUTABLE_PATH_MACOS = "/usr/local/bin/ss-agent"
SS_AGENT_EXECUTABLE_PATH_WINDOWS = r"C:\Program Files\ss-agent\ss-agent.exe"

SS_NETWORK_ANALYZER_EXECUTABLE_PATH_MACOS = "/usr/local/bin/ss-network-analyzer"
SS_NETWORK_ANALYZER_EXECUTABLE_PATH_LINUX = "/usr/local/bin/ss-network-analyzer"
SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS = r"C:\Program Files\ss-network-analyzer\ss-network-analyzer.exe"

# Npcap dirctory
NPCAP_PATH = "C:/Program Files/Npcap"
NPCAP_URL_WINDOWS = "https://npcap.com/dist/npcap-1.79.exe"

# Template file names
FLUENT_BIT_CONF_TEMPLATE = "fluent-bit-template.conf"
FLUENT_BIT_PARSER_TEMPLATE = "fluent-bit-parser-template.conf"

# Parser config file name
FLUENT_BIT_CONFIG_FILENAME = "fluent-bit.conf"
FLUENT_BIT_PARSER_CONFIG_FILENAME = "fluent-bit-parsers.conf"

# Certificate paths and files
CACERT_FILENAME = "cacert.crt"
FLUENT_BIT_CERTS_ZIP_TEMPLATE = "fluent-bit-certificates-{}.zip"

# fluent-bit paths
FLUENT_BIT_DIR_LINUX = "/etc/fluent-bit"
FLUENT_BIT_DIR_MACOS = "/Library/Application Support/FluentBit"
FLUENT_BIT_DIR_WINDOWS = r"C:\ProgramData\fluent-bit"

FLUENT_BIT_CONFIG_DIR_LINUX = "/etc/fluent-bit"
FLUENT_BIT_CONFIG_DIR_MACOS = "/Library/Application Support/FluentBit"
FLUENT_BIT_CONFIG_DIR_WINDOWS = r"C:\ProgramData\fluent-bit"

FLUENT_BIT_SSL_DIR_LINUX = "/etc/fluent-bit/ssl"
FLUENT_BIT_SSL_DIR_MACOS = "/Library/Application Support/FluentBit/ssl"
FLUENT_BIT_SSL_DIR_WINDOWS = r"C:\ProgramData\fluent-bit\ssl"

# Zeek config paths
ZEEK_CONFIG_DIR_LINUX = "/etc/fluent-bit"
ZEEK_CONFIG_DIR_MACOS = "/Library/Application Support/ss-network-analyzer/config"

# Zeek log paths
ZEEK_LOG_PATH_LINUX = "/opt/zeek/logs/current/*.log"
ZEEK_LOG_PATH_MACOS = "/usr/local/opt/zeek/logs/current/*.log"

# Network analyzer config paths
SS_NETWORK_ANALYZER_CONFIG_DIR_LINUX = "/etc/ss-network-analyzer/config"
SS_NETWORK_ANALYZER_CONFIG_DIR_MACOS = "/Library/Application Support/ss-network-analyzer/config"
SS_NETWORK_ANALYZER_CONFIG_DIR_WINDOWS = r"C:\ProgramData\ss-network-analyzer\config"

# Network analyzer log paths
SS_NETWORK_ANALYZER_LOG_PATH_LINUX = "/var/log/ss-network-analyzer/*.log"
SS_NETWORK_ANALYZER_LOG_PATH_MACOS = "/usr/local/var/log/ss-network-analyzer/*.log"
SS_NETWORK_ANALYZER_LOG_PATH_WINDOWS = r"C:\ProgramData\ss-network-analyzer\logs\*.log"

# Network analyzer config file name
NETWORK_ANALYZER_CONFIG_FILENAME = "network-analyzer.conf"

# ss-agent config path
SS_AGENT_CONFIG_DIR_LINUX = "/etc/ss-agent/config"
SS_AGENT_CONFIG_DIR_WINDOWS = r"C:\ProgramData\ss-agent\config"
SS_AGENT_CONFIG_DIR_MACOS = "/Library/Application Support/ss-agent/config"
SS_AGENT_SSL_DIR_LINUX = "/etc/ss-agent/ssl"
SS_AGENT_SSL_DIR_MACOS = "/Library/Application Support/ss-agent/ssl"
SS_AGENT_SSL_DIR_WINDOWS = r"C:\ProgramData\ss-agent\ssl"

# ss-agent config file template
SS_AGENT_TEMPLATE = "ss-agent-template.json"

# User configuration file
USER_CONFIG_FILE = "user_config.json"

# Repositories
FLUENT_BIT_REPO = "securityspectrum/fluent-bit"
SS_AGENT_REPO = "securityspectrum/ss-agent"
SS_NETWORK_ANALYZER_REPO = "securityspectrum/go-network-analyzer"

# Download directories
DOWNLOAD_DIR_LINUX = Path("/tmp")
DOWNLOAD_DIR_WINDOWS = Path(f"{Path.home()}\\Downloads")
DOWNLOAD_DIR_MACOS = Path("~/Downloads")

# Fluent Bit package names
FLUENT_BIT_ASSET_PATTERNS = {
    "centos8": "centos8.x86_64.rpm",
    "centos9": "centos9.x86_64.rpm",
    "fedora": "fedora.x86_64.rpm",  # Example if there's a specific Fedora build
    "debian": "debian-bookworm.amd64.deb",
    "ubuntu_18.04": "ubuntu-18.04.amd64.deb",
    "ubuntu_22.04": "ubuntu-22.04.amd64.deb",
    "macos": "intel.pkg",
    "windows": ".exe",
}
