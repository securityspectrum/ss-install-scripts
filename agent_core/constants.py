from pathlib import Path
import platform
import os

# Install script version
INSTALL_SCRIPT_VERSION = "1.0.0"

# Base API URL
API_URL_DOMAIN = "https://ui.securityspectrum.io"

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
SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS = "C:/Program Files/ss-network-analyzer/bin/ss-network-analyzer.exe"

#SS_NETWORK_ANALYZER_EXECUTABLE_PATH_WINDOWS = r"C:\Program Files\Zeek\bin\zeek.exe"  # Desired installation path on Windows

# Npcap dirctory
NPCAP_PATH = "C:/Program Files/Npcap"
NPCAP_URL_WINDOWS = "https://npcap.com/dist/npcap-1.79.exe"

# Template file names
FLUENT_BIT_CONF_TEMPLATE = "fluent-bit-template.conf"
FLUENT_BIT_PARSER_TEMPLATE = "fluent-bit-parser-template.conf"

# Parser config file name
FLUENT_BIT_CONFIG_FILENAME = "fluent-bit.conf"
FLUENT_BIT_PARSER_CONFIG_FILENAME = "fluent-bit-parsers.conf"
FLUENT_BIT_SERVICE_NAME = 'fluent-bit'

# Certificate paths and files
CACERT_FILENAME = "cacert.crt"
FLUENT_BIT_CERTS_ZIP_TEMPLATE = "fluent-bit-certificates-{}.zip"

MACOS_LAUNCHD_SERVICE_PATH = "/Library/LaunchDaemons"

# fluent-bit paths
FLUENT_BIT_DIR_LINUX = "/etc/fluent-bit"
FLUENT_BIT_DIR_MACOS = "/Library/Application Support/FluentBit"
FLUENT_BIT_DIR_WINDOWS = "C:/Program Files/fluent-bit"
FLUENT_BIT_EXE_WINDOWS = FLUENT_BIT_DIR_WINDOWS + "/bin/fluent-bit.exe"

FLUENT_BIT_SERVICE_MACOS = MACOS_LAUNCHD_SERVICE_PATH + "/fluent-bit.plist"

FLUENT_BIT_CONFIG_DIR_LINUX = "/etc/fluent-bit"
FLUENT_BIT_CONFIG_DIR_MACOS = "/opt/fluent-bit/etc/fluent-bit"
FLUENT_BIT_PROGRAMDATA_DIR_WINDOWS = "C:/ProgramData/fluent-bit"
FLUENT_BIT_CONFIG_DIR_CONF_WINDOWS = FLUENT_BIT_DIR_WINDOWS + "/fluent-bit.conf"

FLUENT_BIT_SSL_DIR_LINUX = "/etc/fluent-bit/ssl"
FLUENT_BIT_SSL_DIR_MACOS = "/Library/Application Support/FluentBit/ssl"
FLUENT_BIT_SSL_DIR_WINDOWS = r"C:\ProgramData\fluent-bit\ssl"

# Zeek config paths
ZEEK_CONFIG_DIR_LINUX = "/etc/fluent-bit"
ZEEK_CONFIG_DIR_MACOS = "/Library/Application Support/ss-network-analyzer/config"
ZEEK_SERVICE_PATH_LINUX = "/etc/systemd/system/zeek.service"

# Zeek log paths
ZEEK_LOG_PATH_LINUX = "/opt/zeek/logs/current/*.log"
ZEEK_LOG_PATH_MACOS = "/usr/local/opt/zeek/logs/current/*.log"
ZEEK_LOG_PATH_WINDOWS = "C:/ProgramData/zeek/logs/*.log"

SS_NETWORK_ANALYZER_SERVICE_NAME = "ss-network-analyzer"

# Network analyzer config paths
SS_NETWORK_ANALYZER_CONFIG_DIR_LINUX = "/etc/ss-network-analyzer/config"
SS_NETWORK_ANALYZER_CONFIG_DIR_MACOS = "/Library/Application Support/ss-network-analyzer/config"
SS_NETWORK_ANALYZER_CONFIG_DIR_WINDOWS = "C:/ProgramData/ss-network-analyzer/config"

# Network analyzer log paths
SS_NETWORK_ANALYZER_LOG_PATH_LINUX = "/var/log/ss-network-analyzer/"
SS_NETWORK_ANALYZER_LOG_PATH_MACOS = "/usr/local/var/log/ss-network-analyzer/"
SS_NETWORK_ANALYZER_LOG_PATH_WINDOWS = r"C:\\ProgramData\\ss-network-analyzer\\logs\\"
SS_NETWORK_ANALYZER_LOG_FILES_MATCH = "*.log"
SS_NETWORK_ANALYZER_CONF_DEFAULT_FLUSH_INTERVAL = 1
# Network analyzer config file name
NETWORK_ANALYZER_CONFIG_FILENAME = "network-analyzer.conf"

# ss-agent config path
SS_AGENT_CONFIG_DIR_LINUX = "/etc/ss-agent/config"
SS_AGENT_CONFIG_DIR_WINDOWS = "C:/ProgramData/ss-agent/config"
SS_AGENT_CONFIG_DIR_MACOS = "/Library/Application Support/ss-agent/config"
SS_AGENT_SSL_DIR_LINUX = "/etc/ss-agent/ssl"
SS_AGENT_SSL_DIR_MACOS = "/Library/Application Support/ss-agent/ssl"
SS_AGENT_SSL_DIR_WINDOWS = "C:/ProgramData/ss-agent/ssl"

# ss-agent service
SS_AGENT_SERVICE_MACOS = '/Library/LaunchDaemons/com.ss-agent.plist'
SS_AGENT_SERVICE_LINUX = '/etc/systemd/system/ss-agent.service'
SS_AGENT_SERVICE_NAME = "ss-agent"
SS_AGENT_PRODUCT_NAME = "SS Agent"
SS_AGENT_SERVICE_BINARY_WINDOWS = "C:/Program Files/ss-agent/ss-agent.exe"

# ss-agent config file template
SS_AGENT_TEMPLATE = "ss-agent-template.json"

OSQUERY_PRODUCT_NAME = "osquery"
OSQUERY_SERVICE_NAME = "osqueryd"
OSQUERY_CONFIG_EXAMPLE_PATH_LINUX = '/opt/osquery/share/osquery/osquery.example.conf'
OSQUERY_CONFIG_EXAMPLE_PATH_MACOS = '/var/osquery/osquery.example.conf'
OSQUERY_CONFIG_EXAMPLE_PATH_WINDOWS = "C:/Program Files/osquery/osquery.example.conf"
OSQUERY_CONFIG_PATH_LINUX = "/etc/osquery/osquery.conf"
OSQUERY_CONFIG_PATH_MACOS = "/var/osquery/osquery.conf"
OSQUERY_CONFIG_PATH_WINDOWS = "C:/Program Files/osquery/osquery.conf"
OSQUERY_LOGGER_PATH_WINDOWS = "C:/ProgramData/osquery/logs"
OSQUERY_PIDFILE_PATH_WINDOWS = "C:/Program Files/osquery/osquery.pid"
OSQUERY_DATABASE_PATH_WINDOWS = "C:/Program Files/osquery/osquery.db"

# Repositories
FLUENT_BIT_REPO = "securityspectrum/fluent-bit"
SS_AGENT_REPO = "securityspectrum/ss-agent"
SS_NETWORK_ANALYZER_REPO = "securityspectrum/go-network-analyzer"

# Download directories
DOWNLOAD_DIR_LINUX = Path("/tmp")
DOWNLOAD_DIR_WINDOWS = Path(f"{Path.home()}\\Downloads")
DOWNLOAD_DIR_MACOS = Path("~/Downloads")


def get_osquery_directories():
    """
    Determines the appropriate download and extract directories for osquery
    based on the operating system.

    Returns:
        tuple: (download_dir, extract_dir)
    """
    system = platform.system().lower()
    home = Path.home()

    if system == "linux":
        download_dir = home / "Downloads" / "osquery"
        extract_dir = home / ".local" / "share" / "osquery"
    elif system == "darwin":
        download_dir = home / "Downloads" / "osquery"
        extract_dir = home / "Library" / "Application Support" / "osquery"
    elif system == "windows":
        download_dir = Path(os.getenv('USERPROFILE')) / "Downloads" / "osquery"
        extract_dir = Path(os.getenv('LOCALAPPDATA')) / "osquery"
    else:
        raise ValueError(f"Unsupported operating system: {system}")

    # Create directories if they don't exist
    download_dir.mkdir(parents=True, exist_ok=True)
    extract_dir.mkdir(parents=True, exist_ok=True)

    return download_dir, extract_dir


# osquery specific directories
OSQUERY_DOWNLOAD_DIR, OSQUERY_EXTRACT_DIR = get_osquery_directories()

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
