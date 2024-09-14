#!/bin/bash
set -x


# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Please run again with 'sudo' or as the root user."
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if Zeek is already installed
check_zeek_installed() {
    if command_exists zeek; then
        ZEEK_VERSION=$(zeek --version | head -n 1)
        echo "Zeek is already installed: $ZEEK_VERSION"
        exit 0
    fi
}

# Function to install required utilities
install_utilities() {
    if [[ "$ID" == "ubuntu" || "$ID_LIKE" =~ debian ]]; then
        apt update -y
        apt install -y apt-transport-https curl gnupg lsb-release
    elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" =~ rhel ]]; then
        yum install -y epel-release curl
    elif [[ "$ID" == "fedora" ]]; then
        dnf install -y curl redhat-lsb-core
    elif [[ "$ID" == "arch" ]]; then
        pacman -Sy --noconfirm curl lsb-release
    elif [[ "$ID" == "opensuse" || "$ID_LIKE" =~ suse ]]; then
        zypper install -y curl lsb-release
    else
        echo "Unsupported distribution for installing utilities."
        exit 1
    fi
}

# Function to install Zeek on Ubuntu or Debian
install_zeek_ubuntu_debian() {
    echo "Detected Ubuntu/Debian. Proceeding with installation..."

    # Install required utilities if not present
    install_utilities

    # Add Zeek GPG key
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_$(lsb_release -rs)/Release.key" | apt-key add -
    if [ $? -ne 0 ]; then
        echo "Failed to add Zeek GPG key."
        exit 1
    fi

    # Add Zeek repository
    echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_$(lsb_release -rs)/ /" > /etc/apt/sources.list.d/zeek.list

    # Update package list and install Zeek
    apt update -y
    apt install -y zeek zeekctl

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on Fedora
install_zeek_fedora() {
    echo "Detected Fedora. Proceeding with installation..."

    # Install required utilities if not present
    install_utilities

    # Update system
    dnf update -y

    # Try to install Zeek from default repositories
    if ! dnf install -y zeek zeekctl; then
        echo "Zeek package not found in default repositories. Adding Zeek OBS repository..."

        # Get Fedora version
        FEDORA_VERSION=$(rpm -E %fedora)

        # Import Zeek GPG key
        rpm --import https://download.opensuse.org/repositories/security:zeek/Fedora_${FEDORA_VERSION}/repodata/repomd.xml.key

        # Add Zeek repository
        cat << EOF > /etc/yum.repos.d/zeek.repo
[zeek]
name=Zeek repository for Fedora \$releasever
baseurl=https://download.opensuse.org/repositories/security:/zeek/Fedora_${FEDORA_VERSION}/
enabled=1
gpgcheck=1
gpgkey=https://download.opensuse.org/repositories/security:/zeek/Fedora_${FEDORA_VERSION}/repodata/repomd.xml.key
EOF

        # Clean metadata and update
        dnf clean all
        dnf update -y

        # Install Zeek
        dnf install -y zeek zeekctl
        if [ $? -ne 0 ]; then
            echo "Failed to install Zeek from OBS repository."
            exit 1
        fi
    fi

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on CentOS/RHEL
install_zeek_centos_rhel() {
    echo "Detected CentOS/RHEL. Proceeding with installation..."

    # Install required utilities if not present
    install_utilities

    # Import Zeek GPG key
    rpm --import https://download.opensuse.org/repositories/security:zeek/RHEL_8/repodata/repomd.xml.key

    # Add Zeek repository
    curl -fsSL -o /etc/yum.repos.d/zeek.repo https://download.opensuse.org/repositories/security:zeek/RHEL_8/security:zeek.repo

    # Update system and install Zeek
    yum update -y
    yum install -y zeek zeekctl

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on Arch Linux
install_zeek_arch() {
    echo "Detected Arch Linux. Proceeding with installation..."

    # Install required utilities if not present
    install_utilities

    # Update system
    pacman -Syu --noconfirm

    # Install Zeek from AUR
    if ! command_exists git; then
        pacman -S --noconfirm git
    fi

    if ! command_exists base-devel; then
        pacman -S --noconfirm base-devel
    fi

    git clone https://aur.archlinux.org/zeek.git
    cd zeek
    makepkg -si --noconfirm
    cd ..

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on openSUSE
install_zeek_opensuse() {
    echo "Detected openSUSE. Proceeding with installation..."

    # Install required utilities if not present
    install_utilities

    # Update system
    zypper refresh

    # Install Zeek
    zypper install -y zeek zeekctl

    # Configure Zeek
    configure_zeek
}

# Function to configure Zeek (common for all distributions)
configure_zeek() {
    echo "Configuring Zeek..."

    # Find zeek-config
    if command_exists zeek-config; then
        ZEEK_CONFIG_PATH=$(command -v zeek-config)
    else
        echo "zeek-config not found in PATH. Searching common directories..."
        # Limit the search to common directories
        ZEEK_CONFIG_PATH=$(find /usr /usr/local /opt -name zeek-config -type f 2>/dev/null | head -n 1)
        if [ -z "$ZEEK_CONFIG_PATH" ]; then
            echo "Unable to find zeek-config. Please ensure Zeek is installed correctly."
            exit 1
        fi
        # Add zeek-config directory to PATH
        export PATH=$(dirname "$ZEEK_CONFIG_PATH"):$PATH
    fi

    echo "Found zeek-config at: $ZEEK_CONFIG_PATH"

    # Get Zeek installation prefix
    ZEEK_PREFIX=$("$ZEEK_CONFIG_PATH" --prefix)
    if [ -z "$ZEEK_PREFIX" ]; then
        echo "Unable to determine Zeek installation prefix."
        exit 1
    fi
    echo "Zeek installation prefix: $ZEEK_PREFIX"

    # Set the network interface
    INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
    if [ -z "$INTERFACE" ]; then
        echo "Unable to detect network interface."
        exit 1
    fi
    echo "Using network interface: $INTERFACE"

    # Update node.cfg
    NODE_CFG="$ZEEK_PREFIX/etc/node.cfg"
    if [ -f "$NODE_CFG" ]; then
        sed -i "s/^interface=.*/interface=$INTERFACE/" "$NODE_CFG"
    else
        echo "node.cfg not found at $NODE_CFG"
        exit 1
    fi

    # Enable JSON logging
    LOCAL_ZEEK="$ZEEK_PREFIX/share/zeek/site/local.zeek"
    if [ -f "$LOCAL_ZEEK" ]; then
        echo 'redef LogAscii::use_json = T;' >> "$LOCAL_ZEEK"
    else
        echo "local.zeek not found at $LOCAL_ZEEK"
        exit 1
    fi

    # Find zeekctl
    if command_exists zeekctl; then
        ZEEKCTL_PATH=$(command -v zeekctl)
    else
        echo "zeekctl not found in PATH. Searching common directories..."
        ZEEKCTL_PATH=$(find /usr /usr/local /opt -name zeekctl -type f 2>/dev/null | head -n 1)
        if [ -z "$ZEEKCTL_PATH" ]; then
            echo "Unable to find zeekctl. Please ensure Zeek is installed correctly."
            exit 1
        fi
        # Add zeekctl directory to PATH
        export PATH=$(dirname "$ZEEKCTL_PATH"):$PATH
    fi
    echo "Found zeekctl at: $ZEEKCTL_PATH"

    # Deploy and start Zeek
    echo "Deploying Zeek..."
    "$ZEEKCTL_PATH" deploy

    if [ $? -ne 0 ]; then
        echo "zeekctl deploy command failed."
        exit 1
    fi

    # Check Zeek status
    echo "Checking Zeek status..."
    "$ZEEKCTL_PATH" status
}

# Function to detect the Linux distribution and install Zeek
detect_distro_and_install() {
    if [ -f /etc/os-release ]; then
        source /etc/os-release
    else
        echo "Cannot determine the operating system."
        exit 1
    fi

    # Install required utilities if not present
    if ! command_exists lsb_release || ! command_exists curl; then
        install_utilities
    fi

    if [[ "$ID" == "ubuntu" || "$ID_LIKE" =~ debian ]]; then
        install_zeek_ubuntu_debian
    elif [[ "$ID" == "fedora" ]]; then
        install_zeek_fedora
    elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" =~ rhel ]]; then
        install_zeek_centos_rhel
    elif [[ "$ID" == "arch" ]]; then
        install_zeek_arch
    elif [[ "$ID" == "opensuse" || "$ID_LIKE" =~ suse ]]; then
        install_zeek_opensuse
    else
        echo "Unsupported Linux distribution: $ID"
        exit 1
    fi
}

# Main function to run the installation
main() {
    echo "Checking if Zeek is already installed..."
    check_zeek_installed
    echo "Detecting Linux distribution..."
    detect_distro_and_install
}

# Execute the main function
main
