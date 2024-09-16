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
    if [[ "$ID" == "ubuntu" || "$ID" == "debian" || "$ID_LIKE" =~ "debian" ]]; then
        apt update -y
        apt install -y apt-transport-https curl gnupg lsb-release
    elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" =~ "rhel" ]]; then
        yum install -y epel-release curl
    elif [[ "$ID" == "fedora" ]]; then
        dnf install -y curl redhat-lsb-core
    elif [[ "$ID" == "arch" ]]; then
        pacman -Sy --noconfirm curl lsb-release
    elif [[ "$ID" == "opensuse" || "$ID_LIKE" =~ "suse" ]]; then
        zypper install -y curl lsb-release
    else
        echo "Unsupported distribution for installing utilities."
        exit 1
    fi
}

# Function to install Zeek on Ubuntu
install_zeek_ubuntu() {
    echo "Detected Ubuntu. Proceeding with installation..."

    # Install required utilities if not present
    install_utilities

    DISTRO_VERSION=$(lsb_release -rs)

    echo "Configuring repository for Ubuntu..."

    # Add Zeek GPG key
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${DISTRO_VERSION}/Release.key" | gpg --dearmor | tee /usr/share/keyrings/zeek-archive-keyring.gpg > /dev/null
    if [ $? -ne 0 ]; then
        echo "Failed to add Zeek GPG key."
        exit 1
    fi

    # Add Zeek repository
    echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${DISTRO_VERSION}/ /" | tee /etc/apt/sources.list.d/zeek.list

    # Update package list and install Zeek
    apt update -y
    apt install -y zeek zeekctl

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on Debian
install_zeek_debian() {
    echo "Detected Debian. Proceeding with installation..."

    # Install required utilities if not present
    install_utilities

    DISTRO_VERSION=$(lsb_release -rs)

    echo "Configuring repository for Debian..."

    # Add Zeek GPG key for Debian
    curl -fsSL "https://download.opensuse.org/repositories/security:zeek/Debian_${DISTRO_VERSION}/Release.key" | gpg --dearmor | tee /usr/share/keyrings/zeek-archive-keyring.gpg > /dev/null
    if [ $? -ne 0 ]; then
        install_zeek_from_source
    fi

    # Add Zeek repository for Debian
    echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] http://download.opensuse.org/repositories/security:/zeek/Debian_${DISTRO_VERSION}/ /" | tee /etc/apt/sources.list.d/zeek.list

    # Update package list and install Zeek
    apt update -y
    apt install -y zeek zeekctl || install_zeek_from_source

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

# Function to install Zeek on RHEL 7
install_zeek_rhel7() {
    echo "Detected RHEL 7. Proceeding with installation..."

    # Install required utilities
    install_utilities

    # Import Zeek GPG key for RHEL 7
    rpm --import https://download.opensuse.org/repositories/security:zeek/RHEL_7/repodata/repomd.xml.key

    # Add Zeek repository for RHEL 7
    curl -fsSL -o /etc/yum.repos.d/zeek.repo https://download.opensuse.org/repositories/security:zeek/RHEL_7/security:zeek.repo

    # Update system and install Zeek
    yum update -y
    yum install -y zeek zeekctl

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on RHEL 8 (Stream or Vault)
install_zeek_rhel8() {
    echo "Detected RHEL 8. Proceeding with installation..."

    # Install required utilities
    install_utilities

    # Import Zeek GPG key for RHEL 8
    rpm --import https://download.opensuse.org/repositories/security:zeek/RHEL_8/repodata/repomd.xml.key

    # Add Zeek repository for RHEL 8
    curl -fsSL -o /etc/yum.repos.d/zeek.repo https://download.opensuse.org/repositories/security:zeek/RHEL_8/security:zeek.repo

    # Update system and install Zeek
    yum update -y
    yum install -y zeek zeekctl

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on CentOS/RHEL (detecting versions)
install_zeek_centos_rhel() {
    echo "Detected CentOS/RHEL. Proceeding with installation..."

    # Determine if it's RHEL or CentOS and the version
    OS_VERSION=$(rpm -E %rhel)

    if [[ "$OS_VERSION" == "7" ]]; then
        install_zeek_rhel7
    elif [[ "$OS_VERSION" == "8" ]]; then
        install_zeek_rhel8
    else
        echo "Unsupported CentOS/RHEL version: $OS_VERSION"
        exit 1
    fi
}

# Function to install Zeek on CentOS 7
install_zeek_centos7() {
    echo "Detected CentOS 7. Proceeding with installation..."

    # Install required utilities
    install_utilities

    # Import Zeek GPG key
    rpm --import https://download.opensuse.org/repositories/security:zeek/CentOS_7/repodata/repomd.xml.key

    # Add Zeek repository
    curl -fsSL -o /etc/yum.repos.d/zeek.repo https://download.opensuse.org/repositories/security:zeek/CentOS_7/security:zeek.repo

    # Update system and install Zeek
    yum update -y
    yum install -y zeek zeekctl

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on CentOS 8 (Stream or Vault)
install_zeek_centos8() {
    echo "Detected CentOS 8. Proceeding with installation..."

    # Install required utilities
    install_utilities

    # Check if the system is CentOS 8 Stream or CentOS 8
    if [[ "$CENTOS_VERSION" == "Stream" ]]; then
        echo "Installing Zeek on CentOS 8 Stream..."

        # Import Zeek GPG key for CentOS 8 Stream
        rpm --import https://download.opensuse.org/repositories/security:zeek/CentOS_8_Stream/repodata/repomd.xml.key

        # Add Zeek repository for CentOS 8 Stream
        curl -fsSL -o /etc/yum.repos.d/zeek.repo https://download.opensuse.org/repositories/security:zeek/CentOS_8_Stream/security:zeek.repo

    else
        echo "Installing Zeek on CentOS 8 (using Vault repository)..."

        # Update the repository to use CentOS Vault since CentOS 8 has reached EOL
        sed -i 's|mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-*.repo
        sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo

        # Import Zeek GPG key for CentOS 8
        rpm --import https://download.opensuse.org/repositories/security:zeek/CentOS_8/repodata/repomd.xml.key

        # Add Zeek repository for CentOS 8
        curl -fsSL -o /etc/yum.repos.d/zeek.repo https://download.opensuse.org/repositories/security:zeek/CentOS_8/security:zeek.repo
    fi

    # Update system and install Zeek
    yum update -y
    yum install -y zeek zeekctl

    # Configure Zeek
    configure_zeek
}

# Function to install Zeek on Arch Linux
install_zeek_arch() {
    echo "Detected Arch Linux. Proceeding with installation from source..."

    # Install required dependencies for building Zeek
    pacman -Syu --noconfirm base-devel git cmake make gcc flex bison libpcap openssl python3 swig zlib geoip libmaxminddb gperftools

    # Create a non-root user for building
    useradd -m builder
    su - builder -c "
        cd /home/builder &&
        git clone --depth=1 https://github.com/zeek/zeek.git &&
        cd zeek &&
        mkdir build &&
        cd build &&
        cmake .. -DCMAKE_PREFIX_PATH=/usr/lib/libpcap.so &&
        make -j$(nproc) &&
        sudo make install
    "

    # Configure Zeek after installation
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

# Function to install Zeek from source
install_zeek_from_source() {
    echo "Installing Zeek from source..."

    # Install required dependencies for building Zeek from source
    if [[ "$ID" == "ubuntu" || "$ID" == "debian" || "$ID_LIKE" =~ "debian" ]]; then
        apt update -y
        apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev zlib1g-dev libcaf-opencl-dev libcaf-dev
    elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" =~ "rhel" ]]; then
        yum groupinstall -y "Development Tools"
        yum install -y cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python3-devel zlib-devel
    elif [[ "$ID" == "fedora" ]]; then
        dnf install -y cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python3-devel zlib-devel
    elif [[ "$ID" == "arch" ]]; then
        pacman -Sy --noconfirm base-devel cmake flex bison libpcap openssl python3 zlib
    elif [[ "$ID" == "opensuse" || "$ID_LIKE" =~ "suse" ]]; then
        zypper install -y cmake make gcc gcc-c++ flex bison libpcap-devel libopenssl-devel python3-devel zlib-devel
    else
        echo "Unsupported distribution for source installation."
        exit 1
    fi

    # Download Zeek source code
    ZEEK_VERSION="5.1.2"
    wget https://download.zeek.org/zeek-${ZEEK_VERSION}.tar.gz
    tar -xzf zeek-${ZEEK_VERSION}.tar.gz
    cd zeek-${ZEEK_VERSION}

    # Build and install Zeek
    ./configure
    make -j$(nproc)
    make install

    if [ $? -ne 0 ]; then
        echo "Failed to compile and install Zeek from source."
        exit 1
    fi

    # Go back to the original directory
    cd ..
    echo "Zeek installed successfully from source."

    # Configure Zeek after installation
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

    if [[ "$ID" == "ubuntu" ]]; then
        install_zeek_ubuntu
    elif [[ "$ID" == "debian" || "$ID_LIKE" =~ "debian" ]]; then
        install_zeek_debian
    elif [[ "$ID" == "fedora" ]]; then
        install_zeek_fedora
    elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" =~ "rhel" ]]; then
        install_zeek_centos_rhel
    elif [[ "$ID" == "arch" ]]; then
        install_zeek_arch
    elif [[ "$ID" == "opensuse" || "$ID_LIKE" =~ "suse" ]]; then
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
