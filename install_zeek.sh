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

# Function to check if Zeek is already installed
is_zeek_installed() {
    if command -v zeek &> /dev/null || command -v zeek-config &> /dev/null; then
        echo "Zeek is already installed."
        return 0
    else
        return 1
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
        install_zeek_from_source
        return
    fi

    # Add Zeek repository
    echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] http://download.opensuse.org/repositories/security:/zeek/xUbuntu_${DISTRO_VERSION}/ /" | tee /etc/apt/sources.list.d/zeek.list

    # Update package list and install Zeek
    apt update -y
    apt install -y zeek zeekctl || {
        echo "Package installation failed, attempting to install from source..."
        install_zeek_from_source
    }

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
        echo "Failed to add Zeek GPG key, attempting to install from source..."
        install_zeek_from_source
        return
    fi

    # Add Zeek repository for Debian
    echo "deb [signed-by=/usr/share/keyrings/zeek-archive-keyring.gpg] http://download.opensuse.org/repositories/security:/zeek/Debian_${DISTRO_VERSION}/ /" | tee /etc/apt/sources.list.d/zeek.list

    # Update package list and install Zeek
    apt update -y
    apt install -y zeek zeekctl || {
        echo "Package installation failed, attempting to install from source..."
        install_zeek_from_source
    }
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
        dnf install -y zeek zeekctl || {
            echo "Package installation failed, attempting to install from source..."
            install_zeek_from_source
        }
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
    yum install -y zeek zeekctl || {
        echo "Package installation failed, attempting to install from source..."
        install_zeek_from_source
    }

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


# Function to install Zeek on openSUSE
install_zeek_opensuse() {
    # Check if Zeek is already installed
    if command -v zeek >/dev/null 2>&1; then
        echo "Zeek is already installed."
        zeek --version
        return 0
    fi

    # Update system repositories
    echo "Updating system repositories..."
    zypper --non-interactive --gpg-auto-import-keys refresh

    # Ensure essential utilities are installed
    echo "Ensuring essential utilities are installed..."
    zypper --non-interactive install -y wget tar gzip

    # Attempt to install Zeek via zypper
    echo "Attempting to install Zeek via zypper..."

    # Try installing Zeek via the default repository first
    if zypper --non-interactive install -y zeek; then
        echo "Zeek installed successfully via zypper."
        zeek --version
        configure_zeek
        return 0
    else
        echo "Zeek not found in default repositories."
        echo "Adding the Zeek and Python repositories."

        # Detect openSUSE version
        . /etc/os-release
        REPO_ALIAS="security_zeek"
        PYTHON_REPO_ALIAS="devel_languages_python"

        # Handle openSUSE Tumbleweed
        if [[ $NAME == "openSUSE Tumbleweed" ]]; then
            REPO_URL="https://download.opensuse.org/repositories/security:zeek/openSUSE_Tumbleweed/"
            PYTHON_REPO_URL="https://download.opensuse.org/repositories/devel:/languages:/python/openSUSE_Tumbleweed/"
            echo "Detected openSUSE Tumbleweed. Adding the appropriate repositories."

        # Handle openSUSE Leap 15.6
        elif [[ $NAME == "openSUSE Leap" && $VERSION_ID == "15.6" ]]; then
            REPO_URL="https://download.opensuse.org/repositories/security:zeek/15.6/"
            PYTHON_REPO_URL="https://download.opensuse.org/repositories/devel:/languages:/python/15.6/"
            echo "Detected openSUSE Leap 15.6. Adding the appropriate repositories."

        # Handle openSUSE Leap 15.5
        elif [[ $NAME == "openSUSE Leap" && $VERSION_ID == "15.5" ]]; then
            REPO_URL="https://download.opensuse.org/repositories/security:zeek/15.5/"
            PYTHON_REPO_URL="https://download.opensuse.org/repositories/devel:/languages:/python/15.5/"
            echo "Detected openSUSE Leap 15.5. Adding the appropriate repositories."

        else
            echo "Unsupported openSUSE version or distribution."
            return 1
        fi

        # Add Zeek repository
        zypper --non-interactive addrepo --check --refresh --name "Zeek Security Repository" $REPO_URL $REPO_ALIAS

        # Add the Python repository to resolve dependencies
        zypper --non-interactive addrepo --check --refresh --name "devel:languages:python" $PYTHON_REPO_URL $PYTHON_REPO_ALIAS

        # Refresh repositories and auto-import GPG keys
        zypper --non-interactive --gpg-auto-import-keys refresh

        # Attempt to install python3-gitpython
        echo "Attempting to install required Python packages..."
        if ! zypper --non-interactive install -y python3-gitpython; then
            echo "python3-gitpython not available, proceeding to install zkg via pip3."
            SKIP_ZKG=true
        else
            echo "python3-gitpython installed successfully."
            SKIP_ZKG=false
        fi

        # Attempt to install Zeek
        echo "Attempting to install Zeek..."
        if $SKIP_ZKG; then
            echo "Installing zeek-core to avoid zkg dependency..."
            if zypper --non-interactive install --no-recommends -y zeek-core zeekctl zeek-devel zeek-client zeek-spicy-devel zeek-btest; then
                echo "Zeek core installed successfully."
                zeek --version

                # Install pip3 if not already installed
                if ! command -v pip3 >/dev/null 2>&1; then
                    echo "pip3 not found. Installing pip3..."
                    zypper --non-interactive install -y python3-pip python3
                fi

                # Install GitPython and semantic-version via pip3
                echo "Installing GitPython and semantic-version via pip3..."
                pip3 install GitPython semantic-version

                # Install zkg via pip3
                echo "Installing zkg via pip3..."
                pip3 install zkg

                # Set environment variable to suppress GitPython warnings
                export GIT_PYTHON_REFRESH=quiet

                # Verifying zkg installation
                echo "Verifying zkg installation..."
                if zkg --version >/dev/null 2>&1; then
                    echo "zkg installed successfully."
                    zkg --version
                else
                    output=$(zkg --version 2>&1)
                    echo "Failed to install zkg: $output"
                    echo "zkg installation failed."
                    exit 1
                fi

                # Configure Zeek
                configure_zeek
                return 0
            else
                echo "Failed to install Zeek core from the repositories."
                echo "Proceeding to build Zeek from source."
            fi
        else
            if zypper --non-interactive install --no-recommends -y zeek; then
                echo "Zeek installed successfully."
                zeek --version
                configure_zeek
                return 0
            else
                echo "Failed to install Zeek from the repositories."
                echo "Proceeding to build Zeek from source."
            fi
        fi
    fi

    # Install build dependencies
    echo "Installing build dependencies..."
    zypper --non-interactive install -y make cmake flex bison libpcap-devel libopenssl-devel python3 python3-devel swig zlib-devel wget tar gzip

    # Verify Python sqlite3 module
    echo "Verifying Python sqlite3 module..."
    if ! python3 -c "import sqlite3" >/dev/null 2>&1; then
        echo "Installing sqlite3 module for Python 3..."
        zypper --non-interactive install -y python3-sqlite3
    fi

    # Install GCC 10
    echo "Adding the devel:gcc repository to install GCC 10..."
    zypper --non-interactive addrepo --check --refresh --name "devel:gcc" "https://download.opensuse.org/repositories/devel:/gcc/openSUSE_Leap_$VERSION_ID/" devel_gcc
    zypper --non-interactive --gpg-auto-import-keys refresh
    echo "Installing GCC 10..."
    zypper --non-interactive install -y gcc10 gcc10-c++

    # Update alternatives to use GCC 10
    echo "Updating gcc and g++ to point to GCC 10..."
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 70
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 100
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-7 70
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-10 100

    # Verify GCC version
    echo "Verifying GCC version..."
    gcc --version

    # Create a directory for the source code
    mkdir -p ~/src
    cd ~/src || exit 1

    # Set the LTS version of Zeek
    ZEEK_VERSION="7.0.1"  # Current LTS version

    # Download the Zeek source code if not already downloaded
    if [ ! -f "zeek-$ZEEK_VERSION.tar.gz" ]; then
        echo "Downloading Zeek source code version $ZEEK_VERSION..."
        wget https://download.zeek.org/zeek-$ZEEK_VERSION.tar.gz
        if [ $? -ne 0 ]; then
            echo "Error downloading Zeek source code. Please check your internet connection."
            return 1
        fi
    else
        echo "Zeek source code version $ZEEK_VERSION already downloaded."
    fi

    # Extract the source code if not already extracted
    if [ ! -d "zeek-$ZEEK_VERSION" ]; then
        echo "Extracting Zeek source code..."
        tar -xzf zeek-$ZEEK_VERSION.tar.gz
        if [ $? -ne 0 ]; then
            echo "Error extracting Zeek source code."
            return 1
        fi
    else
        echo "Zeek source code already extracted."
    fi

    # Build and install Zeek from source
    echo "Building Zeek from source..."
    cd zeek-$ZEEK_VERSION || { echo "Directory zeek-$ZEEK_VERSION does not exist."; return 1; }
    mkdir -p build
    cd build
    cmake ..
    if [ $? -ne 0 ]; then
        echo "CMake configuration failed."
        return 1
    fi
    make -j$(nproc)
    if [ $? -ne 0 ]; then
        echo "Compilation failed."
        return 1
    fi

    echo "Installing Zeek..."
    make install
    if [ $? -ne 0 ]; then
        echo "Installation failed."
        return 1
    fi

    # Determine the home directory
    HOME_DIR=$(getent passwd "$USER" | cut -d: -f6)

    # Add Zeek to the system PATH if not already added
    BASHRC="$HOME_DIR/.bashrc"
    if [ ! -f "$BASHRC" ]; then
        touch "$BASHRC"
    fi
    if ! grep -q '/usr/local/zeek/bin' "$BASHRC"; then
        echo "Adding Zeek to the system PATH..."
        echo 'export PATH=/usr/local/zeek/bin:$PATH' >> "$BASHRC"
        source "$BASHRC"
    fi

    # Verify the Zeek installation
    echo "Verifying Zeek installation..."
    if zeek --version >/dev/null 2>&1; then
        echo "Zeek installed successfully."
        zeek --version
        configure_zeek
    else
        echo "Zeek installation failed."
        return 1
    fi
}



# Function to clean the build directory if necessary
clean_build_directory() {
    echo "Cleaning build directory..."
    if [ -d "build" ]; then
        make distclean || rm -rf build
    fi
}


install_build_dependencies() {
    echo "Installing build dependencies..."
    echo "Detected OS: $ID $VERSION_ID $VERSION"
      # Install required dependencies for building Zeek from source
    if [[ "$ID" == "ubuntu" || "$ID" == "debian" || "$ID_LIKE" =~ "debian" ]]; then
        apt update -y
        apt install -y curl wget lsb-release gnupg build-essential cmake gcc g++ flex bison libpcap-dev libssl-dev python3-dev zlib1g-dev libcaf-dev swig binutils-gold libkrb5-dev nodejs
    elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" =~ "rhel" ]]; then
        yum groupinstall -y "Development Tools"
        yum install -y curl wget cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python3-devel zlib-devel
    elif [[ "$ID" == "fedora" ]]; then
        dnf install -y curl wget cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel python3 python3-devel swig nodejs nodejs-devel zlib-devel
    elif [[ "$ID" == "opensuse" || "$ID_LIKE" =~ "suse" ]]; then
        zypper install -y curl wget cmake make gcc gcc-c++ flex bison libpcap-devel libopenssl-devel python3-devel zlib-devel
    else
        echo "Unsupported distribution for source installation."
        exit 1
    fi
}

# Function to install Zeek from source
install_zeek_from_source() {
    echo "Installing Zeek from source..."

    # Check if Zeek is already installed
    if is_zeek_installed; then
        echo "Skipping source installation as Zeek is already installed."
        return
    fi

    # Set Zeek version
    ZEEK_VERSION="7.0.1"

    # Create non-root user if not exists
    if ! id "builder" &>/dev/null; then
        useradd -m builder
    fi


    # Install build dependencies
    install_build_dependencies

    # Ensure builder's home directory ownership
    chown -R builder:builder /home/builder

    # Create build script for the builder user
    BUILD_SCRIPT="/home/builder/build_zeek.sh"

    cat << 'EOF' > $BUILD_SCRIPT
#!/bin/bash
set -e
cd ~

# Clean previous builds
rm -rf zeek-*

# Download Zeek source code
echo "Downloading Zeek source code..."
DOWNLOAD_URL="https://github.com/zeek/zeek/releases/download/v${ZEEK_VERSION}/zeek-${ZEEK_VERSION}.tar.gz"
curl -L -o zeek-${ZEEK_VERSION}.tar.gz "$DOWNLOAD_URL"

# Verify download
if [ ! -f zeek-${ZEEK_VERSION}.tar.gz ]; then
    echo "Failed to download Zeek source code."
    exit 1
fi

FILE_SIZE=$(stat -c%s "zeek-${ZEEK_VERSION}.tar.gz")
if [ $FILE_SIZE -lt 100000 ]; then
    echo "Downloaded file is too small, indicating a failed download."
    echo "File contents:"
    cat zeek-${ZEEK_VERSION}.tar.gz
    exit 1
fi

# Extract and build
tar -xzf zeek-${ZEEK_VERSION}.tar.gz
cd zeek-${ZEEK_VERSION}
./configure
make -j$(nproc)
EOF

    # Set ownership and permissions
    chown builder:builder $BUILD_SCRIPT
    chmod +x $BUILD_SCRIPT

    # Export variables for the builder user
    su - builder -c "export ZEEK_VERSION=$ZEEK_VERSION && bash $BUILD_SCRIPT"

    # Install Zeek as root
    cd /home/builder/zeek-${ZEEK_VERSION}
    make install

    # Clean up
    rm -f $BUILD_SCRIPT
    cd -

    echo "Zeek installed successfully from source."

    # Configure Zeek
    configure_zeek
}

# Function to check if a command exists
command_exists() {
    command -v "$1" &> /dev/null
}

# Function to find zeek-config and update PATH if necessary
find_zeek_config() {
    # Check if zeek-config is already in the PATH
    if command_exists zeek-config; then
        ZEEK_CONFIG_PATH=$(command -v zeek-config)
        echo "zeek-config found in PATH at: $ZEEK_CONFIG_PATH"
    else
        echo "zeek-config not found in PATH. Searching common directories..."
        # Limit the search to common directories
        ZEEK_CONFIG_PATH=$(find /usr /usr/local /opt -name zeek-config -type f 2>/dev/null | head -n 1)
        if [ -z "$ZEEK_CONFIG_PATH" ]; then
            echo "Unable to find zeek-config. Please ensure Zeek is installed correctly."
            exit 1
        fi
        # Add zeek-config directory to PATH
        ZEEK_CONFIG_DIR=$(dirname "$ZEEK_CONFIG_PATH")
        export PATH="$ZEEK_CONFIG_DIR:$PATH"
        echo "zeek-config found at $ZEEK_CONFIG_PATH and added to PATH."
    fi
}

# Function to update the interface in node.cfg for macOS
update_node_cfg_macos() {
    # Detect macOS and use netstat to get the default network interface
    if [ "$(uname)" == "Darwin" ]; then
        # Extract the interface used by the default route
        INTERFACE=$(route get default 2>/dev/null | awk '/interface:/{print $2}')

        if [ -z "$INTERFACE" ]; then
            echo "Unable to detect network interface from default route."
            exit 1
        fi

        echo "Using network interface: $INTERFACE"

        # Path to node.cfg
        NODE_CFG="/usr/local/etc/node.cfg"

        # Ensure the file exists
        if [ ! -f "$NODE_CFG" ]; then
            echo "Error: node.cfg not found at $NODE_CFG"
            exit 1
        fi

        # Update the node.cfg file with the correct interface
        echo "Updating node.cfg with interface $INTERFACE..."
        sudo sed -i '' "s/^interface=.*/interface=$INTERFACE/" "$NODE_CFG"
        if [ $? -ne 0 ]; then
            echo "Failed to update node.cfg with the correct interface."
            exit 1
        fi
    fi
}

# Function to configure Zeek (common for all distributions)
configure_zeek() {
    echo "Configuring Zeek..."

    # Ensure the script is running as root
    if [ "$(id -u)" -ne 0 ]; then
        echo "Error: This script must be run as root."
        exit 1
    fi

    # Use the existing function to find zeek-config
    find_zeek_config

    echo "Found zeek-config at: $ZEEK_CONFIG_PATH"

    # Get Zeek installation prefix
    ZEEK_PREFIX=$("$ZEEK_CONFIG_PATH" --prefix)
    if [ -z "$ZEEK_PREFIX" ]; then
        echo "Unable to determine Zeek installation prefix."
        exit 1
    fi
    echo "Zeek installation prefix: $ZEEK_PREFIX"

    # Detect and update the network interface for macOS
    if [ "$(uname)" == "Darwin" ]; then
        update_node_cfg_macos
    else
        # For Linux systems, use the ip command to detect the interface
        INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)

        if [ -z "$INTERFACE" ]; then
            echo "Unable to detect network interface."
            exit 1
        fi
        echo "Using network interface: $INTERFACE"

        # Path to node.cfg
        NODE_CFG="$ZEEK_PREFIX/etc/node.cfg"

        # Ensure the /opt/zeek/etc directory exists
        if [ ! -d "$ZEEK_PREFIX/etc" ]; then
            echo "$ZEEK_PREFIX/etc directory not found. Creating it..."
            mkdir -p "$ZEEK_PREFIX/etc"
        fi

        # Check if node.cfg exists
        if [ ! -f "$NODE_CFG" ]; then
            echo "node.cfg not found at $NODE_CFG. Creating node.cfg..."
            tee "$NODE_CFG" > /dev/null <<EOL
[zeek]
type=standalone
host=localhost
interface=$INTERFACE
EOL
        else
            echo "node.cfg found at $NODE_CFG. Updating interface..."
            sed -i "s/^interface=.*/interface=$INTERFACE/" "$NODE_CFG"
        fi
    fi

    # Enable JSON logging
    LOCAL_ZEEK="$ZEEK_PREFIX/share/zeek/site/local.zeek"
    if [ -f "$LOCAL_ZEEK" ]; then
        echo 'redef LogAscii::use_json = T;' >> "$LOCAL_ZEEK"
    else
        echo "local.zeek not found at $LOCAL_ZEEK"
        exit 1
    fi

    # Create missing log, spool, and other directories
    echo "Creating required directories..."
    mkdir -p "$ZEEK_PREFIX/logs"
    mkdir -p "$ZEEK_PREFIX/spool"
    mkdir -p "$ZEEK_PREFIX/spool/zeek"

    # Ensure the directories have proper permissions
    chown -R $(whoami) "$ZEEK_PREFIX/logs"
    chown -R $(whoami) "$ZEEK_PREFIX/spool"

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

    # Check if deploy was successful
    if [ $? -ne 0 ]; then
        echo "zeekctl deploy command failed."
        exit 1
    fi

    # Check Zeek status
    echo "Checking Zeek status..."
    "$ZEEKCTL_PATH" status
}


# Function to install required utilities for macOS
install_utilities_macos() {
    if ! command_exists brew; then
        echo "Homebrew not found. Installing Homebrew..."
        sudo -u "$SUDO_USER" /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        if [ $? -ne 0 ]; then
            echo "Failed to install Homebrew."
            exit 1
        fi
    fi

    echo "Installing required utilities using Homebrew (without sudo)..."
    sudo -u "$SUDO_USER" brew install cmake make gcc flex bison libpcap openssl python3 swig
    if [ $? -ne 0 ]; then
        echo "Failed to install required utilities."
        exit 1
    fi
}

# Function to install Zeek on macOS
install_zeek_macos() {
    echo "Detected macOS. Proceeding with installation..."

    # Install required utilities if not present (without sudo)
    install_utilities_macos

    # Check if Zeek is available via Homebrew
    if sudo -u "$SUDO_USER" brew info zeek >/dev/null 2>&1; then
        echo "Installing Zeek using Homebrew..."
        sudo -u "$SUDO_USER" brew install zeek
        if [ $? -ne 0 ]; then
            echo "Failed to install Zeek via Homebrew. Attempting to install from source."
            install_zeek_from_source
        else
            echo "Zeek installed successfully."
            zeek --version
            configure_zeek
        fi
    else
        echo "Zeek is not available via Homebrew. Proceeding to install from source."
        install_zeek_from_source
    fi
}

# Function to detect the Linux distribution and install Zeek
detect_distro_and_install() {
    if [ "$(uname)" == "Darwin" ]; then
        install_zeek_macos
    elif [ -f /etc/os-release ]; then
        source /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            install_zeek_ubuntu
        elif [[ "$ID" == "debian" || "$ID_LIKE" =~ "debian" ]]; then
            install_zeek_debian
        elif [[ "$ID" == "fedora" ]]; then
            install_zeek_fedora
        elif [[ "$ID" == "centos" || "$ID" == "rhel" || "$ID_LIKE" =~ "rhel" ]]; then
            install_zeek_centos_rhel
        elif [[ "$ID" == "opensuse" || "$ID_LIKE" =~ "suse" ]]; then
            install_zeek_opensuse
        else
            echo "Unsupported Linux distribution: $ID"
            exit 1
        fi
    else
        echo "Cannot determine the operating system."
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
