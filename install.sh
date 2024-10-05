#!/bin/bash
set -euxo pipefail

# Function to print error and exit
error_exit() {
    echo "ERROR: $1" >&2
    exit 1
}

# Install git, curl, and sudo if they are missing
install_prerequisites() {
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y git curl sudo
    elif command -v dnf &> /dev/null; then
        dnf install -y git curl sudo
    elif command -v yum &> /dev/null; then
        yum install -y git curl sudo
    elif command -v zypper &> /dev/null; then
        zypper lu &> /dev/null
        if [ $? -eq 4 ]; then
            echo "Repository metadata is out of date. Refreshing..."
            zypper refresh
        fi
        zypper install -y git curl sudo
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        if ! command -v brew &> /dev/null; then
            echo "Homebrew is not installed. Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            eval "$(/opt/homebrew/bin/brew shellenv)" || eval "$(/usr/local/bin/brew shellenv)"
        fi
        brew install git curl
    else
        error_exit "Unsupported Linux distribution or package manager. Please install git, curl, and sudo manually."
    fi
}

# Ensure that the basic tools are available
if ! command -v git &> /dev/null || ! command -v curl &> /dev/null || ! command -v sudo &> /dev/null; then
    echo "git, curl, or sudo are not installed. Installing missing dependencies..."
    install_prerequisites
else
    echo "All basic dependencies are already installed."
fi

# Clone the GitHub repository
REPO_URL="https://github.com/securityspectrum/ss-install-scripts.git"
REPO_DIR="ss-install-scripts"

if [ -d "$REPO_DIR" ]; then
    echo "Repository already cloned. Pulling the latest changes..."
    cd "$REPO_DIR"
    git pull
else
    echo "Cloning the repository..."
    git clone "$REPO_URL"
    cd "$REPO_DIR"
fi

# Navigate to the scripts directory
echo "Current working directory: $(pwd)"

# Check if requirements.txt exists
if [ ! -f requirements.txt ]; then
    error_exit "requirements.txt not found"
fi

# Check if install_agents.py exists
if [ ! -f install_agents.py ]; then
    error_exit "install_agents.py not found"
fi

# Function to install Python3 and necessary packages on Linux
install_python_on_linux() {
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y python3 python3-venv python3-pip perl-modules libterm-readline-gnu-perl iproute2
    elif command -v dnf &> /dev/null; then
        dnf install -y python3 python3-venv python3-pip perl-TermReadLine-Gnu iproute2
    elif command -v yum &> /dev/null; then
        yum install -y python3 python3-venv python3-pip perl-TermReadLine-Gnu iproute2
    elif command -v zypper &> /dev/null; then
        zypper lu &> /dev/null
        if [ $? -eq 4 ]; then
            echo "Repository metadata is out of date. Refreshing..."
            zypper refresh
        fi
        zypper install -y python3 python3-pip perl-TermReadLine-Gnu iproute2 || \
        zypper install -y python3 python-pip perl-TermReadLine iproute2
    else
        error_exit "Unsupported Linux distribution or package manager. Please install Python3 manually."
    fi
}

# Function to install Python3 and necessary packages on macOS
install_python_on_macos() {
    if ! command -v brew &> /dev/null; then
        echo "Homebrew is not installed. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        eval "$(/opt/homebrew/bin/brew shellenv)" || eval "$(/usr/local/bin/brew shellenv)"
    fi

    if ! brew list python@3 &> /dev/null && ! brew list python3 &> /dev/null; then
        echo "Python3 is not installed. Installing Python3 via Homebrew..."
        brew update
        brew install python3
    else
        echo "Python3 is already installed via Homebrew."
    fi

    brew link --overwrite python3 || true
}

# Detect OS type and install Python accordingly
case "$OSTYPE" in
    darwin*)
        echo "Detected macOS. Proceeding with macOS-specific installation."
        install_python_on_macos
        ;;
    linux*)
        echo "Detected Linux. Proceeding with Linux-specific installation."
        if ! command -v python3 &> /dev/null; then
            echo "Python3 is not installed. Installing Python3..."
            install_python_on_linux
        fi
        ;;
    *)
        error_exit "Unsupported operating system: $OSTYPE"
        ;;
esac

# Verify Python3 installation
if ! command -v python3 &> /dev/null; then
    error_exit "Python3 installation failed."
fi

# Print Python3 version for verification
python3 --version

# Check if venv module is available
if ! python3 -c "import venv" &> /dev/null; then
    echo "venv module is not available. Installing necessary packages..."
    case "$OSTYPE" in
        darwin*)
            brew install python3-venv || true
            ;;
        linux*)
            install_python_on_linux
            ;;
    esac
fi

# Ensure python3-venv and pip are installed
if ! python3 -m venv --help &> /dev/null; then
    echo "Python3-venv is not installed. Installing required packages..."
    case "$OSTYPE" in
        darwin*)
            brew install python3-venv || true
            ;;
        linux*)
            install_python_on_linux
            ;;
    esac
fi

# Re-verify venv module
if ! python3 -c "import venv" &> /dev/null; then
    error_exit "venv module is still not available after installation."
fi

# List Python3 binaries for debugging purposes
echo "Listing Python3 binaries in /usr/bin and /usr/local/bin:"
ls -l /usr/bin/python3* /usr/local/bin/python3* 2>/dev/null || true

# Create virtual environment
echo "Creating virtual environment..."
if python3 -m venv venv; then
    echo "Virtual environment created successfully."
else
    error_exit "Failed to create virtual environment."
fi

# Check if virtual environment was created
if [ ! -f venv/bin/python3 ] && [ ! -f venv/Scripts/python.exe ]; then
    error_exit "Virtual environment creation did not include python3."
fi

# Activate virtual environment
echo "Activating virtual environment..."
# shellcheck disable=SC1091
source venv/bin/activate || source venv/Scripts/activate

# Verify activation
if [ -z "$VIRTUAL_ENV" ]; then
    echo "Failed to activate virtual environment."
    exit 1
fi

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip
if [ $? -ne 0 ]; then
    echo "Failed to upgrade pip."
    exit 1
fi

# Install requirements
if [ -f "requirements.txt" ]; then
    echo "Installing Python dependencies..."
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "Failed to install dependencies."
        exit 1
    fi
else
    echo "requirements.txt not found."
fi

# Run the Python script
if [ -f "install_agents.py" ]; then
    echo "Running install_agents.py..."
    python install_agents.py --log-level INFO
    if [ $? -ne 0 ]; then
        echo "Failed to run install_agents.py."
        exit 1
    fi
else
    echo "install_agents.py not found."
    exit 1
fi