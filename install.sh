#!/bin/bash
set -euxo pipefail

# Function to print error and exit
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Function for logging with timestamps
log() {
    local type="$1"
    shift
    local message="$@"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$type] $message"
}

# Function to display usage
usage() {
    echo "Usage: $0 [--install | --uninstall | --help]"
    echo
    echo "Options:"
    echo "  --install       Install the agents."
    echo "  --uninstall     Uninstall the agents."
    echo "  --help, -h      Display this help message."
    exit 1
}

# Function to compare versions using sort -V (more portable)
version_ge() {
    # Returns 0 (true) if $1 >= $2, else 1
    # Example: version_ge "3.10" "3.8"
    if [[ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]; then
        return 0
    else
        return 1
    fi
}

# Define preferred Python versions
PREFERRED_PYTHON_VERSIONS=("3.12" "3.11" "3.10" "3.9" "3.8")

# Default action is to install
ACTION="install"

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --install)
            ACTION="install"
            shift
            ;;
        --uninstall)
            ACTION="uninstall"
            shift
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Load environment variables from .env file if it exists
if [ -f ".env" ]; then
    log "INFO" "Loading environment variables from .env file."
    set -o allexport
    source .env
    set +o allexport
fi

# Install git, curl, and sudo if they are missing
install_prerequisites() {
    if command -v apt-get &> /dev/null; then
        log "INFO" "Using apt-get to install prerequisites."
        sudo apt-get update
        sudo apt-get install -y git curl sudo
    elif command -v dnf &> /dev/null; then
        log "INFO" "Using dnf to install prerequisites."
        sudo dnf install -y git curl sudo
    elif command -v yum &> /dev/null; then
        log "INFO" "Using yum to install prerequisites."
        sudo yum install -y git curl sudo
    elif command -v zypper &> /dev/null; then
        log "INFO" "Using zypper to install prerequisites."
        sudo zypper lu &> /dev/null
        if [ $? -eq 4 ]; then
            log "INFO" "Repository metadata is out of date. Refreshing..."
            sudo zypper refresh
        fi
        sudo zypper install -y git curl sudo
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        log "INFO" "Using Homebrew to install prerequisites."
        if ! command -v brew &> /dev/null; then
            log "INFO" "Homebrew is not installed. Installing Homebrew..."
            /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
            # Add Homebrew to PATH
            eval "$(/opt/homebrew/bin/brew shellenv)" || eval "$(/usr/local/bin/brew shellenv)"
        fi
        brew install git curl
    else
        error_exit "Unsupported Linux distribution or package manager. Please install git, curl, and sudo manually."
    fi
}

# Ensure that the basic tools are available
MISSING_DEPS=()
for cmd in git curl sudo; do
    if ! command -v "$cmd" &> /dev/null; then
        MISSING_DEPS+=("$cmd")
    fi
done

if [ ${#MISSING_DEPS[@]} -ne 0 ]; then
    log "INFO" "Missing dependencies: ${MISSING_DEPS[@]}. Installing missing dependencies..."
    install_prerequisites
else
    log "INFO" "All basic dependencies are already installed."
fi

# Clone the GitHub repository
REPO_URL="https://github.com/securityspectrum/ss-install-scripts.git"
REPO_DIR="ss-install-scripts"

if [ -d "$REPO_DIR" ]; then
    log "INFO" "Repository already cloned. Pulling the latest changes..."
    cd "$REPO_DIR"
    if ! git pull; then
        error_exit "Failed to pull latest changes from repository."
    fi
else
    log "INFO" "Cloning the repository..."
    if ! git clone "$REPO_URL"; then
        error_exit "Failed to clone repository."
    fi
    cd "$REPO_DIR"
fi

# Navigate to the scripts directory
log "INFO" "Current working directory: $(pwd)"

# Check if requirements.txt exists
if [ ! -f requirements.txt ]; then
    error_exit "requirements.txt not found."
fi

# Check if install_agents.py exists
if [ ! -f install_agents.py ]; then
    error_exit "install_agents.py not found."
fi

# Function to install Python3 and necessary packages on Linux
install_python_on_linux() {
    SELECTED_PYTHON=""
    if command -v apt-get &> /dev/null; then
        log "INFO" "Using apt-get to install Python and dependencies."
        sudo apt-get update
        sudo apt-get install -y software-properties-common python3-apt
        sudo add-apt-repository ppa:deadsnakes/ppa -y
        sudo apt-get update
        for version in "${PREFERRED_PYTHON_VERSIONS[@]}"; do
            log "INFO" "Attempting to install Python $version."
            if sudo apt-get install -y "python${version}" "python${version}-venv" "python${version}-distutils" "python${version}-dev"; then
                SELECTED_PYTHON="/usr/bin/python${version}"
                log "INFO" "Successfully installed Python ${version}."
                break
            else
                log "WARN" "Python ${version} not available via apt-get."
            fi
        done
        if [ -z "$SELECTED_PYTHON" ]; then
            error_exit "Failed to install a suitable Python version."
        fi
        # Install pip for the selected Python version if not already installed
        if ! "${SELECTED_PYTHON}" -m pip --version &> /dev/null; then
            log "INFO" "Installing pip for ${SELECTED_PYTHON}."
            curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
            sudo "${SELECTED_PYTHON}" get-pip.py
            rm get-pip.py
        fi
        # Install additional necessary packages
        sudo apt-get install -y perl-modules libterm-readline-gnu-perl iproute2
    elif command -v dnf &> /dev/null; then
        log "INFO" "DNF package manager detected. Installing support is not implemented."
        error_exit "DNF package manager support not implemented in this script."
    elif command -v yum &> /dev/null; then
        log "INFO" "YUM package manager detected. Installing support is not implemented."
        error_exit "YUM package manager support not implemented in this script."
    elif command -v zypper &> /dev/null; then
        log "INFO" "Zypper package manager detected. Installing support is not implemented."
        error_exit "Zypper package manager support not implemented in this script."
    else
        error_exit "Unsupported Linux distribution or package manager. Please install Python3 manually."
    fi

    # Verify the selected Python version
    PYTHON_VERSION_INSTALLED=$("${SELECTED_PYTHON}" --version 2>&1 | awk '{print $2}')
    log "INFO" "Installed Python version: ${PYTHON_VERSION_INSTALLED}"

    if ! version_ge "$PYTHON_VERSION_INSTALLED" "3.8"; then
        error_exit "Selected Python version is below 3.8. Installed version: $PYTHON_VERSION_INSTALLED"
    fi
}

# Function to install Python3 and necessary packages on macOS
install_python_on_macos() {
    if ! command -v brew &> /dev/null; then
        log "INFO" "Homebrew is not installed. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        # Add Homebrew to PATH
        eval "$(/opt/homebrew/bin/brew shellenv)" || eval "$(/usr/local/bin/brew shellenv)"
    fi

    SELECTED_PYTHON=""
    for version in "${PREFERRED_PYTHON_VERSIONS[@]}"; do
        if brew list "python@${version}" &> /dev/null; then
            SELECTED_PYTHON="$(brew --prefix "python@${version}")/bin/python${version}"
            log "INFO" "Found Python ${version} installed via Homebrew."
            break
        fi
    done

    if [ -z "$SELECTED_PYTHON" ]; then
        log "INFO" "Installing Python via Homebrew."
        for version in "${PREFERRED_PYTHON_VERSIONS[@]}"; do
            if brew install "python@${version}"; then
                SELECTED_PYTHON="$(brew --prefix "python@${version}")/bin/python${version}"
                log "INFO" "Successfully installed Python ${version} via Homebrew."
                break
            else
                log "WARN" "Python ${version} not available via Homebrew."
            fi
        done
    else
        log "INFO" "Python is already installed via Homebrew."
    fi

    if [ -z "$SELECTED_PYTHON" ]; then
        error_exit "Failed to install Python on macOS."
    fi

    # Verify the selected Python version
    PYTHON_VERSION_INSTALLED=$("${SELECTED_PYTHON}" --version 2>&1 | awk '{print $2}')
    log "INFO" "Installed Python version: ${PYTHON_VERSION_INSTALLED}"

    if ! version_ge "$PYTHON_VERSION_INSTALLED" "3.8"; then
        error_exit "Selected Python version is below 3.8. Installed version: $PYTHON_VERSION_INSTALLED"
    fi

    # Install pip if necessary
    if ! "${SELECTED_PYTHON}" -m pip --version &> /dev/null; then
        log "INFO" "Installing pip for ${SELECTED_PYTHON}."
        curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
        "${SELECTED_PYTHON}" get-pip.py
        rm get-pip.py
    fi
}

# Detect OS type and install Python accordingly
case "$OSTYPE" in
    darwin*)
        log "INFO" "Detected macOS. Proceeding with macOS-specific installation."
        install_python_on_macos
        ;;
    linux*)
        log "INFO" "Detected Linux. Proceeding with Linux-specific installation."
        # Check if python3 is installed
        if ! command -v python3 &> /dev/null; then
            log "INFO" "Python3 is not installed. Installing Python3..."
            install_python_on_linux
            SELECTED_PYTHON=$(command -v python3)  # May not be accurate, needs to set in install_python_on_linux
        else
            # Check python3 version
            PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
            log "INFO" "Detected python3 version: $PYTHON_VERSION"

            if version_ge "$PYTHON_VERSION" "3.8"; then
                log "INFO" "Python3 version is sufficient: $PYTHON_VERSION"
                SELECTED_PYTHON=$(command -v python3)
            else
                log "INFO" "Python3 version is below 3.8 ($PYTHON_VERSION). Installing a newer version..."
                install_python_on_linux
                SELECTED_PYTHON=$(command -v python3)
            fi
        fi
        ;;
    *)
        error_exit "Unsupported operating system: $OSTYPE"
        ;;
esac

# Verify Python installation
if [ -z "${SELECTED_PYTHON:-}" ]; then
    error_exit "Python installation failed."
fi

# Print Python version for verification
"${SELECTED_PYTHON}" --version

# Check if venv module is available
if ! "${SELECTED_PYTHON}" -c "import venv" &> /dev/null; then
    log "INFO" "venv module is not available in ${SELECTED_PYTHON}. Installing necessary packages..."
    if command -v apt-get &> /dev/null; then
        PYTHON_VERSION_SHORT=$(echo "${PYTHON_VERSION_INSTALLED}" | cut -d'.' -f1,2)
        sudo apt-get install -y "python${PYTHON_VERSION_SHORT}-venv"
    elif command -v brew &> /dev/null; then
        # Typically venv comes with Python on macOS via Homebrew
        log "INFO" "venv module should be available via Homebrew Python."
    else
        log "WARN" "Cannot install venv module automatically. Please install it manually."
    fi
fi

# Re-verify venv module
if ! "${SELECTED_PYTHON}" -c "import venv" &> /dev/null; then
    error_exit "venv module is still not available after installation."
fi

# Remove existing virtual environment if it exists
if [ -d "venv" ]; then
    log "INFO" "Removing existing virtual environment..."
    rm -rf venv
fi

# Create virtual environment using the selected Python version
log "INFO" "Creating virtual environment..."
if "${SELECTED_PYTHON}" -m venv venv; then
    log "INFO" "Virtual environment created successfully."
else
    error_exit "Failed to create virtual environment with ${SELECTED_PYTHON}."
fi

# Check if virtual environment was created
if [ ! -f venv/bin/python ] && [ ! -f venv/Scripts/python.exe ]; then
    error_exit "Virtual environment creation did not include python."
fi

# Activate virtual environment
log "INFO" "Activating virtual environment..."
# shellcheck disable=SC1091
source venv/bin/activate || source venv/Scripts/activate

# Verify activation
if [ -z "$VIRTUAL_ENV" ]; then
    error_exit "Failed to activate virtual environment."
fi

# Upgrade pip
log "INFO" "Upgrading pip..."
pip install --upgrade pip
if [ $? -ne 0 ]; then
    error_exit "Failed to upgrade pip."
fi

# Install requirements
if [ -f "requirements.txt" ]; then
    log "INFO" "Installing Python dependencies..."
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        error_exit "Failed to install dependencies."
    fi
else
    log "WARN" "requirements.txt not found."
fi

# Run the Python script with the selected action
if [ -f "install_agents.py" ]; then
    log "INFO" "Running install_agents.py with action: --$ACTION"

    # Only validate environment variables if the action is 'install'
    if [ "$ACTION" = "install" ]; then
        # Validate environment variables
        required_vars=("ORG_KEY" "API_ACCESS_KEY" "API_SECRET_KEY" "JWT_TOKEN" "MASTER_KEY")
        for var in "${required_vars[@]}"; do
            if [ -z "${!var:-}" ]; then
                log "ERROR" "Environment variable $var is not set."
                exit 1
            else
                log "INFO" "$var is set."
            fi
        done
    fi

    # Run the install_agents.py script with the selected action
    python install_agents.py --log-level INFO --"$ACTION"
    if [ $? -ne 0 ]; then
        error_exit "Failed to run install_agents.py."
    fi
else
    error_exit "install_agents.py not found."
fi
