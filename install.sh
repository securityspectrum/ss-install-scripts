#!/bin/bash
# We remove -x from here so it's not always on:
set -euo pipefail

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
    echo "Usage: $0 [--install | --uninstall | --verbose | --help]"
    echo
    echo "Options:"
    echo "  --install       Install the agents."
    echo "  --uninstall     Uninstall the agents."
    echo "  --verbose       Enable verbose mode (disables quiet mode for apt/pip and turns on xtrace)."
    echo "  --help, -h      Display this help message."
    exit 1
}

# Function to compare versions using sort -V (more portable)
version_ge() {
    # Returns 0 (true) if $1 >= $2, else 1
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

# Default verbose flag is off
VERBOSE=false

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
        --verbose)
            VERBOSE=true
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

# If --verbose is enabled, turn on xtrace
if [ "$VERBOSE" = true ]; then
    set -x
fi

# Determine apt/pip verbosity based on --verbose
if [ "$VERBOSE" = true ]; then
    APT_QUIET=""
    PIP_QUIET=""
    LOG_LEVEL="DEBUG"
else
    APT_QUIET="-qq"
    PIP_QUIET="-q"
    LOG_LEVEL="ERROR"
fi

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
        sudo apt-get update $APT_QUIET
        sudo apt-get install $APT_QUIET -y git curl sudo
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

# Function to check and install Python and necessary modules
install_python_and_modules() {
    # Function to install Python3 and necessary packages on Linux
    install_python_on_linux() {
        SELECTED_PYTHON=""
        PACKAGE_MANAGER=""

        if command -v apt-get &> /dev/null; then
            PACKAGE_MANAGER="apt-get"
        elif command -v dnf &> /dev/null; then
            PACKAGE_MANAGER="dnf"
        elif command -v yum &> /dev/null; then
            PACKAGE_MANAGER="yum"
        elif command -v zypper &> /dev/null; then
            PACKAGE_MANAGER="zypper"
        else
            error_exit "No supported package manager found (apt-get, dnf, yum, zypper). Please install Python3 manually."
        fi

        case "$PACKAGE_MANAGER" in
            apt-get)
                log "INFO" "Using apt-get to install Python and dependencies."
                sudo apt-get update $APT_QUIET
                sudo apt-get install $APT_QUIET -y python3-full
                SELECTED_PYTHON=$(command -v python3)
                ;;
            dnf|yum)
                log "INFO" "Using $PACKAGE_MANAGER to install Python and dependencies."
                sudo "$PACKAGE_MANAGER" install -y python3 python3-venv python3-pip
                SELECTED_PYTHON=$(command -v python3)
                ;;
            zypper)
                log "INFO" "Using zypper to install Python and dependencies."
                sudo zypper refresh
                sudo zypper install -y python3 python3-venv python3-pip
                SELECTED_PYTHON=$(command -v python3)
                ;;
        esac

        if [ -z "$SELECTED_PYTHON" ]; then
            error_exit "Failed to install Python using $PACKAGE_MANAGER."
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

        if ! brew list "python@3" &> /dev/null; then
            log "INFO" "Installing Python 3 via Homebrew."
            brew install python@3
        else
            log "INFO" "Python 3 is already installed via Homebrew."
        fi

        SELECTED_PYTHON=$(brew --prefix python@3)/bin/python3

        if [ -z "$SELECTED_PYTHON" ]; then
            error_exit "Failed to install Python on macOS."
        fi
    }

    # Detect OS type and install Python accordingly
    if [[ "$OSTYPE" == "darwin"* ]]; then
        log "INFO" "Detected macOS. Proceeding with macOS-specific installation."
        install_python_on_macos
    elif [[ "$OSTYPE" == "linux"* ]]; then
        log "INFO" "Detected Linux. Proceeding with Linux-specific installation."
        if ! command -v python3 &> /dev/null; then
            log "INFO" "Python3 is not installed. Installing Python3..."
            install_python_on_linux
        else
            SELECTED_PYTHON=$(command -v python3)
            PYTHON_VERSION=$("$SELECTED_PYTHON" --version 2>&1 | awk '{print $2}')
            if version_ge "$PYTHON_VERSION" "3.8"; then
                log "INFO" "Detected python3 version: $PYTHON_VERSION (ok)"
                if ! "$SELECTED_PYTHON" -m venv -h &> /dev/null || ! "$SELECTED_PYTHON" -m pip -V &> /dev/null; then
                    log "INFO" "Required Python modules not available. Installing Python3 and modules..."
                    install_python_on_linux
                fi
            else
                log "INFO" "Detected python3 version: $PYTHON_VERSION (requires at least 3.8)"
                install_python_on_linux
            fi
        fi
    else
        error_exit "Unsupported operating system: $OSTYPE"
    fi
}

install_python_and_modules

# Remove existing virtual environment if it exists
if [ -d "venv" ]; then
    log "INFO" "Removing existing virtual environment..."
    rm -rf venv
fi

# Create virtual environment using the selected Python version
log "INFO" "Creating virtual environment..."
if "$SELECTED_PYTHON" -m venv venv; then
    log "INFO" "Virtual environment created successfully."
else
    error_exit "Failed to create virtual environment with ${SELECTED_PYTHON}."
fi

# Activate virtual environment
log "INFO" "Activating virtual environment..."
# shellcheck disable=SC1091
source venv/bin/activate || source venv/Scripts/activate

# Verify activation
if [ -z "$VIRTUAL_ENV" ]; then
    error_exit "Failed to activate virtual environment."
fi

# Upgrade pip within the virtual environment (use $PIP_QUIET)
log "INFO" "Upgrading pip in virtual environment..."
pip install $PIP_QUIET --upgrade pip
if [ $? -ne 0 ]; then
    error_exit "Failed to upgrade pip in virtual environment."
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
    log "INFO" "Cloning the repository from $REPO_URL"
    if [ "$VERBOSE" = true ]; then
        if ! git clone "$REPO_URL"; then
            error_exit "Failed to clone repository."
        fi
    else
        if ! git clone "$REPO_URL" > /dev/null 2>&1; then
            error_exit "Failed to clone repository."
        fi
    fi
    cd "$REPO_DIR"
    log "INFO" "Repository cloned successfully from $REPO_URL"
fi

# Navigate to the scripts directory
log "INFO" "Current working directory: $(pwd)"

# Check if requirements.txt exists
if [ ! -f requirements.txt ]; then
    error_exit "requirements.txt not found."
fi

# Install requirements (use $PIP_QUIET)
log "INFO" "Installing Python packages from requirements.txt..."
pip install $PIP_QUIET -r requirements.txt
if [ $? -ne 0 ]; then
    error_exit "Failed to install packages."
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
                if [ "$VERBOSE" = true ]; then
                    log "INFO" "$var is set."
                fi
            fi
        done
    fi

    python install_agents.py --log-level "$LOG_LEVEL" --"$ACTION"
    if [ $? -ne 0 ]; then
        error_exit "Failed to run install_agents.py."
    fi
else
    error_exit "install_agents.py not found."
fi
