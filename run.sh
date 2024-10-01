#!/bin/bash
set -euxo pipefail

cd /scripts

# Function to print error and exit
error_exit() {
    echo "ERROR: $1" >&2
    exit 1
}

# Navigate to the scripts directory
echo "Current working directory: $(pwd)"

# Check if requirements.txt exists
if [ ! -f requirements.txt ]; then
    error_exit "requirements.txt not found"
fi

# Check if main.py exists
if [ ! -f main.py ]; then
    error_exit "main.py not found"
fi

# Function to install Python3 and necessary packages
install_python_on_linux() {
    if command -v apt-get &> /dev/null; then
        apt-get update
        apt-get install -y python3 python3-venv python3-pip perl-modules libterm-readline-gnu-perl iproute2
    elif command -v dnf &> /dev/null; then
        dnf install -y python3 python3-venv python3-pip perl-TermReadLine-Gnu iproute2
    elif command -v yum &> /dev/null; then
        yum install -y python3 python3-venv python3-pip perl-TermReadLine-Gnu iproute2
    elif command -v zypper &> /dev/null; then
        # Check if the repo metadata is up-to-date by listing updates
        zypper lu &> /dev/null
        if [ $? -eq 4 ]; then  # Exit code 4 means the metadata is out of date
            echo "Repository metadata is out of date. Refreshing..."
            zypper refresh
        fi

        # Now try installing the required packages
        zypper install -y python3 python3-pip perl-TermReadLine-Gnu iproute2 || \
        zypper install -y python3 python-pip perl-TermReadLine iproute2
    else

        error_exit "Unsupported Linux distribution or package manager. Please install Python3 manually."
    fi
}

# Install Python3 and necessary packages if not already installed
if ! command -v python3 &> /dev/null; then
    echo "Python3 is not installed. Installing Python3..."
    install_python_on_linux
fi

# Verify Python3 installation
if ! command -v python3 &> /dev/null; then
    error_exit "Python3 installation failed."
fi

# Print Python3 version for verification
python3 --version

# Check if venv module is available
if ! python3 -c "import venv" &> /dev/null; then
    echo "venv module is not available. Installing Python3-venv..."
    install_python_on_linux
fi

# Ensure python3-venv and pip are installed
if ! python3 -m venv --help &> /dev/null; then
    echo "Python3-venv is not installed. Installing required packages..."
    install_python_on_linux
fi

# Re-verify venv module
if ! python3 -c "import venv" &> /dev/null; then
    error_exit "venv module is still not available after installation."
fi

# List Python3 binaries for debugging purposes
echo "Listing Python3 binaries in /usr/bin:"
ls -l /usr/bin/python3*

# Create virtual environment
echo "Creating virtual environment..."
if python3 -m venv venv; then
    echo "Virtual environment created successfully."
else
    error_exit "Failed to create virtual environment."
fi

# Check if virtual environment was created
if [ ! -f venv/bin/python3 ]; then
    error_exit "Virtual environment creation did not include python3."
fi

# Check if virtual environment directory exists
if [ venv ]; then
    echo "Virtual environment directory exists."
    rm -rf venv
fi
python3 -m venv venv
if [ $? -ne 0 ]; then
    echo "Failed to create virtual environment."
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

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
if [ -f "main.py" ]; then
    echo "Running main.py..."
    python main.py --log-level INFO
    if [ $? -ne 0 ]; then
        echo "Failed to run main.py."
        exit 1
    fi
else
    echo "main.py not found."
    exit 1
fi
