#!/bin/bash
set -x

# Check if running on macOS
if [[ "$OSTYPE" == "darwin"* ]]; then
    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        echo "Homebrew is not installed. Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

        # Update Homebrew and install Python if not already installed
        echo "Installing Python via Homebrew..."
        brew update
        brew install python3
    else
        echo "Homebrew is already installed."
    fi

    # Check if Python3 is installed via Homebrew
    if ! brew list python3 &> /dev/null; then
        echo "Python3 is not installed. Installing Python3 via Homebrew..."
        brew install python3
    else
        echo "Python3 is already installed."
    fi
fi

# Proceed with setting up the Python virtual environment
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Run the Python script
python main.py

