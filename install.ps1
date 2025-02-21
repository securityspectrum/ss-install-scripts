param (
    [switch]$Uninstall,
    [switch]$Verbose
)

# Set log level and pip quiet flag based on $Verbose
if ($Verbose) {
    $LOG_LEVEL = "DEBUG"
    $PIP_QUIET = ""
} else {
    $LOG_LEVEL = "ERROR"
    $PIP_QUIET = "-q"
}

# Logging function that prints a timestamped message with a given log level
function Log {
    param (
        [string]$Type,
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Type] $Message"
}

# Enable strict mode for better error handling
Set-StrictMode -Version Latest

# Function to print error and exit
function Error-Exit {
    param (
        [string]$message
    )
    Log "ERROR" $message
    exit 1
}

# Function to check and request execution policy change
function Check-ExecutionPolicy {
    $currentPolicy = Get-ExecutionPolicy -Scope Process
    if ($currentPolicy -ne 'Bypass') {
        Log "INFO" "The current execution policy is '$currentPolicy'. This script requires 'Bypass' to run."
        $response = Read-Host "Do you want to change the execution policy to 'Bypass' for this session? (y/n)"
        if ($response -eq 'y') {
            Log "INFO" "Changing the execution policy to 'Bypass' for this session..."
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            Log "INFO" "Execution policy changed to 'Bypass' for this session."
        } else {
            Error-Exit "Script cannot run without changing the execution policy. Exiting."
        }
    } else {
        Log "INFO" "Execution policy is already set to 'Bypass'."
    }
}

# Function to install prerequisites (git and curl)
function Install-Prerequisites {
    $programs = @("git", "curl")
    foreach ($program in $programs) {
        if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
            Log "INFO" "$program is not installed. Installing $program..."
            if ($program -eq "git") {
                choco install git -y
            } elseif ($program -eq "curl") {
                choco install curl -y
            }
        } else {
            if ($Verbose) {
                Log "DEBUG" "$program is already installed."
            }
        }
    }
}

# Function to install Chocolatey if not present
function Install-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Log "INFO" "Chocolatey is not installed. Installing Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    } else {
        if ($Verbose) {
            Log "DEBUG" "Chocolatey is already installed."
        }
    }
}

# Function to install Python if not present
function Install-Python {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Log "INFO" "Python is not installed. Installing Python via Chocolatey..."
        choco install python -y
    } else {
        if ($Verbose) {
            Log "DEBUG" "Python is already installed."
        }
    }
}

# -------------------- Script Execution Flow -------------------- #

# Start by checking the execution policy
Check-ExecutionPolicy

# Determine the action based on the provided arguments
if ($Uninstall) {
    $Action = "uninstall"
    Log "INFO" "Action selected: UNINSTALL"
} else {
    $Action = "install"
    Log "INFO" "Action selected: INSTALL"
}

if ($Verbose) {
    Log "DEBUG" "Action before prerequisites: --$Action"
}

# Install prerequisites if installing
if ($Action -eq "install") {
    Log "INFO" "Installing prerequisites..."
    Install-Chocolatey
    Install-Prerequisites
    Install-Python
} else {
    Log "INFO" "Skipping prerequisites installation for UNINSTALL action."
}

if ($Verbose) {
    Log "DEBUG" "Proceeding with repository cloning and setup..."
}

# Clone the GitHub repository
$repoUrl = "https://github.com/securityspectrum/ss-install-scripts.git"
$repoDir = "ss-install-scripts"

if (Test-Path $repoDir) {
    Log "INFO" "Repository already cloned. Pulling the latest changes..."
    Set-Location $repoDir
    git pull
} else {
    Log "INFO" "Cloning the repository..."
    git clone $repoUrl
    Set-Location $repoDir
}

# Check if requirements.txt exists
if (-not (Test-Path "requirements.txt")) {
    Error-Exit "requirements.txt not found"
}

# Check if install_agents.py exists
if (-not (Test-Path "install_agents.py")) {
    Error-Exit "install_agents.py not found"
}

# Create virtual environment if it doesn't exist
if (-not (Test-Path "venv")) {
    Log "INFO" "Creating virtual environment..."
    python -m venv venv
    if ($?) {
        Log "INFO" "Virtual environment created successfully."
    } else {
        Error-Exit "Failed to create virtual environment."
    }
} else {
    if ($Verbose) {
        Log "DEBUG" "Virtual environment already exists."
    }
}

# Define the path to the virtual environment's Python executable
$venvPython = Join-Path $PWD "venv\Scripts\python.exe"

# Upgrade pip using the virtual environment's Python (using pip quiet flag if not verbose)
Log "INFO" "Upgrading pip..."
& $venvPython -m pip install $PIP_QUIET --upgrade pip
if (-not $?) {
    Error-Exit "Failed to upgrade pip."
} else {
    if ($Verbose) {
        Log "DEBUG" "Pip upgraded successfully."
    }
}

# Install requirements using the virtual environment's Python (with pip quiet flag)
Log "INFO" "Installing Python dependencies..."
& $venvPython -m pip install $PIP_QUIET -r requirements.txt
if (-not $?) {
    Error-Exit "Failed to install dependencies."
} else {
    if ($Verbose) {
        Log "DEBUG" "Python dependencies installed successfully."
    }
}

# Only check for environment variables if the action is 'install'
if ($Action -eq "install") {
    Log "INFO" "Validating environment variables..."
    $requiredVars = @("ORG_KEY", "API_ACCESS_KEY", "API_SECRET_KEY", "JWT_TOKEN", "MASTER_KEY")
    foreach ($var in $requiredVars) {
        $envValue = [System.Environment]::GetEnvironmentVariable($var)
        if (-not $envValue) {
            Error-Exit "Environment variable $var is not set."
        } else {
            if ($Verbose) {
                $numChars = 4
                if ($envValue.Length -gt ($numChars * 2)) {
                    $startPart = $envValue.Substring(0, $numChars)
                    $endPart = $envValue.Substring($envValue.Length - $numChars, $numChars)
                    Log "DEBUG" "$var is set: $startPart***$endPart"
                } else {
                    Log "DEBUG" "$var is set: $envValue"
                }
            }
        }
    }
} else {
    Log "INFO" "Skipping environment variable validation for UNINSTALL action."
}

if ($Verbose) {
    Log "DEBUG" "Action before running Python script: --$Action"
}

# Run the Python script with the selected action using the virtual environment's Python
Log "INFO" "Running install_agents.py with --$Action..."
if ($Verbose) {
    Log "DEBUG" "Executing: & $venvPython install_agents.py --log-level $LOG_LEVEL --$Action"
}
& $venvPython install_agents.py --log-level $LOG_LEVEL --$Action
if (-not $?) {
    Error-Exit "Failed to run install_agents.py."
} else {
    Log "INFO" "install_agents.py completed successfully with action: --$Action"
}
