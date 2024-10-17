# Enable strict mode for better error handling
Set-StrictMode -Version Latest

# -------------------- Parameter Definitions -------------------- #
param (
    [switch]$Uninstall
)

# -------------------- Function Definitions -------------------- #

# Function to print error and exit
function Error-Exit {
    param (
        [string]$message
    )
    Write-Host "ERROR: $message" -ForegroundColor Red
    exit 1
}

# Function to check and request execution policy change
function Check-ExecutionPolicy {
    $currentPolicy = Get-ExecutionPolicy -Scope Process
    if ($currentPolicy -ne 'Bypass') {
        Write-Host "The current execution policy is '$currentPolicy'. This script requires 'Bypass' to run."
        $response = Read-Host "Do you want to change the execution policy to 'Bypass' for this session? (y/n)"
        if ($response -eq 'y') {
            Write-Host "Changing the execution policy to 'Bypass' for this session..."
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            Write-Host "Execution policy changed to 'Bypass' for this session."
        } else {
            Error-Exit "Script cannot run without changing the execution policy. Exiting."
        }
    } else {
        Write-Host "Execution policy is already set to 'Bypass'."
    }
}

# Function to install prerequisites (git and curl)
function Install-Prerequisites {
    $programs = @("git", "curl")
    foreach ($program in $programs) {
        if (-not (Get-Command $program -ErrorAction SilentlyContinue)) {
            Write-Host "$program is not installed. Installing $program..."
            if ($program -eq "git") {
                choco install git -y
            } elseif ($program -eq "curl") {
                choco install curl -y
            }
        } else {
            Write-Host "$program is already installed."
        }
    }
}

# Function to install Chocolatey if not present
function Install-Chocolatey {
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Chocolatey is not installed. Installing Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    } else {
        Write-Host "Chocolatey is already installed."
    }
}

# Function to install Python if not present
function Install-Python {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Host "Python is not installed. Installing Python via Chocolatey..."
        choco install python -y
    } else {
        Write-Host "Python is already installed."
    }
}

# -------------------- Script Execution Flow -------------------- #

# Start by checking the execution policy
Check-ExecutionPolicy

# Determine the action based on the provided arguments
if ($Uninstall) {
    $Action = "uninstall"
    Write-Host "Action selected: UNINSTALL" -ForegroundColor Cyan
} else {
    $Action = "install"
    Write-Host "Action selected: INSTALL" -ForegroundColor Cyan
}

# Install prerequisites if installing
if ($Action -eq "install") {
    Write-Host "Checking and installing prerequisites..." -ForegroundColor Yellow
    Install-Chocolatey
    Install-Prerequisites
    Install-Python
} else {
    Write-Host "Skipping prerequisites installation for UNINSTALL action." -ForegroundColor Yellow
}

# Clone the GitHub repository
$repoUrl = "https://github.com/securityspectrum/ss-install-scripts.git"
$repoDir = "ss-install-scripts"

if (Test-Path $repoDir) {
    Write-Host "Repository already cloned. Pulling the latest changes..." -ForegroundColor Green
    Set-Location $repoDir
    git pull
} else {
    Write-Host "Cloning the repository..." -ForegroundColor Green
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
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
    if ($?) {
        Write-Host "Virtual environment created successfully." -ForegroundColor Green
    } else {
        Error-Exit "Failed to create virtual environment."
    }
} else {
    Write-Host "Virtual environment already exists." -ForegroundColor Green
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& .\venv\Scripts\Activate

# Upgrade pip
Write-Host "Upgrading pip..." -ForegroundColor Yellow
& "$PWD\venv\Scripts\python.exe" -m pip install --upgrade pip

if (-not $?) {
    Error-Exit "Failed to upgrade pip."
} else {
    Write-Host "Pip upgraded successfully." -ForegroundColor Green
}

# Install requirements
Write-Host "Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt
if (-not $?) {
    Error-Exit "Failed to install dependencies."
} else {
    Write-Host "Python dependencies installed successfully." -ForegroundColor Green
}

# Only check for environment variables if the action is 'install'
if ($Action -eq "install") {
    Write-Host "Validating environment variables for INSTALL action..." -ForegroundColor Yellow
    $requiredVars = @("ORG_KEY", "API_ACCESS_KEY", "API_SECRET_KEY", "JWT_TOKEN", "MASTER_KEY")
    foreach ($var in $requiredVars) {
        # Get the value of the environment variable dynamically
        $envValue = [System.Environment]::GetEnvironmentVariable($var)

        if (-not $envValue) {
            Error-Exit "Environment variable $var is not set."
        } else {
            # Define the number of characters to show from the start and end
            $numChars = 4
            $startPart = $envValue.Substring(0, [Math]::Min($numChars, $envValue.Length))
            $endPart = $envValue.Substring([Math]::Max(0, $envValue.Length - $numChars), $numChars)

            # Output the preview with the first few and last few characters
            Write-Host "$var is set: $startPart***$endPart"
        }
    }
} else {
    Write-Host "Skipping environment variable validation for UNINSTALL action." -ForegroundColor Yellow
}

# Run the Python script with the selected action
Write-Host "Running install_agents.py with --$Action..." -ForegroundColor Magenta
python install_agents.py --log-level INFO --$Action
if (-not $?) {
    Error-Exit "Failed to run install_agents.py."
} else {
    Write-Host "install_agents.py completed successfully with action: --$Action" -ForegroundColor Green
}
