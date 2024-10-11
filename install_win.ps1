# Enable strict mode for better error handling
Set-StrictMode -Version Latest

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

# Start by checking the execution policy
Check-ExecutionPolicy

# Check if git, curl, and python are installed
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

# Install Chocolatey if it's not installed (Windows Package Manager)
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

# Install Python if it's not installed
function Install-Python {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Host "Python is not installed. Installing Python via Chocolatey..."
        choco install python -y
    } else {
        Write-Host "Python is already installed."
    }
}

# Clone the GitHub repository
$repoUrl = "https://github.com/securityspectrum/ss-install-scripts.git"
$repoDir = "ss-install-scripts"

if (Test-Path $repoDir) {
    Write-Host "Repository already cloned. Pulling the latest changes..."
    Set-Location $repoDir
    git pull
} else {
    Write-Host "Cloning the repository..."
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

# Create virtual environment
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..."
    python -m venv venv
    if ($?) {
        Write-Host "Virtual environment created successfully."
    } else {
        Error-Exit "Failed to create virtual environment."
    }
}

# Activate virtual environment
Write-Host "Activating virtual environment..."
& .\venv\Scripts\Activate

# Upgrade pip
Write-Host "Upgrading pip..."
& "$PWD\venv\Scripts\python.exe" -m pip install --upgrade pip

if (-not $?) {
    Error-Exit "Failed to upgrade pip."
}

# Install requirements
Write-Host "Installing Python dependencies..."
pip install -r requirements.txt
if (-not $?) {
    Error-Exit "Failed to install dependencies."
}


# Check if required environment variables are set
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

# Run the Python script
Write-Host "Running install_agents.py..."
python install_agents.py --log-level INFO --install
if (-not $?) {
    Error-Exit "Failed to run install_agents.py."
}
