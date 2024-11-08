Generating requirements.txt

1. Install pip-tools:
```bash
pip install pip-tools
```

2. Generate requirements.txt:
```sh
pip-compile requirements.in
```

#. Install the agent:
```bash
#!/bin/bash
set -euxo pipefail

# Export secrets as environment variables (values provided by the webapp)
export ORG_KEY=""
export API_ACCESS_KEY=""
export API_SECRET_KEY=""
export JWT_TOKEN=""
export MASTER_KEY=""

# Run the installation script
curl -sL https://github.com/securityspectrum/ss-install-scripts/raw/main/install.sh | bash
```

For Windows
```bash
$env:ORG_KEY = ""
$env:API_ACCESS_KEY = ""
$env:API_SECRET_KEY = ""
$env:JWT_TOKEN = ""
$env:MASTER_KEY = ""

# Download and run the installation script
Invoke-WebRequest -Uri "https://github.com/securityspectrum/ss-install-scripts/raw/main/install.ps1" -OutFile "install.ps1"
powershell -ExecutionPolicy Bypass -File .\install.ps1
```