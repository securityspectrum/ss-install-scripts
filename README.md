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

For a local platform, export `SS_API_URL=https://localhost` and run
the V2 project's `scripts/install-local-agent.sh` after exporting the organization
variables from its setup wizard. Use updated checkouts of V2, this installer,
and Fluent Bit (including commit `3c25db66ce6b47ee118f271dcccc986be8cba2b6`).
This includes the encryption repair, the EL8 compiler fix, and correct handling
of empty text in deterministic AES-GCM.
The launcher prepares a corrected collector and passes `--fluent-bit-binary`
to this installer's Python entry point. A fresh host gets its binary and systemd
unit; an existing host gets a service override and a restart. Cached builds are
verified and reused, and missing caches are rebuilt. See V2's local development
guide for the Fedora build prerequisites.

To use a prepared Linux collector directly, run
`python install_agents.py --install --fluent-bit-binary /absolute/path/to/fluent-bit`
from this checkout after installing its requirements in a virtual environment.
Without that option the installer still downloads the released Fluent Bit package.
The default API address is the hosted service.
The remote bootstrap uses the published repository. The Python installer
retains the environment through `sudo -E`.

The public bootstrap needs these installer changes and the corrected collector
published before it can reproduce this local workflow on another machine.

For Linux hosts that already run Zeek and osquery, use
`python install_agents.py --install --keep-existing-sensors`. This requires both
services to be active and preserves their packages and configuration. Fluent Bit
and SS Agent are installed/configured normally. Use `--check` instead of `--install`
to validate the organization configuration and download both certificate archives
without changing packages or services. Preflight also runs before installation
and before sudo prompts or service stops.

Preflight checks the collector's PII and encryption-key endpoints with API-key
authentication and rejects redirects. On Linux, an existing SS Agent unit is
enabled and started on reinstall, even when no new unit file needs to be created.

The installer waits briefly after starting Linux services and verifies they
remain active, so an immediate collector exit is reported as an installation
failure. The installer needs an interactive sudo password on systems without passwordless
sudo. Run from a terminal. Its generated configuration contains credentials;
do not enable shell tracing or share the installation log.

The shell installer uses PyPI by default and ignores workstation pip config
files. Set `PIP_INDEX_URL` explicitly if your environment needs another package
index.

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
