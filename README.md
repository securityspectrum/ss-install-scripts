Generating requirements.txt

1. Install pip-tools:
```bash
pip install pip-tools
```

2. Generate requirements.txt:
```sh
pip-compile requirements.in
```


```bash
#!/bin/bash
set -euxo pipefail

# Export secrets as environment variables (values provided by the webapp)
export ORG_KEY="your_org_key_here"
export API_ACCESS_KEY="your_api_access_key_here"
export API_SECRET_KEY="your_api_secret_key_here"
export JWT_TOKEN="your_jwt_token_here"
export MASTER_KEY="your_master_key_here"

# Run the installation script
curl -sL https://github.com/securityspectrum/ss-install-scripts/raw/main/install.sh | bash
```