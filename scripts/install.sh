#!/bin/bash
# scripts/install.sh
set -e

echo "Installing OpenResty and dependencies..."

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y wget gnupg ca-certificates lsb-release

        wget -O - https://openresty.org/package/pubkey.gpg | apt-key add -
        echo "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main" \
            | tee /etc/apt/sources.list.d/openresty.list
        apt-get update
        apt-get install -y openresty

        # Install luarocks for yaml parsing
        apt-get install -y luarocks
        luarocks install yaml

    elif command -v yum &> /dev/null; then
        # CentOS/RHEL
        yum install -y yum-utils
        yum-config-manager --add-repo https://openresty.org/package/centos/openresty.repo
        yum install -y openresty

        yum install -y luarocks
        luarocks install yaml
    fi

elif [[ "$OSTYPE" == "msys"* ]] || [[ "$OSTYPE" == "cygwin"* ]]; then
    echo "Windows detected. Please install OpenResty manually from:"
    echo "https://openresty.org/en/download.html"
    echo "Then install lua-yaml via luarocks."
    exit 1
fi

# Create log directory
mkdir -p logs

echo "Installation complete."
echo "Run 'scripts/start.sh' to start the WAF."
