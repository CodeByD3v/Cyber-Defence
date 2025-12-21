#!/bin/bash
# Zeek Installation Script for WSL Ubuntu
# Run this inside WSL: wsl -d Ubuntu-22.04

echo "=========================================="
echo "  Zeek Installation for SOC Platform"
echo "=========================================="

# Update package list
echo "[1/4] Updating package list..."
sudo apt-get update

# Install dependencies
echo "[2/4] Installing dependencies..."
sudo apt-get install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev

# Add Zeek repository
echo "[3/4] Adding Zeek repository..."
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get update

# Install Zeek
echo "[4/4] Installing Zeek..."
sudo apt-get install -y zeek

# Verify installation
echo ""
echo "=========================================="
echo "  Verifying Installation"
echo "=========================================="
which zeek && zeek --version

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Zeek is installed at: $(which zeek)"
echo ""
echo "To use Zeek from Windows, set this environment variable:"
echo "  SOC_ZEEK_BIN=wsl -d Ubuntu-22.04 -- /opt/zeek/bin/zeek"
echo ""
