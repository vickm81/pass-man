#!/bin/bash
# Exit on error
set -e
# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root or with sudo privileges"
    exit 1
fi
# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect operating system"
    exit 1
fi
echo "Detected operating system: $OS"
# Install Docker based on OS
case $OS in
    ubuntu)
        echo "Installing Docker on Ubuntu..."
        
        # Update apt and install required packages
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl software-properties-common
        # Add Docker's official GPG key
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        
        # Add Docker repository
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
          $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker Engine
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io
        ;;
        
    linuxmint)
        echo "Installing Docker on Linux Mint..."
        
        # Update apt and install required packages
        apt-get update
        apt-get install -y apt-transport-https ca-certificates curl software-properties-common
        # Add Docker's official GPG key
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
        
        # Add Docker repository - using Ubuntu repositories since Mint is Ubuntu-based
        # Get the Ubuntu codename that this Mint release is based on
        UBUNTU_CODENAME=$(grep UBUNTU_CODENAME /etc/os-release | cut -d= -f2)
        if [ -z "$UBUNTU_CODENAME" ]; then
            # Fallback to determining from /etc/upstream-release if available
            if [ -f /etc/upstream-release/lsb-release ]; then
                . /etc/upstream-release/lsb-release
                UBUNTU_CODENAME=$(echo $DISTRIB_CODENAME)
            else
                # Final fallback - determine from Mint version (approximate mapping)
                case $VERSION_ID in
                    "20"*)
                        UBUNTU_CODENAME="focal"
                        ;;
                    "21"*)
                        UBUNTU_CODENAME="jammy"
                        ;;
                    *)
                        echo "Cannot determine Ubuntu base for this Mint version"
                        exit 1
                        ;;
                esac
            fi
        fi
        
        echo \
          "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
          $UBUNTU_CODENAME stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        # Install Docker Engine
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io
        ;;
        
    fedora)
        echo "Installing Docker on Fedora..."
        
        # Add Docker repository
        sudo curl -o /etc/yum.repos.d/docker-ce.repo https://download.docker.com/linux/fedora/docker-ce.repo
        # Install Docker Engine
        dnf install -y docker-ce docker-ce-cli containerd.io
        ;;
        
    *)
        echo "Unsupported operating system: $OS"
        echo "This script only supports Ubuntu, Linux Mint, and Fedora"
        exit 1
        ;;
esac
# Start and enable Docker service
systemctl start docker
systemctl enable docker
echo "Docker has been installed successfully"
# Pull the Docker image
echo "Pulling Docker image"
docker pull vickm81/pass-man
# Run the Docker image
echo "Running Docker image"
docker run -p 5000:5000 vickm81/pass-man
echo "Done!"