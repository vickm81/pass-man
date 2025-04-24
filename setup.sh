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
        
    fedora)
        echo "Installing Docker on Fedora..."
        
        # Install required packages
        dnf -y install dnf-plugins-core
        
        # Add Docker repository
        dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        
        # Install Docker Engine
        dnf install -y docker-ce docker-ce-cli containerd.io
        ;;
        
    *)
        echo "Unsupported operating system: $OS"
        echo "This script only supports Ubuntu and Fedora"
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