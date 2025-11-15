#!/bin/bash
set -e

echo "=== Vexxy Premium Service Entrypoint ==="

# Function to setup kubeconfig
setup_kubeconfig() {
    echo "[INFO] Setting up Kubernetes configuration..."

    # Check if kubeconfig source exists
    if [ -f "/tmp/kubeconfig/config" ]; then
        echo "[INFO] Found kubeconfig at /tmp/kubeconfig/config"

        # Create .kube directory if it doesn't exist
        mkdir -p /root/.kube

        # Copy kubeconfig to the standard location
        cp /tmp/kubeconfig/config /root/.kube/config
        chmod 600 /root/.kube/config

        # Set KUBECONFIG environment variable
        export KUBECONFIG=/root/.kube/config

        echo "[INFO] Kubeconfig copied to /root/.kube/config"

        # Verify kubectl is installed
        if command -v kubectl &> /dev/null; then
            echo "[INFO] kubectl version: $(kubectl version --client -o yaml | grep gitVersion | head -1)"

            # Test kubectl connectivity (non-blocking)
            if kubectl cluster-info &> /dev/null; then
                echo "[SUCCESS] kubectl can connect to cluster"
            else
                echo "[WARNING] kubectl installed but cannot connect to cluster (this may be expected if cluster is not running)"
            fi
        else
            echo "[ERROR] kubectl is not installed!"
            exit 1
        fi
    else
        echo "[WARNING] No kubeconfig found at /tmp/kubeconfig/config"
        echo "[WARNING] Kubernetes operations will not be available"
        echo "[INFO] This may be expected in some environments"
    fi
}

# Function to verify tools installation
verify_tools() {
    echo "[INFO] Verifying required tools..."

    # Check kubectl
    if command -v kubectl &> /dev/null; then
        echo "[OK] kubectl is installed"
    else
        echo "[WARNING] kubectl is NOT installed"
    fi

    # Check helm
    if command -v helm &> /dev/null; then
        echo "[OK] helm is installed: $(helm version --short)"
    else
        echo "[WARNING] helm is NOT installed"
    fi

    # Check docker (for worker that needs it)
    if command -v docker &> /dev/null; then
        echo "[OK] docker client is installed: $(docker --version)"
    else
        echo "[INFO] docker client is NOT installed (not required for all services)"
    fi
}

# Main setup
echo "[INFO] Starting service setup..."

# Setup kubeconfig
setup_kubeconfig

# Verify tools
verify_tools

echo "[INFO] Environment setup complete"
echo "========================================="

# Execute the main command
echo "[INFO] Executing command: $@"
exec "$@"
