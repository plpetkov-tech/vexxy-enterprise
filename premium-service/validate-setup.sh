#!/bin/bash
# Validation script to verify kubeconfig and kubectl setup in containers

set -e

echo "=================================================="
echo "   Vexxy Premium Service Setup Validation"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check a container
check_container() {
    local container=$1
    local service=$2

    echo "Checking $service ($container)..."
    echo "----------------------------------------"

    # Check if container is running
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        echo -e "${RED}✗ Container is not running${NC}"
        return 1
    fi
    echo -e "${GREEN}✓ Container is running${NC}"

    # Check kubectl installation
    if docker exec "$container" which kubectl &>/dev/null; then
        echo -e "${GREEN}✓ kubectl is installed${NC}"
        kubectl_version=$(docker exec "$container" kubectl version --client -o yaml 2>/dev/null | grep gitVersion | head -1 | awk '{print $2}')
        echo "  Version: $kubectl_version"
    else
        echo -e "${RED}✗ kubectl is not installed${NC}"
    fi

    # Check helm installation
    if docker exec "$container" which helm &>/dev/null; then
        echo -e "${GREEN}✓ helm is installed${NC}"
        helm_version=$(docker exec "$container" helm version --short 2>/dev/null)
        echo "  Version: $helm_version"
    else
        echo -e "${YELLOW}⚠ helm is not installed${NC}"
    fi

    # Check kubeconfig
    if docker exec "$container" test -f /root/.kube/config; then
        echo -e "${GREEN}✓ Kubeconfig exists at /root/.kube/config${NC}"

        # Check kubeconfig permissions
        perms=$(docker exec "$container" stat -c "%a" /root/.kube/config 2>/dev/null || echo "unknown")
        echo "  Permissions: $perms"

        # Try kubectl cluster-info
        if docker exec "$container" kubectl cluster-info &>/dev/null; then
            echo -e "${GREEN}✓ kubectl can connect to cluster${NC}"
        else
            echo -e "${YELLOW}⚠ kubectl cannot connect to cluster (cluster may not be running)${NC}"
        fi
    else
        echo -e "${RED}✗ Kubeconfig does not exist${NC}"
    fi

    # Check KUBECONFIG env var
    if docker exec "$container" env | grep -q "KUBECONFIG"; then
        kubeconfig_path=$(docker exec "$container" env | grep KUBECONFIG | cut -d= -f2)
        echo -e "${GREEN}✓ KUBECONFIG environment variable is set${NC}"
        echo "  Path: $kubeconfig_path"
    else
        echo -e "${YELLOW}⚠ KUBECONFIG environment variable is not set${NC}"
    fi

    # Check Docker CLI (for worker)
    if [ "$service" = "worker" ]; then
        if docker exec "$container" which docker &>/dev/null; then
            echo -e "${GREEN}✓ Docker CLI is installed${NC}"
            docker_version=$(docker exec "$container" docker --version 2>/dev/null)
            echo "  $docker_version"
        else
            echo -e "${RED}✗ Docker CLI is not installed${NC}"
        fi
    fi

    echo ""
}

# Check all services
check_container "vexxy-premium-api" "API"
check_container "vexxy-premium-worker" "Worker"
check_container "vexxy-premium-flower" "Flower"

echo "=================================================="
echo "   Validation Complete"
echo "=================================================="
