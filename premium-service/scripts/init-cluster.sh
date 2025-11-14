#!/bin/bash
set -e

echo "🚀 Initializing Kubernetes cluster for Vexxy Premium Service..."

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found. Please install kubectl first."
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to Kubernetes cluster. Please check your kubeconfig."
    exit 1
fi

echo "✅ Connected to Kubernetes cluster"

# Create vexxy-sandbox namespace if it doesn't exist
echo "📦 Creating vexxy-sandbox namespace..."
if kubectl get namespace vexxy-sandbox &> /dev/null; then
    echo "  ℹ️  Namespace vexxy-sandbox already exists"
else
    kubectl create namespace vexxy-sandbox
    echo "  ✅ Created namespace: vexxy-sandbox"
fi

# Label the namespace
kubectl label namespace vexxy-sandbox app=vexxy vexxy.dev/premium=true --overwrite
echo "  ✅ Labeled namespace"

# Check if Kubescape namespace exists (optional - the service will auto-install)
if kubectl get namespace kubescape &> /dev/null; then
    echo "✅ Kubescape namespace found (already installed)"
else
    echo "ℹ️  Kubescape not installed yet - will be auto-installed on first analysis"
fi

echo ""
echo "✅ Cluster initialization complete!"
echo ""
echo "Next steps:"
echo "  1. Start the services: docker-compose up"
echo "  2. Submit an analysis job to test"
echo ""
