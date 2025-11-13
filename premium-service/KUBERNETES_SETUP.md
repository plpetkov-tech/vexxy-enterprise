# Kubernetes Setup for Premium Service

The premium VEX service requires a Kubernetes cluster to deploy and analyze container images. **Docker Compose alone is not sufficient** - you need a separate K8s cluster.

## Why Kubernetes is Required

The service uses Kubernetes for:
1. **Kubescape** - Runs as K8s operator, requires cluster access
2. **Workload Deployment** - Deploys containers as K8s Deployments for analysis
3. **CRD Extraction** - Reads VEX and SBOM from Kubescape CRDs
4. **Isolation** - K8s namespaces provide sandbox isolation

## Quick Start (Recommended)

### Option 1: Docker Desktop with Kubernetes (Easiest)

**Best for**: Mac/Windows users, simplest setup

**Steps:**
```bash
# 1. Install Docker Desktop
# Download from: https://www.docker.com/products/docker-desktop

# 2. Enable Kubernetes
# Docker Desktop → Settings → Kubernetes → Enable Kubernetes
# Wait 2-3 minutes for K8s to start

# 3. Verify it's running
kubectl get nodes
# Expected output:
# NAME             STATUS   ROLES           AGE   VERSION
# docker-desktop   Ready    control-plane   2m    v1.27.2

# 4. Start premium service
cd premium-service
docker-compose up -d

# 5. Verify worker can access K8s
docker-compose exec worker kubectl get nodes
# Should show docker-desktop node
```

**Advantages:**
- ✅ Zero configuration needed
- ✅ Shares Docker network with compose
- ✅ Built into Docker Desktop
- ✅ Good for local testing

**Disadvantages:**
- ❌ Mac/Windows only (no Linux support)
- ❌ Uses more resources (2GB+ RAM)

---

### Option 2: minikube (Cross-Platform)

**Best for**: Linux users, or users wanting more control

**Steps:**
```bash
# 1. Install minikube
# Mac:
brew install minikube

# Linux:
curl -LO https://storage.googleapis.com/minikube/releases/latest/minikube-linux-amd64
sudo install minikube-linux-amd64 /usr/local/bin/minikube

# Windows:
choco install minikube

# 2. Start minikube cluster
minikube start --cpus=4 --memory=8192 --driver=docker

# 3. Verify cluster is running
kubectl get nodes
# Expected output:
# NAME       STATUS   ROLES           AGE   VERSION
# minikube   Ready    control-plane   1m    v1.27.4

# 4. Configure kubeconfig (usually automatic)
minikube kubectl -- get nodes

# 5. Start premium service
cd premium-service
docker-compose up -d

# 6. Verify connectivity
docker-compose exec worker kubectl get nodes
```

**Advantages:**
- ✅ Cross-platform (Mac/Linux/Windows)
- ✅ Lightweight
- ✅ Easy to reset (minikube delete)
- ✅ Good for development

**Disadvantages:**
- ❌ Requires more setup than Docker Desktop
- ❌ Separate from Docker (different network)

**Troubleshooting:**
```bash
# If worker can't connect to minikube
minikube ip  # Get minikube IP
# Update ~/.kube/config to use minikube IP instead of localhost

# Or use host network
docker-compose exec worker kubectl --kubeconfig=/root/.kube/config get nodes
```

---

### Option 3: kind (Kubernetes in Docker)

**Best for**: CI/CD, multiple clusters, advanced users

**Steps:**
```bash
# 1. Install kind
# Mac:
brew install kind

# Linux:
curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
chmod +x ./kind
sudo mv ./kind /usr/local/bin/kind

# 2. Create cluster
kind create cluster --name vexxy --config - <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
- role: worker
EOF

# 3. Verify cluster
kubectl cluster-info --context kind-vexxy
kubectl get nodes

# 4. Start premium service
cd premium-service
docker-compose up -d

# 5. Test connectivity
docker-compose exec worker kubectl get nodes
```

**Advantages:**
- ✅ Fast startup
- ✅ Multiple clusters easily
- ✅ Good for CI/CD
- ✅ Runs inside Docker

**Disadvantages:**
- ❌ More complex networking
- ❌ Requires kind-specific configuration

---

### Option 4: k3s (Lightweight Production)

**Best for**: Resource-constrained environments, production-like testing

**Steps:**
```bash
# 1. Install k3s (Linux only)
curl -sfL https://get.k3s.io | sh -

# 2. Get kubeconfig
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
sudo chown $USER ~/.kube/config

# 3. Verify cluster
kubectl get nodes

# 4. Start premium service
cd premium-service
docker-compose up -d
```

**Advantages:**
- ✅ Very lightweight (40MB)
- ✅ Production-ready
- ✅ Fast startup
- ✅ Good for edge/IoT

**Disadvantages:**
- ❌ Linux only
- ❌ Runs as system service (not containerized)

---

## Production Setup

### Option 5: Cloud Kubernetes (AWS EKS, GKE, AKS)

**Best for**: Production deployments

**Setup:**
```bash
# Example: AWS EKS
aws eks update-kubeconfig --region us-west-2 --name vexxy-cluster

# Example: Google GKE
gcloud container clusters get-credentials vexxy-cluster --zone us-central1-a

# Example: Azure AKS
az aks get-credentials --resource-group vexxy-rg --name vexxy-cluster

# Deploy premium service in K8s (not docker-compose)
kubectl apply -f k8s/premium-service.yaml
```

**For production**, deploy the premium service **inside** Kubernetes, not with docker-compose:

```yaml
# k8s/premium-service.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vexxy-premium-worker
  namespace: vexxy
spec:
  replicas: 3
  selector:
    matchLabels:
      app: vexxy-premium-worker
  template:
    metadata:
      labels:
        app: vexxy-premium-worker
    spec:
      serviceAccountName: vexxy-premium
      containers:
      - name: worker
        image: vexxy-premium:latest
        command: ["celery", "-A", "workers.celery_app", "worker"]
        env:
        - name: K8S_IN_CLUSTER
          value: "true"  # Use in-cluster config
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: vexxy-db
              key: url
```

---

## Verifying Setup

After starting K8s and docker-compose, verify everything works:

```bash
# 1. Check K8s cluster is accessible
kubectl get nodes

# 2. Check docker-compose services
docker-compose ps
# All services should be "Up"

# 3. Test worker K8s access
docker-compose exec worker kubectl get nodes
# Should show your K8s nodes

# 4. Check kubeconfig is mounted
docker-compose exec worker cat /root/.kube/config
# Should show your kubeconfig

# 5. Test namespace creation
docker-compose exec worker kubectl create namespace test-vexxy
docker-compose exec worker kubectl delete namespace test-vexxy

# 6. Check Kubescape installation
docker-compose exec worker kubectl get pods -n kubescape
# May be empty initially - Kubescape auto-installs on first job
```

---

## Troubleshooting

### "Unable to connect to the server"

**Problem**: Worker can't reach K8s API server

**Solutions:**
```bash
# Check kubeconfig exists
ls -la ~/.kube/config

# Check kubeconfig is mounted in worker
docker-compose exec worker ls -la /root/.kube/config

# Check K8s API server is reachable from host
kubectl cluster-info

# For Docker Desktop: Make sure K8s is enabled
# For minikube: Make sure it's running
minikube status

# Check network connectivity
docker-compose exec worker curl -k https://kubernetes.default.svc
```

### "Permission denied" for kubeconfig

**Problem**: Docker can't read kubeconfig

**Solution:**
```bash
# Make kubeconfig readable
chmod 644 ~/.kube/config

# Or use absolute path in docker-compose.yml
volumes:
  - /Users/yourname/.kube/config:/root/.kube/config:ro
```

### Kubescape installation fails

**Problem**: Helm not available in worker container

**Solution:**
```bash
# Install Helm in worker (temporary)
docker-compose exec worker sh -c 'curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash'

# Or pre-install Kubescape manually
helm repo add kubescape https://kubescape.github.io/helm-charts
helm install kubescape kubescape/kubescape-operator \
  -n kubescape --create-namespace \
  -f premium-service/kubescape-values.yaml
```

### Worker can access K8s but jobs fail

**Problem**: RBAC permissions issue

**Solution:**
```bash
# Create service account with proper permissions
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vexxy-premium
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: vexxy-premium
rules:
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["create", "get", "list", "delete"]
- apiGroups: [""]
  resources: ["pods", "namespaces"]
  verbs: ["create", "get", "list", "delete"]
- apiGroups: ["spdx.softwarecomposition.kubescape.io"]
  resources: ["openvulnerabilityexchangecontainers", "sbomsyftfiltereds"]
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: vexxy-premium
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: vexxy-premium
subjects:
- kind: ServiceAccount
  name: vexxy-premium
  namespace: default
EOF

# Update kubeconfig to use this service account
# (For local testing, default user usually has admin permissions)
```

---

## Resource Requirements

### Minimum (Local Testing)
- **K8s Cluster**: 2 CPU, 4GB RAM
- **Kubescape**: 500MB RAM, 200m CPU
- **Premium Service**: 1GB RAM, 500m CPU per worker
- **Per Analysis Job**: 2-4GB RAM, 1-2 CPU

### Recommended (Multi-Job)
- **K8s Cluster**: 4 CPU, 8GB RAM
- **Kubescape**: 1GB RAM, 500m CPU
- **Premium Service**: 2GB RAM, 1 CPU per worker (3 workers)
- **Per Analysis Job**: 4GB RAM, 2 CPU

### Production
- **K8s Cluster**: Auto-scaling, 8+ nodes
- **Kubescape**: 2GB RAM per node
- **Premium Service**: 10+ workers with HPA
- **Per Analysis Job**: Configurable limits

---

## Alternative: All-in-One Docker Compose

If you want **everything** in docker-compose (including K8s), use this enhanced version:

```yaml
# docker-compose-all.yml
version: '3.8'

services:
  # ... existing services (postgres, redis, api, worker, flower)

  # Add K3s lightweight K8s
  k3s:
    image: rancher/k3s:v1.27.4-k3s1
    container_name: vexxy-k3s
    command: server --disable traefik --write-kubeconfig-mode 644
    privileged: true
    environment:
      K3S_TOKEN: vexxy-k3s-secret
      K3S_KUBECONFIG_OUTPUT: /output/kubeconfig.yaml
    volumes:
      - k3s-data:/var/lib/rancher/k3s
      - k3s-kubeconfig:/output
    ports:
      - "6443:6443"
    tmpfs:
      - /run
      - /var/run
    restart: unless-stopped

  worker:
    # ... existing worker config
    volumes:
      - .:/app
      - k3s-kubeconfig:/root/.kube:ro
    environment:
      KUBECONFIG: /root/.kube/kubeconfig.yaml
      K8S_IN_CLUSTER: "false"
    depends_on:
      - k3s

volumes:
  postgres_data:
  redis_data:
  k3s-data:
  k3s-kubeconfig:
```

**Start with:**
```bash
docker-compose -f docker-compose-all.yml up -d
```

---

## Recommendation

**For development/testing**: Use **Docker Desktop with K8s** (Option 1)
- Simplest setup
- Works immediately
- No configuration needed

**For CI/CD**: Use **kind** (Option 3)
- Fast
- Reproducible
- Easy to automate

**For production**: Deploy premium service **inside K8s** (Option 5)
- Better isolation
- Easier scaling
- Proper service accounts

---

## Next Steps

1. Choose a K8s option above
2. Verify setup with verification commands
3. Start premium service: `docker-compose up -d`
4. Test with a real image (see README.md)
5. Monitor Kubescape installation: `kubectl get pods -n kubescape`

---

## Summary

**What you need:**
- ✅ A Kubernetes cluster (any of the 5 options above)
- ✅ `kubectl` access from your machine
- ✅ Kubeconfig at `~/.kube/config`
- ✅ Docker Compose (for premium service)

**What happens:**
1. You start K8s cluster (separate from docker-compose)
2. You start premium service with docker-compose
3. Worker mounts your kubeconfig
4. Worker deploys analysis jobs to K8s cluster
5. Kubescape monitors jobs and generates VEX
6. Worker extracts results from K8s CRDs

**The premium service does NOT include Kubernetes** - it just connects to one you provide.
